"""AST-based static checks for first-party Python (owner: agent F).

Each ``check_*`` function takes parsed source and returns findings as
``(line, message)`` tuples. They are intentionally conservative pattern checks
that complement ruff's bandit rules (``S``) with ExtorQ-specific invariants:

* SQL (ClickHouse and SQLite) is never built from f-strings, ``%``/``+``
  concatenation or ``str.format`` and then passed to a query/command/execute
  call. Values must be bound server-side (``{name:Type}`` for ClickHouse,
  ``?``/named parameters for SQLite).
* No shell: ``shell=True``, ``os.system``, ``os.popen``,
  ``subprocess.getoutput``/``getstatusoutput``, ``create_subprocess_shell``.
* No dynamic code execution or unsafe deserialisation: ``eval``/``exec``,
  ``yaml.load`` without a safe loader, ``pickle``/``marshal``/``shelve`` loads.
* TLS verification is never disabled.

Reviewed exceptions use an inline pragma on the flagged line(s) with a reason::

    client.query(sql)  # extorq: sql-reviewed identifiers come from TABLES allow-list

The pragma reason must be at least 10 characters; reviewers grep for it.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterable

SQL_PRAGMA = re.compile(r"#\s*extorq:\s*sql-reviewed\s+(?P<reason>.*)$")

#: Methods whose first argument is SQL text (clickhouse-connect, DB-API, sqlite3).
SQL_METHODS = frozenset(
    {
        "query",
        "command",
        "raw_query",
        "raw_stream",
        "query_df",
        "query_np",
        "query_arrow",
        "query_rows",
        "query_df_stream",
        "query_np_stream",
        "query_arrow_stream",
        "query_row_block_stream",
        "query_column_block_stream",
        "execute",
        "executemany",
        "executescript",
    }
)
SQL_KEYWORDS = frozenset({"query", "cmd", "sql", "statement", "operation", "sql_script"})

_UPPER_CONST = re.compile(r"^_?[A-Z][A-Z0-9_]*$")

Finding = tuple[int, str]


# ── helpers ──────────────────────────────────────────────────────────────────


def _dotted(node: ast.AST) -> str:
    """Render ``a.b.c`` for Name/Attribute chains, '' otherwise."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_constant_reference(node: ast.AST) -> bool:
    """Module constants (UPPER_CASE), subscripts of them, and enum-style attributes."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return bool(_UPPER_CONST.match(node.id))
    if isinstance(node, ast.Subscript):
        return isinstance(node.value, ast.Name) and bool(_UPPER_CONST.match(node.value.id))
    if isinstance(node, ast.Attribute):
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        # Enum members / class constants: SomeEnum.MEMBER.value, Config.TABLE
        return isinstance(root, ast.Name) and root.id[:1].isupper()
    return False


def _is_static(node: ast.AST, assignments: dict[str, list[ast.AST]], depth: int = 0) -> bool:
    """True when ``node`` is built only from literals and module constants."""
    if depth > 8:
        return False
    if _is_constant_reference(node):
        return True
    # Numeric casts cannot inject: str(int(x)) is only digits and a sign.
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"int", "float", "len"}
    ):
        return True
    if isinstance(node, ast.Name) and node.id in assignments:
        return all(_is_static(v, assignments, depth + 1) for v in assignments[node.id])
    if isinstance(node, ast.JoinedStr):
        return all(
            not isinstance(v, ast.FormattedValue) or _is_static(v.value, assignments, depth + 1)
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_static(node.left, assignments, depth + 1) and _is_static(
            node.right, assignments, depth + 1
        )
    return False


def _is_stringish(
    node: ast.AST, assignments: dict[str, list[ast.AST]] | None = None, depth: int = 0
) -> bool:
    if depth > 8:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_stringish(node.left, assignments, depth + 1) or _is_stringish(
            node.right, assignments, depth + 1
        )
    if isinstance(node, ast.Name) and assignments and node.id in assignments:
        return any(_is_stringish(v, assignments, depth + 1) for v in assignments[node.id])
    return False


def _is_dynamic_string(
    node: ast.AST, assignments: dict[str, list[ast.AST]], depth: int = 0
) -> bool:
    """True when ``node`` builds a string from non-constant parts."""
    if depth > 8:
        return False
    if isinstance(node, ast.JoinedStr):
        return not _is_static(node, assignments, depth + 1)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _is_stringish(node.left, assignments) or _is_dynamic_string(
            node.left, assignments, depth + 1
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if _is_static(node, assignments, depth + 1):
            return False
        sides = (node.left, node.right)
        return any(
            _is_stringish(side, assignments) or _is_dynamic_string(side, assignments, depth + 1)
            for side in sides
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"format", "format_map"}:
            return True
        if node.func.attr == "join" and isinstance(node.func.value, ast.Constant):
            return not all(_is_static(a, assignments, depth + 1) for a in node.args)
    if isinstance(node, ast.Name) and node.id in assignments:
        return any(_is_dynamic_string(v, assignments, depth + 1) for v in assignments[node.id])
    return False


def _scope_assignments(scope: ast.AST) -> dict[str, list[ast.AST]]:
    """Values assigned to simple names anywhere in a function/module body."""
    found: dict[str, list[ast.AST]] = {}
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                found.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            # `sql += f"..."` is dynamic if the added part is dynamic.
            found.setdefault(node.target.id, []).append(
                ast.BinOp(left=ast.Constant(value=""), op=node.op, right=node.value)
            )
        elif isinstance(node, ast.For | ast.AsyncFor) and isinstance(node.target, ast.Name):
            # `for table in ALLOWED_TABLES:` binds `table` to elements of the iterable.
            # The iterable itself stands in for the element: a module constant
            # (UPPER_CASE) is static, anything else (a parameter, a call) stays dynamic.
            found.setdefault(node.target.id, []).append(node.iter)
    return found


def enclosing_function(tree: ast.Module, line: int) -> str:
    """Qualified name (``Class.method``) of the innermost def containing ``line``.

    Used to key reviewed exceptions by function instead of by line number, so
    unrelated edits that shift lines do not invalidate a review.
    """
    best: tuple[int, str] = (-1, "<module>")

    def visit(node: ast.AST, prefix: str, depth: int) -> None:
        nonlocal best
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                name = f"{prefix}{child.name}"
                start, end = child.lineno, child.end_lineno or child.lineno
                if start <= line <= end:
                    if not isinstance(child, ast.ClassDef) and depth >= best[0]:
                        best = (depth, name)
                    visit(child, f"{name}.", depth + 1)
            else:
                visit(child, prefix, depth)

    visit(tree, "", 0)
    return best[1]


def _pragma_lines(source_lines: list[str]) -> dict[int, str]:
    """Pragmas found in real comment tokens (text inside string literals is ignored)."""
    lines: dict[int, str] = {}
    source = "\n".join(source_lines) + "\n"
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.COMMENT:
                continue
            match = SQL_PRAGMA.search(token.string)
            if match:
                lines[token.start[0]] = match.group("reason").strip()
    except (tokenize.TokenError, SyntaxError):
        return {}
    return lines


def _enclosing_scopes(tree: ast.Module) -> Iterable[tuple[ast.AST, list[ast.Call]]]:
    """Yield (scope, calls directly inside it) for the module and every function."""
    scopes: list[ast.AST] = [tree]
    scopes.extend(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda)
    )
    owner: dict[int, ast.AST] = {}
    for scope in scopes:
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                owner[id(node)] = scope  # innermost scope wins (walked later)
    by_scope: dict[int, list[ast.Call]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            by_scope.setdefault(id(owner[id(node)]), []).append(node)
    for scope in scopes:
        yield scope, by_scope.get(id(scope), [])


# ── checks ───────────────────────────────────────────────────────────────────


def check_sql_construction(tree: ast.Module, source_lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    pragmas = _pragma_lines(source_lines)
    module_assignments = _scope_assignments(tree)
    for scope, calls in _enclosing_scopes(tree):
        assignments = dict(module_assignments)
        if scope is not tree:
            assignments.update(_scope_assignments(scope))
        for call in calls:
            if not (isinstance(call.func, ast.Attribute) and call.func.attr in SQL_METHODS):
                continue
            candidates: list[ast.AST] = []
            if call.args:
                candidates.append(call.args[0])
            candidates.extend(kw.value for kw in call.keywords if kw.arg in SQL_KEYWORDS)
            for candidate in candidates:
                if not _is_dynamic_string(candidate, assignments):
                    continue
                span = range(call.lineno, (call.end_lineno or call.lineno) + 1)
                related = list(span)
                if isinstance(candidate, ast.Name):
                    related.extend(
                        v.lineno for v in assignments.get(candidate.id, []) if hasattr(v, "lineno")
                    )
                reasons = [pragmas[n] for n in related if n in pragmas]
                if any(len(r) >= 10 for r in reasons):
                    continue
                findings.append(
                    (
                        call.lineno,
                        f".{call.func.attr}() receives a query/command string built from "
                        "dynamic parts; "
                        "bind values as server-side parameters ({name:Type}) or add a reviewed "
                        "'# extorq: sql-reviewed <reason>' pragma",
                    )
                )
    return findings


def check_pragmas_have_reasons(source_lines: list[str]) -> list[Finding]:
    return [
        (number, "sql-reviewed pragma needs a reason of at least 10 characters")
        for number, reason in _pragma_lines(source_lines).items()
        if len(reason) < 10
    ]


_SHELL_FUNCS = {
    "os.system": "os.system runs a shell",
    "os.popen": "os.popen runs a shell",
    "subprocess.getoutput": "subprocess.getoutput runs a shell",
    "subprocess.getstatusoutput": "subprocess.getstatusoutput runs a shell",
    "asyncio.create_subprocess_shell": "create_subprocess_shell runs a shell",
}


def check_shell_usage(tree: ast.Module) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if name in _SHELL_FUNCS:
            findings.append((node.lineno, _SHELL_FUNCS[name]))
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "create_subprocess_shell",
            "subprocess_shell",
        }:
            findings.append((node.lineno, f"{node.func.attr} runs a shell"))
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            value = keyword.value
            if isinstance(value, ast.Constant) and value.value in (False, None, 0):
                continue
            literal_true = isinstance(value, ast.Constant) and value.value is True
            # A non-literal shell= only matters on process-spawning calls; elsewhere
            # ``shell`` is ordinary data (e.g. a user's login shell). Wrappers that pass
            # it through are caught at their inner subprocess call.
            if literal_true or _is_process_call(name, node.func):
                findings.append((node.lineno, "shell= must be False (use argument lists)"))
    return findings


_PROCESS_CALLS = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "spawn",
        "run_fixed",
        "run_command",
    }
)


def _is_process_call(dotted: str, func: ast.AST) -> bool:
    if dotted.startswith(("subprocess.", "asyncio.", "os.")):
        return True
    last = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return last in _PROCESS_CALLS


_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}


def check_unsafe_deserialisation_and_eval(tree: ast.Module) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if name in {"eval", "exec"}:
            findings.append((node.lineno, f"{name}() executes dynamic code"))
        elif name in {
            "yaml.unsafe_load",
            "yaml.full_load",
            "yaml.unsafe_load_all",
            "yaml.full_load_all",
        }:
            findings.append(
                (node.lineno, f"{name} is unsafe for untrusted input; use yaml.safe_load")
            )
        elif name in {"yaml.load", "yaml.load_all"}:
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            loader_name = _dotted(loader).rsplit(".", 1)[-1] if loader is not None else ""
            if loader_name not in _SAFE_YAML_LOADERS:
                findings.append((node.lineno, f"{name} without a safe Loader; use yaml.safe_load"))
        elif name in {
            "pickle.load",
            "pickle.loads",
            "cPickle.load",
            "cPickle.loads",
            "marshal.load",
            "marshal.loads",
            "shelve.open",
            "dill.load",
            "dill.loads",
            "joblib.load",
        }:
            findings.append((node.lineno, f"{name} deserialises arbitrary objects"))
    return findings


def check_tls_verification(tree: ast.Module) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if (
                    keyword.arg in {"verify", "verify_ssl", "check_hostname"}
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    findings.append((node.lineno, f"{keyword.arg}=False disables TLS verification"))
            name = _dotted(node.func)
            if name.endswith("_create_unverified_context"):
                findings.append((node.lineno, "unverified SSL context"))
            if name.endswith("disable_warnings") and name.startswith(("urllib3", "requests")):
                findings.append((node.lineno, "TLS warnings disabled"))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr in {"check_hostname", "verify_ssl", "verify"}
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is False
                ):
                    findings.append(
                        (node.lineno, f"{target.attr} = False disables TLS verification")
                    )
        elif isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
            findings.append((node.lineno, "ssl.CERT_NONE disables certificate verification"))
    return findings
