"""Static security invariants for first-party Python (AGENTS.md security invariants).

Runs without the stack. Scope: every ``*.py`` file in the repository except
vendored/runtime directories, ``lab/`` (monitored lab targets, not ExtorQ) and
this package's own fixtures. The SQL-construction check covers production code
(everything except ``tests/``).
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest
from security_helpers import format_findings, iter_files, read_text, rel
from security_static import (
    Finding,
    check_pragmas_have_reasons,
    check_shell_usage,
    check_sql_construction,
    check_tls_verification,
    check_unsafe_deserialisation_and_eval,
    enclosing_function,
)

EXCLUDED_PREFIXES = ("lab/", "tests/security/fixtures/")

#: Dynamic-SQL call sites that agent F reviewed as safe but whose OWNER has not yet
#: added the in-code ``# extorq: sql-reviewed <reason>`` pragma (F cannot edit other
#: agents' files). Keyed by (path, enclosing function), not line numbers. Every entry
#: names the finding in docs/team/status/F.md and the owner who must add the pragma.
#: Entries are reported as warnings so they stay visible; anything NOT listed here
#: fails the test. Remove an entry once the owner's pragma lands (a stale entry warns).
PENDING_OWNER_PRAGMA: dict[tuple[str, str], str] = {}


def _python_files() -> list[Path]:
    return sorted(iter_files(suffixes=(".py",), exclude_prefixes=EXCLUDED_PREFIXES))


def _parse(path: Path) -> tuple[ast.Module, list[str]] | None:
    source = read_text(path)
    try:
        return ast.parse(source, filename=str(path)), source.splitlines()
    except SyntaxError:
        return None


PY_FILES = _python_files()


def _scan(
    check: Callable[[ast.Module, list[str]], list[Finding]],
    *,
    production_only: bool = False,
) -> list[str]:
    findings: list[str] = []
    for path in PY_FILES:
        relative = rel(path)
        if production_only and relative.startswith("tests/"):
            continue
        parsed = _parse(path)
        if parsed is None:
            findings.append(f"{relative}: could not be parsed")
            continue
        tree, lines = parsed
        findings.extend(f"{relative}:{line}: {message}" for line, message in check(tree, lines))
    return findings


# ── repository scans ─────────────────────────────────────────────────────────


def test_python_files_were_found() -> None:
    assert any(rel(p).startswith("backend/src/extorq/contracts/") for p in PY_FILES)


def test_no_shell_execution() -> None:
    findings = _scan(lambda tree, _lines: check_shell_usage(tree))
    assert not findings, "shell execution found (use argument lists):\n" + format_findings(findings)


def _sql_findings_by_function() -> list[tuple[str, str, str]]:
    """(path, enclosing function, 'path:line: message') for production code."""
    out: list[tuple[str, str, str]] = []
    for path in PY_FILES:
        relative = rel(path)
        if relative.startswith("tests/"):
            continue
        parsed = _parse(path)
        if parsed is None:
            out.append((relative, "<unparsed>", f"{relative}: could not be parsed"))
            continue
        tree, lines = parsed
        for line, message in check_sql_construction(tree, lines):
            out.append((relative, enclosing_function(tree, line), f"{relative}:{line}: {message}"))
    return out


def test_no_sql_built_from_dynamic_strings() -> None:
    findings = _sql_findings_by_function()
    unexpected = [text for p, fn, text in findings if (p, fn) not in PENDING_OWNER_PRAGMA]
    pending = sorted(
        {PENDING_OWNER_PRAGMA[(p, fn)] for p, fn, _ in findings if (p, fn) in PENDING_OWNER_PRAGMA}
    )
    stale = sorted(
        f"{p}::{fn}"
        for p, fn in PENDING_OWNER_PRAGMA
        if not any((p, fn) == (fp, ffn) for fp, ffn, _ in findings)
    )
    if pending:
        warnings.warn(
            "reviewed dynamic SQL awaiting the owner's sql-reviewed pragma:\n"
            + format_findings(pending),
            stacklevel=1,
        )
    if stale:
        warnings.warn(
            "PENDING_OWNER_PRAGMA entries no longer needed (owner fixed them; F removes):\n"
            + format_findings(stale),
            stacklevel=1,
        )
    assert not unexpected, "dynamic SQL construction found:\n" + format_findings(unexpected)


def test_enclosing_function_names_methods() -> None:
    source = (
        "class A:\n"
        "    def m(self):\n"
        "        x = 1\n"
        "        def inner():\n"
        "            return 2\n"
        "def f():\n"
        "    return 3\n"
    )
    tree = ast.parse(source)
    assert enclosing_function(tree, 3) == "A.m"
    assert enclosing_function(tree, 5) == "A.m.inner"
    assert enclosing_function(tree, 7) == "f"
    assert enclosing_function(tree, 1) == "<module>"


def test_sql_review_pragmas_have_reasons() -> None:
    findings = _scan(lambda _tree, lines: check_pragmas_have_reasons(lines))
    assert not findings, format_findings(findings)


def test_no_eval_or_unsafe_deserialisation() -> None:
    findings = _scan(lambda tree, _lines: check_unsafe_deserialisation_and_eval(tree))
    assert not findings, format_findings(findings)


def test_tls_verification_is_never_disabled() -> None:
    findings = _scan(lambda tree, _lines: check_tls_verification(tree))
    assert not findings, format_findings(findings)


# ── analyser self-tests (code snippets are parsed, never executed) ───────────


def _sql(snippet: str) -> list[Finding]:
    return check_sql_construction(ast.parse(snippet), snippet.splitlines())


@pytest.mark.parametrize(
    "snippet",
    [
        "client.query(f\"SELECT * FROM extorq.events WHERE asset_id = '{asset}'\")",
        'client.command("DROP TABLE " + name)',
        'client.query("SELECT * FROM t WHERE x = %s" % value)',
        'client.query("SELECT {} FROM t".format(col))',
        'sql = f"SELECT * FROM t WHERE id = {i}"\nclient.query(sql)',
        'def f(c, ids):\n    q = "SELECT 1 WHERE id IN ("\n    q += ", ".join(ids)\n    c.query(q)',
        'conn.execute(f"INSERT INTO spool VALUES ({v})")',
        'cur.executemany("DELETE FROM outbox WHERE id = " + str(i), [])',
        'client.query(query=f"SELECT {x}")',
        'client.query(f"SELECT {x}")  # extorq: sql-reviewed short',
        'def f(c, where):\n    c.query("SELECT 1 " + _FROM + where)',
        'def f(c, col):\n    base = "SELECT "\n    c.query(base + col)',
        # loop variables are only as static as their iterable
        'def f(c, tables):\n    for t in tables:\n        c.command(f"TRUNCATE TABLE {t}")',
        'def f(c):\n    for t in load_tables():\n        c.command(f"DROP TABLE {t}")',
        "def f(c, pw):\n    for u in USERS:\n        c.command(f\"ALTER USER {u} BY '{pw}'\")",
    ],
)
def test_sql_check_flags_dynamic_sql(snippet: str) -> None:
    assert _sql(snippet), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        'client.query("SELECT * FROM extorq.events WHERE asset_id = {asset:String}", '
        'parameters={"asset": a})',
        'conn.execute("INSERT INTO spool (id, body) VALUES (?, ?)", (i, b))',
        'TABLE = "extorq.events"\nclient.query(f"SELECT count() FROM {TABLE}")',
        'client.query(f"SELECT * FROM {TABLES[kind]} LIMIT 1")',
        'client.query(f"SELECT {Kind.EVENT.value}")',
        "sql = path.read_text()\nclient.query(sql, parameters=p)",
        'client.query(f"SELECT {x}")  # extorq: sql-reviewed x is a validated allow-list entry',
        'client.insert("extorq.events", rows, column_names=cols)',
        'client.query("SELECT 1 " + "FROM system.one")',
        '_FROM = "FROM t "\nclient.query("SELECT a " + _FROM + "LIMIT {n:UInt32}", parameters=p)',
        'def f(c):\n    base = "SELECT 1 "\n    c.query(base + "FROM system.one")',
        'conn.execute(f"PRAGMA busy_timeout = {int(ms)}")',
        'TABLES = ("events", "alerts")\n'
        'def f(c):\n    for t in TABLES:\n        c.command(f"TRUNCATE TABLE extorq.{t}")',
    ],
)
def test_sql_check_accepts_parameterised_sql(snippet: str) -> None:
    assert not _sql(snippet), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess\nsubprocess.run(cmd, shell=True)",
        "import subprocess\nsubprocess.Popen(cmd, shell=flag)",
        "import os\nos.system('ls')",
        "import os\nos.popen('ls')",
        "import subprocess\nsubprocess.getoutput('ls')",
        "import asyncio\nasyncio.create_subprocess_shell('ls')",
        "run_cmd(cmd, shell=True)",
        "def f(cmd, flag):\n    run_command(cmd, shell=flag)",
    ],
)
def test_shell_check_flags_shell_use(snippet: str) -> None:
    assert check_shell_usage(ast.parse(snippet)), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess\nsubprocess.run(['ls', '-l'], check=True, timeout=5)",
        "import subprocess\nsubprocess.run(['ls'], shell=False)",
        "Account(name=name, uid=uid, shell=shells.get(name))",
        "row = dict(user=u, shell=login_shell)",
    ],
)
def test_shell_check_accepts_argument_lists(snippet: str) -> None:
    assert not check_shell_usage(ast.parse(snippet)), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "eval(text)",
        "exec(code)",
        "import yaml\nyaml.load(stream)",
        "import yaml\nyaml.load(stream, Loader=yaml.FullLoader)",
        "import yaml\nyaml.unsafe_load(stream)",
        "import pickle\npickle.loads(blob)",
    ],
)
def test_deserialisation_check_flags_unsafe_calls(snippet: str) -> None:
    assert check_unsafe_deserialisation_and_eval(ast.parse(snippet)), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "import yaml\nyaml.safe_load(stream)",
        "import yaml\nyaml.load(stream, Loader=yaml.SafeLoader)",
        "import ast\nast.literal_eval(text)",
        "import json\njson.loads(text)",
    ],
)
def test_deserialisation_check_accepts_safe_calls(snippet: str) -> None:
    assert not check_unsafe_deserialisation_and_eval(ast.parse(snippet)), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "import httpx\nhttpx.Client(verify=False)",
        "import ssl\nctx = ssl._create_unverified_context()",
        "import ssl\nctx.check_hostname = False",
        "import ssl\nctx.verify_mode = ssl.CERT_NONE",
        "configuration.verify_ssl = False",
        "import urllib3\nurllib3.disable_warnings()",
    ],
)
def test_tls_check_flags_disabled_verification(snippet: str) -> None:
    assert check_tls_verification(ast.parse(snippet)), snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "import httpx\nhttpx.Client(verify=ssl_context)",
        "import httpx\nhttpx.Client(verify='/path/ca.pem')",
        "import ssl\nctx = ssl.create_default_context(cafile=path)",
    ],
)
def test_tls_check_accepts_verified_clients(snippet: str) -> None:
    assert not check_tls_verification(ast.parse(snippet)), snippet
