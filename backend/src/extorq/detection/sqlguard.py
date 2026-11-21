"""Static validation of detection-rule SQL.

This is defence in depth. The authoritative boundary is the ClickHouse identity
``extorq_rules_ro`` (``readonly=1``, SELECT only on the telemetry tables). The
validator rejects anything a rule never needs so that mistakes and malicious
rule changes fail at load time, in review and in CI, not at runtime:

* exactly one statement that starts with ``SELECT`` or ``WITH``; no ``;``
* only ``--`` comments (no ``/* */`` or ``#``, which invite parser differentials)
* no quoted identifiers, ``$$`` heredocs, backslashes or non-ASCII outside strings
* no statement/settings keywords (INSERT, ALTER, DROP, SYSTEM, SETTINGS, INTO,
  FORMAT clause, ...)
* tables only from :data:`ALLOWED_TABLES` (optionally qualified ``extorq.``) or CTEs
  defined in the same query; no table functions (``url()``, ``file()``,
  ``remote()``, ``s3()``, ...), no other databases, no ``system.*``
* dangerous scalar functions (``file``, ``dictGet*``, ``joinGet``, ``sleep``,
  introspection ...) are rejected everywhere
* parameters only as server-side placeholders ``{name:Type}``: the window bounds
  ``{window_start:DateTime64(3, 'UTC')}`` / ``{window_end:DateTime64(3, 'UTC')}``
  (both mandatory) and parameters declared in the rule's ``params``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

ALLOWED_TABLES: frozenset[str] = frozenset(
    {"events", "assets", "inventory_items", "finding_observations", "scan_runs", "simulation_runs"}
)
ALLOWED_DATABASE = "extorq"
WINDOW_PARAMS: tuple[str, str] = ("window_start", "window_end")
WINDOW_TYPE = "DateTime64(3,'UTC')"  # whitespace-normalised form
#: Optional engine-provided parameters (name -> required type). ``bucket_seconds`` is
#: the rule's dedup bucket, available to window_bucket rules only.
OPTIONAL_RESERVED: dict[str, str] = {"bucket_seconds": "UInt32"}
MAX_SQL_BYTES = 32 * 1024

FORBIDDEN_KEYWORDS: frozenset[str] = frozenset(
    {
        "INSERT",
        "ALTER",
        "DROP",
        "SYSTEM",
        "SETTINGS",
        "CREATE",
        "TRUNCATE",
        "RENAME",
        "OPTIMIZE",
        "KILL",
        "GRANT",
        "REVOKE",
        "ATTACH",
        "DETACH",
        "EXCHANGE",
        "DELETE",
        "UPDATE",
        "UNDROP",
        "BACKUP",
        "RESTORE",
        "WATCH",
        "MOVE",
        "SET",
        "USE",
        "SHOW",
        "EXPLAIN",
        "DESCRIBE",
        "INTO",
        "OUTFILE",
        "GLOBAL",
        "INFORMATION_SCHEMA",
        "PASTE",
    }
)
#: Functions that read files/network/dictionaries, sleep, or introspect the server.
FORBIDDEN_FUNCTIONS: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "file",
        "url",
        "urlCluster",
        "remote",
        "remoteSecure",
        "s3",
        "s3Cluster",
        "gcs",
        "cosn",
        "oss",
        "azureBlobStorage",
        "azureBlobStorageCluster",
        "hdfs",
        "hdfsCluster",
        "mysql",
        "postgresql",
        "mongodb",
        "redis",
        "sqlite",
        "jdbc",
        "odbc",
        "executable",
        "executablePool",
        "input",
        "cluster",
        "clusterAllReplicas",
        "dictionary",
        "merge",
        "generateRandom",
        "view",
        "viewIfPermitted",
        "viewExplain",
        "iceberg",
        "icebergS3",
        "icebergAzure",
        "icebergHDFS",
        "icebergLocal",
        "deltaLake",
        "hudi",
        "fuzzJSON",
        "fuzzQuery",
        "loop",
        "mergeTreeIndex",
        "mergeTreeProjection",
        "joinGet",
        "joinGetOrNull",
        "dictGet",
        "dictGetOrDefault",
        "dictGetOrNull",
        "dictHas",
        "dictGetString",
        "dictGetUInt64",
        "dictGetHierarchy",
        "dictIsIn",
        "dictGetAll",
        "dictGetChildren",
        "dictGetDescendants",
        "sleep",
        "sleepEachRow",
        "addressToLine",
        "addressToLineWithInlines",
        "addressToSymbol",
        "demangle",
        "filesystemAvailable",
        "filesystemCapacity",
        "filesystemUnreserved",
        "getMacro",
        "getServerSetting",
        "getMergeTreeSetting",
        "catboostEvaluate",
        "naiveBayesClassifier",
        "throwIf",
        "transactionID",
        "transactionLatestSnapshot",
        "currentQueryID",
        "initialQueryID",
        "arrowFlight",
        "prometheusQuery",
        "ytsaurus",
        "paimon",
        "timeSeriesData",
        "timeSeriesMetrics",
        "timeSeriesTags",
    )
)
#: Clause keywords that end a FROM clause at the same nesting depth.
_FROM_END = frozenset(
    {
        "WHERE",
        "PREWHERE",
        "GROUP",
        "ORDER",
        "LIMIT",
        "HAVING",
        "WINDOW",
        "QUALIFY",
        "UNION",
        "EXCEPT",
        "INTERSECT",
        "OFFSET",
    }
)
#: Every table/view name of the extorq database: CTEs may not shadow them (a CTE is
#: only visible in its own scope, so a shadowing name could reach the real table).
RESERVED_NAMES: frozenset[str] = frozenset(
    {
        "assets",
        "inventory_items",
        "events",
        "scan_runs",
        "finding_observations",
        "detection_rules",
        "rule_runs",
        "alerts",
        "alert_evidence",
        "investigation_contexts",
        "context_relationships",
        "ai_assessments",
        "analyst_state",
        "analyst_actions",
        "collector_health",
        "pipeline_health",
        "ingest_quarantine",
        "ingest_audit",
        "simulation_runs",
        "v_assets",
        "v_alerts",
        "v_analyst_state",
        "v_inventory_current",
        "v_collector_latest",
        "v_pipeline_latest",
        "v_rule_latest_run",
        "v_findings_current",
        "v_scan_runs_current",
        "system",
        "default",
        "extorq",
    }
)
_PARAM_TYPE_RE = re.compile(
    r"^(String|U?Int(8|16|32|64)|Float(32|64)|Bool|DateTime64\(3,'UTC'\)|"
    r"Array\((String|U?Int(8|16|32|64))\))$"
)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"[0-9][0-9A-Za-z_.]*")
_PARAM_RE = re.compile(r"\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^{}]{1,64}?)\s*\}")
_SYMBOLS = set("()[],.+-*/%<>=!?:|&~^")


@dataclass(frozen=True)
class Token:
    kind: str  # ident | number | string | param | symbol
    value: str
    pos: int


@dataclass
class SqlCheck:
    """Result of :func:`check_rule_sql`."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Placeholder name -> normalised ClickHouse type.
    placeholders: dict[str, str] = field(default_factory=dict)
    #: Table identifiers referenced (normalised, without database).
    tables: set[str] = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return not self.errors


class SqlTokenizeError(ValueError):
    pass


def _normalise_type(raw: str) -> str:
    return re.sub(r"\s+", "", raw).replace('"', "'")


def tokenize(sql: str) -> list[Token]:
    """Tokenise rule SQL strictly; raise :class:`SqlTokenizeError` on anything unusual."""
    tokens: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end == -1 else end + 1
            continue
        if sql.startswith("/*", i):
            raise SqlTokenizeError(f"block comments are not allowed (position {i}); use --")
        if ch == "#":
            raise SqlTokenizeError(f"'#' comments are not allowed (position {i}); use --")
        if ch == "'":
            j = i + 1
            buf: list[str] = []
            while True:
                if j >= n:
                    raise SqlTokenizeError(f"unterminated string literal at position {i}")
                c = sql[j]
                if c == "\\":
                    if j + 1 >= n:
                        raise SqlTokenizeError(f"dangling escape at position {j}")
                    buf.append(sql[j : j + 2])
                    j += 2
                    continue
                if c == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        buf.append("''")
                        j += 2
                        continue
                    break
                buf.append(c)
                j += 1
            tokens.append(Token("string", "".join(buf), i))
            i = j + 1
            continue
        if ch in '"`':
            raise SqlTokenizeError(f"quoted identifiers are not allowed (position {i})")
        if ch == "$":
            raise SqlTokenizeError(f"'$' (heredoc) is not allowed (position {i})")
        if ch == ";":
            raise SqlTokenizeError(
                f"';' is not allowed: a rule is exactly one statement (position {i})"
            )
        if ch == "\\":
            raise SqlTokenizeError(f"backslash outside a string literal (position {i})")
        if ch == "{":
            m = _PARAM_RE.match(sql, i)
            if not m:
                raise SqlTokenizeError(f"malformed parameter placeholder at position {i}")
            tokens.append(Token("param", f"{m.group(1)}:{_normalise_type(m.group(2))}", i))
            i = m.end()
            continue
        if ch == "}":
            raise SqlTokenizeError(f"unbalanced '}}' at position {i}")
        if ord(ch) > 127:
            raise SqlTokenizeError(f"non-ASCII character outside a string literal (position {i})")
        m = _IDENT_RE.match(sql, i)
        if m:
            tokens.append(Token("ident", m.group(0), i))
            i = m.end()
            continue
        m = _NUMBER_RE.match(sql, i)
        if m:
            tokens.append(Token("number", m.group(0), i))
            i = m.end()
            continue
        if ch in _SYMBOLS:
            # Two-character operators are irrelevant for validation; emit singles.
            tokens.append(Token("symbol", ch, i))
            i += 1
            continue
        raise SqlTokenizeError(f"unexpected character {ch!r} at position {i}")
    return tokens


def _upper(tok: Token | None) -> str:
    return tok.value.upper() if tok is not None and tok.kind == "ident" else ""


def _collect_ctes(tokens: list[Token]) -> set[str]:
    """Names introduced as ``name AS ( SELECT|WITH ...`` (common table expressions)."""
    ctes: set[str] = set()
    for idx in range(len(tokens) - 3):
        a, b, c, d = tokens[idx : idx + 4]
        if (
            a.kind == "ident"
            and _upper(b) == "AS"
            and c.kind == "symbol"
            and c.value == "("
            and _upper(d) in {"SELECT", "WITH"}
        ):
            ctes.add(a.value)
    return ctes


def check_rule_sql(
    sql: str,
    declared_params: dict[str, object] | None = None,
    *,
    reserved: dict[str, str] | None = None,
) -> SqlCheck:
    """Validate rule SQL against the ExtorQ rule contract (see module docstring).

    ``reserved`` lists the optional engine-provided parameters this rule may use
    (name -> required type); by default none.
    """
    result = SqlCheck()
    declared = dict(declared_params or {})
    reserved = dict(reserved or {})
    if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        result.errors.append(f"SQL exceeds {MAX_SQL_BYTES} bytes")
        return result
    try:
        tokens = tokenize(sql)
    except SqlTokenizeError as exc:
        result.errors.append(str(exc))
        return result
    if not tokens:
        result.errors.append("SQL is empty")
        return result
    if _upper(tokens[0]) not in {"SELECT", "WITH"}:
        result.errors.append("rule SQL must start with SELECT or WITH")

    ctes = _collect_ctes(tokens)

    # Keyword / function checks.
    for idx, tok in enumerate(tokens):
        if tok.kind != "ident":
            continue
        upper = tok.value.upper()
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
        prev = tokens[idx - 1] if idx > 0 else None
        followed_by_paren = nxt is not None and nxt.kind == "symbol" and nxt.value == "("
        preceded_by_dot = prev is not None and prev.kind == "symbol" and prev.value == "."
        if preceded_by_dot:
            continue  # a column/field after a qualifier (e.g. e.event_id), never a keyword
        if upper in FORBIDDEN_KEYWORDS:
            result.errors.append(f"forbidden keyword {upper} at position {tok.pos}")
        if upper == "FORMAT" and not followed_by_paren:
            result.errors.append(f"FORMAT clause is not allowed (position {tok.pos})")
        if followed_by_paren and tok.value.lower() in FORBIDDEN_FUNCTIONS:
            result.errors.append(f"forbidden function {tok.value}() at position {tok.pos}")
        if tok.value.lower().startswith("dictget") and followed_by_paren:
            result.errors.append(
                f"dictionary access is not allowed ({tok.value}) at position {tok.pos}"
            )
        if tok.value.lower() == "system" and nxt is not None and nxt.value == ".":
            result.errors.append(f"system tables are not allowed (position {tok.pos})")

    for name in sorted(ctes):
        if name.lower() in RESERVED_NAMES:
            result.errors.append(f"CTE name {name} shadows a database object; rename it")

    # Table references: identifiers following FROM / JOIN / IN in a query context.
    paren_stack: list[str] = []  # 'query' or 'func'
    in_from: list[bool] = [False]
    for idx, tok in enumerate(tokens):
        if tok.kind == "symbol" and tok.value == "(":
            nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
            kind = "query" if _upper(nxt) in {"SELECT", "WITH"} else "func"
            paren_stack.append(kind)
            in_from.append(False)
            continue
        if tok.kind == "symbol" and tok.value == ")":
            if not paren_stack:
                result.errors.append(f"unbalanced ')' at position {tok.pos}")
                break
            paren_stack.pop()
            in_from.pop()
            continue
        upper = _upper(tok)
        if upper == "IN":
            # ``x IN table`` reads a table without FROM: treat it as a table reference.
            _check_table_ref(tokens, idx, ctes, result, allow_expression=True)
            continue
        context = paren_stack[-1] if paren_stack else "query"
        if context == "func":
            continue  # e.g. EXTRACT(HOUR FROM ts) / substring(x FROM 1): not a table reference
        if tok.kind == "symbol" and tok.value == "," and in_from[-1]:
            result.errors.append(
                f"comma joins are not allowed; use explicit JOIN (position {tok.pos})"
            )
            continue
        if upper in _FROM_END:
            in_from[-1] = False
            continue
        if upper not in {"FROM", "JOIN"}:
            continue
        if upper == "JOIN" and idx > 0 and _upper(tokens[idx - 1]) == "ARRAY":
            in_from[-1] = False  # ARRAY JOIN <expression>[, <expression>]
            continue
        in_from[-1] = True
        _check_table_ref(tokens, idx, ctes, result, allow_expression=False)
    if paren_stack:
        result.errors.append("unbalanced '(' in SQL")
    if not result.tables:
        result.errors.append("rule SQL does not read any allowed table")

    # Parameters.
    for tok in tokens:
        if tok.kind != "param":
            continue
        name, _, ptype = tok.value.partition(":")
        previous = result.placeholders.get(name)
        if previous is not None and previous != ptype:
            result.errors.append(
                f"parameter {name} used with conflicting types {previous} / {ptype}"
            )
            continue
        result.placeholders[name] = ptype
        if name in WINDOW_PARAMS:
            if ptype != WINDOW_TYPE:
                result.errors.append(f"{{{name}}} must be typed DateTime64(3, 'UTC'), got {ptype}")
            continue
        if name in OPTIONAL_RESERVED:
            if name not in reserved:
                result.errors.append(f"reserved parameter {name} is not available to this rule")
            elif ptype != reserved[name]:
                result.errors.append(f"{{{name}}} must be typed {reserved[name]}, got {ptype}")
            continue
        if not _PARAM_TYPE_RE.match(ptype):
            result.errors.append(f"parameter {name} has unsupported type {ptype}")
        if name not in declared:
            result.errors.append(f"parameter {name} is used in SQL but not declared in params")
            continue
        type_problem = _value_matches_type(declared[name], ptype)
        if type_problem:
            result.errors.append(f"parameter {name}: {type_problem}")
    for name in WINDOW_PARAMS:
        if name not in result.placeholders:
            result.errors.append(
                f"rule SQL must bound the window with {{{name}:DateTime64(3, 'UTC')}}"
            )
    for name in declared:
        if name in WINDOW_PARAMS or name in OPTIONAL_RESERVED:
            result.errors.append(f"params may not redefine the reserved parameter {name}")
        elif name not in result.placeholders:
            result.warnings.append(f"declared param {name} is not used by the SQL")
    return result


def _check_table_ref(
    tokens: list[Token], idx: int, ctes: set[str], result: SqlCheck, *, allow_expression: bool
) -> None:
    """Validate the table reference that follows ``tokens[idx]`` (FROM / JOIN / IN)."""
    keyword = tokens[idx].value.upper()
    target = tokens[idx + 1] if idx + 1 < len(tokens) else None
    if target is None:
        result.errors.append(f"{keyword} without an operand at position {tokens[idx].pos}")
        return
    if target.kind == "symbol" and target.value == "(":
        return  # subquery / tuple; its contents are checked on their own
    if target.kind != "ident":
        if not allow_expression:
            result.errors.append(f"unexpected token after {keyword} at position {target.pos}")
        return  # IN {param:Array(...)} / IN literal
    after = tokens[idx + 2] if idx + 2 < len(tokens) else None
    if after is not None and after.kind == "symbol" and after.value == "(":
        if allow_expression:
            return  # IN tuple(...) / IN array(...): a function call, checked by the function scan
        result.errors.append(
            f"table function {target.value}() is not allowed (position {target.pos})"
        )
        return
    if after is not None and after.kind == "symbol" and after.value == ".":
        table_tok = tokens[idx + 3] if idx + 3 < len(tokens) else None
        if target.value != ALLOWED_DATABASE or table_tok is None or table_tok.kind != "ident":
            result.errors.append(
                f"only the '{ALLOWED_DATABASE}' database may be referenced (position {target.pos})"
            )
            return
        if table_tok.value not in ALLOWED_TABLES:
            result.errors.append(
                f"table {ALLOWED_DATABASE}.{table_tok.value} is not allowed for rules"
            )
            return
        result.tables.add(table_tok.value)
        return
    if target.value in ctes:
        return
    if target.value not in ALLOWED_TABLES:
        result.errors.append(
            f"table {target.value} is not allowed for rules (position {target.pos})"
        )
        return
    result.tables.add(target.value)


def _value_matches_type(value: object, ptype: str) -> str | None:
    """Check a declared param value against its placeholder type."""
    if ptype == "String":
        return None if isinstance(value, str) else f"expected a string for {ptype}"
    if ptype == "Bool":
        return None if isinstance(value, bool) else f"expected a boolean for {ptype}"
    if re.match(r"^U?Int", ptype):
        if isinstance(value, bool) or not isinstance(value, int):
            return f"expected an integer for {ptype}"
        if ptype.startswith("U") and value < 0:
            return f"expected a non-negative integer for {ptype}"
        return None
    if ptype.startswith("Float"):
        ok = isinstance(value, int | float) and not isinstance(value, bool)
        return None if ok else f"expected a number for {ptype}"
    if ptype.startswith("Array("):
        if not isinstance(value, list):
            return f"expected a list for {ptype}"
        inner = ptype[len("Array(") : -1]
        for item in value:
            problem = _value_matches_type(item, inner)
            if problem:
                return f"list item: {problem}"
        return None
    if ptype == WINDOW_TYPE:
        return "DateTime64 rule params are not supported (use the window parameters)"
    return f"unsupported type {ptype}"
