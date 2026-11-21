"""Static safety checks for detection rule SQL (``rules/**/*.sql``, owner C2).

Rule SQL runs as ``extorq_rules_ro`` (``readonly=1``, PLAN 4.4). These checks
are defence in depth on top of that identity:

* exactly one statement, and it is a ``SELECT``/``WITH`` query;
* no write/DDL/admin keywords and no ``INTO OUTFILE``;
* no table functions that reach outside the database (``url``, ``file``,
  ``remote``, ``s3``, ``executable``, ...);
* values are bound only through ClickHouse server-side parameters
  ``{name:Type}``: no Python ``str.format``/``%`` placeholders;
* tables referenced in the ``extorq`` database are limited to the ones
  ``extorq_rules_ro`` may read.

Skipped until rule SQL exists.
"""

from __future__ import annotations

import re

import pytest
from security_helpers import format_findings, iter_files, read_text, rel

RULE_SQL = sorted(iter_files(suffixes=(".sql",), roots=("rules",)))

#: Tables/views extorq_rules_ro may read (PLAN 4.4 + duplicate-safe views over them).
ALLOWED_TABLES = frozenset(
    {
        "events",
        "assets",
        "inventory_items",
        "finding_observations",
        "scan_runs",
        "simulation_runs",
        "v_assets",
        "v_inventory_current",
        "v_findings_current",
    }
)
FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|ALTER|DROP|CREATE|TRUNCATE|RENAME|DELETE|UPDATE|SYSTEM|KILL|GRANT|REVOKE|"
    r"OPTIMIZE|ATTACH|DETACH|EXCHANGE|UNDROP|BACKUP|RESTORE)\b|\bINTO\s+OUTFILE\b|\bSET\s+ROLE\b",
    re.IGNORECASE,
)
EXTERNAL_TABLE_FUNCTIONS = re.compile(
    r"\b(url|urlCluster|file|fileCluster|remote|remoteSecure|cluster|clusterAllReplicas|s3|s3Cluster|"
    r"gcs|azureBlobStorage|hdfs|mysql|postgresql|mongodb|redis|sqlite|jdbc|odbc|executable|input|"
    r"iceberg|deltaLake|hudi)\s*\(",
    re.IGNORECASE,
)
SERVER_PARAM = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*:[^{}]+\}")
ANY_BRACE = re.compile(r"\{[^{}]*\}")
PRINTF_PARAM = re.compile(r"%\(\w+\)s|%s\b")
TABLE_REF = re.compile(r"\bextorq\.([A-Za-z_][A-Za-z0-9_]*)\b")


def _lex(sql: str) -> tuple[str, str]:
    """Single pass over SQL text.

    Returns ``(without_comments, without_comments_or_strings)``: comments are
    replaced by a space; in the second form single-quoted literals become ``''``.
    ``--`` or ``/*`` inside a literal is not a comment, and quotes inside
    comments do not open literals.
    """
    keep: list[str] = []
    blank: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end == -1 else end
            keep.append(" ")
            blank.append(" ")
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
            keep.append(" ")
            blank.append(" ")
        elif ch == "'":
            j = i + 1
            while j < n:
                if sql[j] == "\\":
                    j += 2
                    continue
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            literal = sql[i : j + 1]
            keep.append(literal)
            blank.append("''")
            i = j + 1
        else:
            keep.append(ch)
            blank.append(ch)
            i += 1
    return "".join(keep), "".join(blank)


def rule_sql_problems(sql: str, relative: str) -> list[str]:
    problems: list[str] = []
    no_comments, body = _lex(sql)
    body = body.strip()
    statements = [s for s in body.split(";") if s.strip()]
    if len(statements) != 1:
        problems.append(f"{relative}: must contain exactly one statement (found {len(statements)})")
    first = body.lstrip("( \n\t").split(None, 1)[0].upper() if body else ""
    if first not in {"SELECT", "WITH"}:
        problems.append(f"{relative}: must start with SELECT or WITH (found {first or 'nothing'})")
    for match in FORBIDDEN_KEYWORDS.finditer(body):
        problems.append(f"{relative}: forbidden keyword {match.group(0).upper()!r}")
    for match in EXTERNAL_TABLE_FUNCTIONS.finditer(body):
        problems.append(f"{relative}: external table function {match.group(1)}()")
    # Placeholders are checked with literals intact: '{x}' inside quotes is the
    # classic str.format injection shape.
    for brace in ANY_BRACE.findall(no_comments):
        if not SERVER_PARAM.fullmatch(brace):
            problems.append(f"{relative}: placeholder {brace} is not a typed server-side parameter")
    if PRINTF_PARAM.search(no_comments):
        problems.append(f"{relative}: printf-style placeholder (use {{name:Type}})")
    for table in TABLE_REF.findall(body):
        if table not in ALLOWED_TABLES:
            problems.append(
                f"{relative}: extorq.{table} is not readable by extorq_rules_ro (PLAN 4.4)"
            )
    return problems


@pytest.mark.skipif(not RULE_SQL, reason="no rule SQL under rules/ yet (owner: C2)")
def test_rule_sql_is_single_parameterised_read_only_select() -> None:
    problems: list[str] = []
    for path in RULE_SQL:
        problems.extend(rule_sql_problems(read_text(path), rel(path)))
    assert not problems, format_findings(problems)


# ── self-tests ───────────────────────────────────────────────────────────────

GOOD_RULE = """
-- VM-001 (synthetic example for the checker self-test)
SELECT asset_id, src_ip, uniqExact(event_id) AS n
FROM extorq.events
WHERE event_type IN {event_types:Array(String)}
  AND event_time >= {window_start:DateTime64(3, 'UTC')}
  AND message != 'DROP TABLE x; -- inside a string'
GROUP BY asset_id, src_ip
HAVING n >= {threshold:UInt32}
"""


def test_checker_accepts_parameterised_select() -> None:
    assert rule_sql_problems(GOOD_RULE, "good.sql") == []


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1; DROP TABLE extorq.events",
        "INSERT INTO extorq.alerts SELECT * FROM extorq.events",
        "SELECT * FROM url('http://example.invalid/x', CSV)",
        "SELECT * FROM extorq.events WHERE asset_id = '{asset}'",
        "SELECT * FROM extorq.events WHERE asset_id = %(asset)s",
        "SELECT * FROM extorq.alerts",
        "SELECT * FROM extorq.events INTO OUTFILE '/tmp/x'",
        "SYSTEM FLUSH LOGS",
    ],
)
def test_checker_flags_unsafe_rule_sql(sql: str) -> None:
    assert rule_sql_problems(sql, "bad.sql"), sql
