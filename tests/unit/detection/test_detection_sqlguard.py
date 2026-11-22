"""Static rule-SQL validation (defence in depth before the readonly ClickHouse identity).

This module deliberately builds hostile SQL strings as inputs for the validator; nothing
here is executed against a database.
"""
# ruff: noqa: S608

from __future__ import annotations

from pathlib import Path

import pytest

from extorq.detection.sqlguard import check_rule_sql

W = (
    "WHERE event_time >= {window_start:DateTime64(3, 'UTC')} "
    "AND event_time < {window_end:DateTime64(3, 'UTC')}"
)
RULES = Path(__file__).resolve().parents[3] / "rules"


def ok(sql: str, params: dict | None = None, **kw) -> None:
    result = check_rule_sql(sql, params or {}, **kw)
    assert result.ok, result.errors


def bad(sql: str, needle: str, params: dict | None = None) -> None:
    result = check_rule_sql(sql, params or {})
    assert not result.ok
    assert any(needle.lower() in e.lower() for e in result.errors), result.errors


def test_minimal_valid_rule() -> None:
    result = check_rule_sql(f"SELECT event_id FROM events {W}", {})
    assert result.ok and result.tables == {"events"}
    assert result.placeholders == {
        "window_start": "DateTime64(3,'UTC')",
        "window_end": "DateTime64(3,'UTC')",
    }


def test_every_repository_rule_passes_the_guard() -> None:
    import yaml

    for path in RULES.rglob("*.sql"):
        meta = yaml.safe_load(path.with_suffix(".yaml").read_text())
        reserved = (
            {"bucket_seconds": "UInt32"} if meta["dedup"]["strategy"] == "window_bucket" else {}
        )
        result = check_rule_sql(path.read_text(), meta.get("params") or {}, reserved=reserved)
        assert result.ok, (path.name, result.errors)


def test_detector_owns_the_result_limit() -> None:
    bad(f"SELECT event_id FROM events {W} LIMIT 1000", "top-level LIMIT")
    ok(f"WITH seen AS (SELECT event_id FROM events {W} LIMIT 1 BY event_id) SELECT * FROM seen")


@pytest.mark.parametrize(
    ("sql", "needle"),
    [
        (f"SELECT 1 FROM events {W}; DROP TABLE events", "';' is not allowed"),
        (f"INSERT INTO alerts SELECT * FROM events {W}", "must start with SELECT"),
        (f"SELECT * FROM events {W} SETTINGS readonly = 0", "forbidden keyword SETTINGS"),
        (f"SELECT * FROM url('http://x', CSV, 'a String') {W}", "table function url()"),
        (f"SELECT * FROM remote('h', extorq.events) {W}", "table function remote()"),
        (f"SELECT * FROM s3('https://b/k') {W}", "table function s3()"),
        (f"SELECT file('/etc/passwd') FROM events {W}", "forbidden function file()"),
        (f"SELECT * FROM system.users {W}", "system tables are not allowed"),
        (f"SELECT * FROM alerts {W}", "table alerts is not allowed"),
        (f"SELECT * FROM other.events {W}", "only the 'extorq' database"),
        (f"SELECT * FROM events, assets {W}", "comma joins are not allowed"),
        (f'SELECT "event_id" FROM events {W}', "quoted identifiers"),
        (f"SELECT 1 /* hidden */ FROM events {W}", "block comments"),
        (f"SELECT dictGet('d', 'a', 1) FROM events {W}", "forbidden function dictGet()"),
        (f"SELECT 1 FROM events {W} AND x IN alerts", "table alerts is not allowed"),
        ("SELECT * FROM events", "must bound the window"),
        (
            "WITH alerts AS (SELECT * FROM events " + W + ") SELECT * FROM alerts",
            "shadows a database object",
        ),
        (f"SELECT * FROM events {W} FORMAT JSON", "FORMAT clause"),
        (f"SELECT {{x:String}} FROM events {W}", "not declared in params"),
    ],
)
def test_dangerous_or_malformed_sql_is_rejected(sql: str, needle: str) -> None:
    bad(sql, needle)


def test_parameters_must_match_declared_types() -> None:
    sql = f"SELECT 1 FROM events {W} AND src_ip IN {{ips:Array(String)}} AND n > {{n:UInt32}}"
    ok(sql, {"ips": ["10.0.2.2"], "n": 5})
    bad(sql, "expected a list", {"ips": "10.0.2.2", "n": 5})
    bad(sql, "non-negative integer", {"ips": [], "n": -1})
    bad(f"SELECT 1 FROM events {W} AND a = {{window_start:String}}", "conflicting types")
    only_string = (
        "SELECT 1 FROM events WHERE a = {window_start:String} "
        "AND event_time < {window_end:DateTime64(3, 'UTC')}"
    )
    bad(only_string, "must be typed DateTime64")


def test_reserved_bucket_parameter_only_for_window_bucket_rules() -> None:
    bucket = "toStartOfInterval(event_time, toIntervalSecond({bucket_seconds:UInt32}))"
    sql = f"SELECT {bucket} FROM events {W}"
    ok(sql, reserved={"bucket_seconds": "UInt32"})
    bad(sql, "reserved parameter bucket_seconds is not available")


def test_function_keywords_inside_calls_are_not_table_references() -> None:
    ok(f"SELECT EXTRACT(HOUR FROM event_time), substring(message FROM 1) FROM events {W}")
    ok(f"SELECT e.event_id FROM events AS e ARRAY JOIN e.k8s_user_groups AS g {W}")
