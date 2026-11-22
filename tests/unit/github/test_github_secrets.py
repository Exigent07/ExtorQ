"""Credential detection in added lines. All credential-shaped values are SYNTHETIC."""

from __future__ import annotations

import dataclasses
import hashlib
import uuid

from extorq_collectors.github.secrets import MAX_FINDINGS_PER_COMMIT, scan_added_lines

AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"  # 20 chars, AWS access-key shaped
AWS_SECRET = "".join(
    ["aB3dE5gH7j", "K9mN1pQ3sT", "5vW7yZ9bC1", "dE3fG5hI7j"]
)  # 40 chars, built at runtime
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8" + "I9j0K1l2M3n4O5p6Q7r8"


def _patch(*lines: str, start: int = 1) -> str:
    return f"@@ -0,0 +{start},{len(lines)} @@\n" + "\n".join(f"+{line}" for line in lines)


def _blob(findings: list) -> str:
    return repr([dataclasses.asdict(f) for f in findings])


def test_aws_key_pair_is_reported_with_pattern_line_and_no_value() -> None:
    patch = _patch(
        "# deploy settings",
        f"aws_access_key_id = {AWS_KEY}",
        f'aws_secret_access_key = "{AWS_SECRET}"',
        start=10,
    )
    findings = scan_added_lines("deploy/settings.conf", patch)
    assert {(f.pattern, f.line) for f in findings} >= {("aws_access_key", 11)}
    assert all(f.path == "deploy/settings.conf" for f in findings)
    blob = _blob(findings)
    assert AWS_KEY not in blob and AWS_SECRET not in blob, "a raw credential leaked into a finding"
    assert "[REDACTED:" in blob


def test_github_token_is_detected_and_redacted() -> None:
    findings = scan_added_lines("ci/token.txt", _patch(f"token: {GH_TOKEN}"))
    assert [f.pattern for f in findings] == ["github_token"]
    assert GH_TOKEN not in _blob(findings)


def test_benign_high_entropy_lines_do_not_match() -> None:
    checksum = hashlib.sha256(b"release").hexdigest()
    patch = _patch(
        f"{checksum}  extorq-1.0.tar.gz",
        f"request-id: {uuid.uuid4()}",
        "build_number: 20261122",
        "contact: ops@example.invalid",
    )
    assert scan_added_lines("RELEASE_SHA256SUMS", patch) == []


def test_removed_and_context_lines_are_ignored_and_numbering_follows_the_new_file() -> None:
    patch = "\n".join(
        [
            "@@ -1,4 +1,4 @@",
            " context line one",
            f"-old = {AWS_KEY}",  # a REMOVED credential is not an exposure by this commit
            "+new safe line",
            " context line three",
            f"+added = {AWS_KEY}",
        ]
    )
    findings = scan_added_lines("a.txt", patch)
    assert [(f.pattern, f.line) for f in findings] == [("aws_access_key", 4)]


def test_findings_per_commit_are_bounded() -> None:
    patch = _patch(*[f"k{i} = {AWS_KEY}" for i in range(MAX_FINDINGS_PER_COMMIT + 30)])
    assert len(scan_added_lines("big.txt", patch)) == MAX_FINDINGS_PER_COMMIT


def test_empty_and_malformed_patches_are_safe() -> None:
    assert scan_added_lines("x", "") == []
    assert scan_added_lines("x", "not a diff at all\n+++\n---\n\\ No newline") == []
