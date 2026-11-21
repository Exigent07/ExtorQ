"""SSH transport (argv, grammar, error classification, retries) and dispatch protocol parsing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from linux_testlib import FIXTURES, FakeVM, make_client

from extorq_collectors.linux.protocol import (
    ProtocolError,
    parse_audit_response,
    parse_journal_response,
    parse_json_document,
)
from extorq_collectors.linux.ssh import (
    DispatchDenied,
    HostKeyVerificationError,
    RunResult,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHDispatchClient,
    SSHDispatchError,
    SSHTarget,
    validate_command,
)


def test_client_grammar_mirrors_dispatcher() -> None:
    assert validate_command("journal - 5000") == "journal - 5000"
    for bad in ("journal - 5001", "audit - 0 1", "id", "inventory x", "journal  - 1", "ls;id"):
        with pytest.raises(ValueError):
            validate_command(bad)


def test_argv_is_hardened(ssh_files: tuple[Path, Path]) -> None:
    client = make_client(FakeVM(), ssh_files)
    argv = client.build_argv("version")
    joined = " ".join(argv)
    assert argv[:3] == ["/usr/bin/ssh", "-F", "/dev/null"]
    for option in (
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "BatchMode=yes",
        "PasswordAuthentication=no",
        "IdentityAgent=none",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "UpdateHostKeys=no",
        f"UserKnownHostsFile={ssh_files[1]}",
    ):
        assert option in joined
    assert argv[-2:] == ["127.0.0.1", "version"] and argv[-3] == "--"


def test_target_validation_rejects_injection() -> None:
    for host in ("-oProxyCommand=sh", "a b", "host;id"):
        with pytest.raises(ValueError):
            SSHTarget(host=host)
    with pytest.raises(ValueError):
        SSHTarget(user="root;id")


def test_identity_file_must_be_private(tmp_path: Path, ssh_files: tuple[Path, Path]) -> None:
    os.chmod(ssh_files[0], 0o644)
    client = make_client(FakeVM(), ssh_files)
    with pytest.raises(SSHDispatchError, match="chmod 600"):
        client.run("version")


def _client_with(
    results: list[RunResult], ssh_files: tuple[Path, Path]
) -> tuple[SSHDispatchClient, list[str]]:
    calls: list[str] = []

    def runner(argv: list[str], timeout: float, max_output: int) -> RunResult:
        calls.append(argv[-1])
        return results.pop(0)

    key, known = ssh_files
    target = SSHTarget(identity_file=key, known_hosts_file=known, control_dir=None, max_attempts=3)
    return SSHDispatchClient(target, runner=runner, sleep=lambda _s: None), calls


def test_denied_and_host_key_errors_are_not_retried(ssh_files: tuple[Path, Path]) -> None:
    client, calls = _client_with([RunResult(77, b"", b"denied\n", 0.1)], ssh_files)
    with pytest.raises(DispatchDenied):
        client.run("version")
    assert len(calls) == 1
    hostkey = (
        b"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.\n"
    )
    client, calls = _client_with([RunResult(255, b"", hostkey, 0.1)], ssh_files)
    with pytest.raises(HostKeyVerificationError):
        client.run("version")
    assert len(calls) == 1
    client, calls = _client_with(
        [RunResult(255, b"", b"extorq-collector@127.0.0.1: Permission denied (publickey).\n", 0.1)],
        ssh_files,
    )
    with pytest.raises(SSHAuthenticationError):
        client.run("version")
    assert len(calls) == 1


def test_connection_errors_retry_with_bound(ssh_files: tuple[Path, Path]) -> None:
    refused = RunResult(
        255, b"", b"ssh: connect to host 127.0.0.1 port 2222: Connection refused\n", 0.1
    )
    client, calls = _client_with([refused, refused, refused], ssh_files)
    with pytest.raises(SSHConnectionError):
        client.run("version")
    assert len(calls) == 3  # max_attempts, then give up
    ok = RunResult(0, b'{"type":"version","protocol":1}\n', b"", 0.1)
    client, calls = _client_with([refused, ok], ssh_files)
    assert "version" in client.run("version")
    assert len(calls) == 2


def test_journal_response_real_capture() -> None:
    batch = parse_journal_response((FIXTURES / "dispatch" / "journal_response.ndjson").read_bytes())
    assert batch.complete and batch.cursor_exact is True and batch.truncated is True
    assert len(batch.entries) == 25 and batch.malformed_lines == 0
    assert (
        batch.trailer is not None and batch.trailer["last_cursor"] == batch.entries[-1]["__CURSOR"]
    )


def test_journal_response_cut_mid_line_keeps_complete_entries() -> None:
    data = (FIXTURES / "dispatch" / "journal_response.ndjson").read_bytes()
    cut = data[: data.index(b"\n", 4000) + 30]  # ends inside an entry, no trailer
    batch = parse_journal_response(cut)
    assert not batch.complete
    assert batch.malformed_lines == 1 and len(batch.entries) >= 1
    assert all("__CURSOR" in e for e in batch.entries)


def test_journal_response_rejects_entries_after_trailer() -> None:
    trailer = b'{"_extorq":{"type":"journal_end","protocol":1}}\n'
    batch = parse_journal_response(trailer + b'{"__CURSOR":"x"}\n')
    assert batch.complete and batch.entries == [] and batch.malformed_lines == 1


def test_audit_response_validation() -> None:
    header = (
        b'{"_extorq":{"type":"audit","protocol":1,"inode":5,"start_offset":0,'
        b'"next_offset":6,"gap":false}}\n'
    )
    chunk = parse_audit_response(header + b"a=b c\n")
    assert chunk.inode == 5 and chunk.next_offset == 6 and not chunk.gap
    with pytest.raises(ProtocolError):
        parse_audit_response(header + b"a=b c")  # not line aligned
    with pytest.raises(ProtocolError):
        parse_audit_response(header + b"a=b c\nmore than advertised\n")
    with pytest.raises(ProtocolError):
        parse_audit_response(b'{"_extorq":{"type":"journal_end","protocol":1}}\n')
    with pytest.raises(ProtocolError):
        parse_audit_response(b"no header")


def test_json_documents_require_type_and_protocol() -> None:
    version = parse_json_document((FIXTURES / "dispatch" / "version.json").read_bytes(), "version")
    assert version["user"] == "extorq-collector" and version["version"] == "1.1.0"
    with pytest.raises(ProtocolError):
        parse_json_document(b'{"type":"posture","protocol":2}', "posture")
    with pytest.raises(ProtocolError):
        parse_json_document(b'{"type":"inventory","protocol":1}', "posture")
    with pytest.raises(ProtocolError):
        parse_json_document(b"not json", "posture")
