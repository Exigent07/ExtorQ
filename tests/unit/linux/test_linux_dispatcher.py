"""Unit tests of the VM-side dispatch boundary (infra/vm/files/extorq-collect-dispatch).

The dispatcher is loaded from the exact file cloud-init deploys. Only pure functions are
exercised here (grammar, ss/nginx/sshd parsing, audit read planning); its behaviour inside
the VM is verified live (docs/team/status/B1.md).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

DISPATCHER = (
    Path(__file__).resolve().parents[3] / "infra" / "vm" / "files" / "extorq-collect-dispatch"
)


def _load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("extorq_collect_dispatch", str(DISPATCHER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module  # dataclasses resolve their module by name
    loader.exec_module(module)
    return module


d = _load()
CURSOR = (
    "s=573dfc44e4d24e9d9b349a93721f0462;i=12b5;b=f914254357f7410fb96b532f72d5dfe9;"
    "m=391adb975;t=660ca668be4e8;x=3712d8aa66d26661"
)


@pytest.mark.parametrize(
    "raw,name",
    [
        ("version", "version"),
        ("inventory", "inventory"),
        ("packages", "packages"),
        ("posture", "posture"),
        ("journal - 1", "journal"),
        (f"journal {CURSOR} 5000", "journal"),
        ("audit - 0 4096", "audit"),
        ("audit 262353 6444739 1048576", "audit"),
    ],
)
def test_allowed_commands_parse(raw: str, name: str) -> None:
    assert d.parse_command(raw).name == name


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "cat /etc/shadow",
        "version extra",
        "journal - 5001",
        "journal - 0",
        "journal ../etc 10",
        "journal - 10 extra",
        f"journal {CURSOR};id 10",
        "audit - 0 4095",
        "audit - 0 1048577",
        "audit 0 0 4096",
        "audit - -1 4096",
        "audit - 01 4096",
        "inventory  ",
        " version",
        "version\nid",
        "posture;id",
        "packages $(id)",
        "journal - 1\x00",
        "journal\t-\t1",
        "a" * 600,
        "sh -c id",
        "INVENTORY",
    ],
)
def test_everything_else_is_denied(raw: str | None) -> None:
    with pytest.raises(d.Denied):
        d.parse_command(raw)


def test_cursor_and_ranges_are_typed() -> None:
    command = d.parse_command(f"journal {CURSOR} 250")
    assert command.cursor == CURSOR and command.max_entries == 250
    audit = d.parse_command("audit 262353 100 65536")
    assert (audit.inode, audit.offset, audit.max_bytes) == (262353, 100, 65536)
    assert d.parse_command("audit - 0 4096").inode is None


# Real `ss -H -t -u -l -p -n -e --cgroup` output captured unprivileged on lab-vm-01.
SS_OUTPUT = """\
udp UNCONN 0      0            127.0.0.54:53   0.0.0.0:* uid:991 ino:5072 sk:1 cgroup:/system.slice/systemd-resolved.service <-> cgroup:/system.slice/systemd-resolved.service
udp UNCONN 0      0      10.0.2.15%enp0s3:68   0.0.0.0:* uid:998 ino:6549 sk:3 cgroup:/system.slice/systemd-networkd.service <-> cgroup:/system.slice/systemd-networkd.service
tcp LISTEN 0      64            127.0.0.1:8080 0.0.0.0:* uid:64881 ino:20642 sk:4 cgroup:/system.slice/lab-portal.service <-> cgroup:/system.slice/lab-portal.service
tcp LISTEN 0      4096            0.0.0.0:22   0.0.0.0:* ino:6746 sk:7 cgroup:/system.slice/ssh.socket <-> cgroup:/system.slice/ssh.socket
tcp LISTEN 0      4096               [::]:22      [::]:* ino:6748 sk:9 cgroup:/system.slice/ssh.socket v6only:1 <-> cgroup:/system.slice/ssh.socket
"""  # noqa: E501


def test_parse_ss_extended_fields_without_root() -> None:
    rows = d.parse_ss(SS_OUTPUT)
    assert len(rows) == 5
    resolved, dhcp, portal, ssh4, ssh6 = rows
    assert resolved["uid"] == 991 and resolved["cgroup"] == "/system.slice/systemd-resolved.service"
    assert dhcp["local_address"] == "10.0.2.15" and dhcp["interface"] == "enp0s3"
    assert portal["local_port"] == 8080 and portal["uid"] == 64881
    # ss omits uid 0: present extended output means uid 0, not unknown.
    assert ssh4["uid"] == 0 and ssh4["cgroup"] == "/system.slice/ssh.socket"
    assert ssh6["local_address"] == "::" and ssh6["v6only"] is True
    # Process owner is NOT shown without root and must stay unknown (None), never guessed.
    assert all(r["processes"] is None for r in rows)


def test_parse_ss_without_extended_output_keeps_fields_absent() -> None:
    rows = d.parse_ss("tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n")
    assert rows[0]["local_port"] == 80
    assert "cgroup" not in rows[0] and "uid" not in rows[0]


def test_parse_ss_own_socket_process() -> None:
    line = 'tcp LISTEN 0 5 127.0.0.1:9000 0.0.0.0:* users:(("python3",pid=42,fd=3)) ino:1 sk:2\n'
    assert d.parse_ss(line)[0]["processes"] == [{"name": "python3", "pid": 42}]


def test_nginx_tokenizer_handles_quotes_and_comments() -> None:
    text = 'log_format x \'{"a":"$b"}\';  # comment ; {\nserver { listen 80; }'
    assert d.tokenize_nginx(text) == [
        "log_format",
        "x",
        '{"a":"$b"}',
        ";",
        "server",
        "{",
        "listen",
        "80",
        ";",
        "}",
    ]


def test_nginx_config_directives_and_include_confinement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "nginx"
    (root / "conf.d").mkdir(parents=True)
    lab = Path(__file__).resolve().parents[3] / "infra/vm/files/nginx/extorq-lab.conf"
    (root / "conf.d" / "extorq-lab.conf").write_text(lab.read_text())
    outside = tmp_path / "outside.conf"
    outside.write_text("server { listen 9999; }\n")
    (root / "nginx.conf").write_text(
        "user www-data;\nerror_log /var/log/nginx/error.log;\n"
        f"http {{ access_log /var/log/nginx/access.log; include conf.d/*.conf; "
        f"include {outside}; }}\n"
    )
    monkeypatch.setattr(d, "NGINX_ROOT", str(root))
    parsed = d.parse_nginx_config(str(root / "nginx.conf"))
    server = next(c for c in parsed["contexts"] if c["context"] == "server")
    assert server["directives"]["listen"] == ["80 default_server"]
    assert any("tag=nginx_access" in v for v in server["directives"]["access_log"])
    assert any("tag=nginx_error" in v for v in server["directives"]["error_log"])
    location = next(c for c in parsed["contexts"] if c["context"] == "location")
    assert location["directives"]["proxy_pass"] == ["http://127.0.0.1:8080"]
    # An include outside the nginx root is never read.
    assert str(outside) in parsed["unreadable"]
    assert all("9999" not in str(c) for c in parsed["contexts"])


def test_sshd_config_first_value_wins_and_ports_accumulate(tmp_path: Path) -> None:
    drop = tmp_path / "10-extorq.conf"
    drop.write_text(
        "PasswordAuthentication no\nPort 22\nMatch User x\n  PasswordAuthentication yes\n"
    )
    main = tmp_path / "sshd_config"
    main.write_text(
        f"Include {tmp_path}/*.conf\nPasswordAuthentication yes\nPort 2200\nLogLevel=VERBOSE\n"
    )
    parsed = d.parse_sshd_config(str(main))
    assert parsed["settings"]["passwordauthentication"]["value"] == "no"
    assert parsed["settings"]["loglevel"]["value"] == "VERBOSE"
    assert parsed["multi"]["port"] == ["22", "2200"]
    assert parsed["match_blocks"][0]["settings"]["passwordauthentication"] == "yes"


def test_audit_read_planning_detects_rotation_and_truncation() -> None:
    files = [("audit.log.1", 10, 500), ("audit.log", 11, 100)]
    assert d.plan_audit_read(files, None, 50) == (1, 50, False, None)
    assert d.plan_audit_read(files, 11, 40) == (1, 40, False, None)
    # Checkpoint in a rotated file: finish it first, then continue with the live file.
    assert d.plan_audit_read(files, 10, 200) == (0, 200, False, None)
    assert d.plan_audit_read(files, 10, 500) == (1, 0, False, None)
    # File shrank below the checkpoint / inode rotated out of the retained set: gap.
    assert d.plan_audit_read(files, 11, 400) == (1, 0, True, "file_truncated")
    assert d.plan_audit_read(files, 99, 10) == (1, 0, True, "rotated_past_offset")


def test_journal_entry_filter_drops_unlisted_fields() -> None:
    entry = {
        "__CURSOR": CURSOR,
        "MESSAGE": "x",
        "_CMDLINE": "secret args",
        "_PID": "1",
        "SYSLOG_IDENTIFIER": [104, 105],
    }
    filtered = d.filter_journal_entry(entry)
    assert "_CMDLINE" not in filtered
    assert filtered["SYSLOG_IDENTIFIER"] == "hi"  # binary field decoded, bounded
    assert set(filtered) <= set(d.JOURNAL_FIELDS)


def test_unit_directive_allow_list_excludes_environment(tmp_path: Path) -> None:
    unit = tmp_path / "x.service"
    unit.write_text(
        "[Service]\nType=oneshot\nEnvironment=PASSWORD=hunter2\n"
        "ExecStart=-/bin/true synthetic-argument\nExecStart=relative synthetic-other\n"
        "User=nobody\n[Install]\nWantedBy=multi-user.target\n"
    )
    details = d._unit_details(str(unit))
    assert details["exec_start"] == ["/bin/true"]
    assert details["directives"] == {
        "Type": ["oneshot"],
        "User": ["nobody"],
        "WantedBy": ["multi-user.target"],
    }
    assert "hunter2" not in str(details)
    assert "synthetic-argument" not in str(details)
