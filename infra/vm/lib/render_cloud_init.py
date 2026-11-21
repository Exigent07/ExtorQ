#!/usr/bin/env python3
"""Render the ExtorQ lab VM cloud-init NoCloud seed (user-data + meta-data).

Standard library only; invoked by infra/vm/vm.sh with ``python3 -I``.

Placeholders in the templates:
  @@NAME@@        replaced by a JSON-encoded string (a valid YAML double-quoted
                  scalar, so multi-line values such as the host key are safe)
  @@B64:path@@    replaced by the JSON-encoded base64 of a file, where ``path``
                  starts with ``files/`` (infra/vm/files) or ``lab-portal/``
                  (lab/apps/lab-portal)

Rendering fails closed: unknown placeholders, missing files, malformed keys or
leftover ``@@`` markers abort with a non-zero exit status.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path

_PLACEHOLDER = re.compile(r"@@([A-Z0-9_]+|B64:[A-Za-z0-9._/-]+)@@")
_PUBKEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/=]{60,100}( [A-Za-z0-9@._-]{1,64})?$")
_PRIVATE_KEY = re.compile(
    r"^-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END OPENSSH PRIVATE KEY-----\n?$"
)
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_INSTANCE_ID = re.compile(r"^[A-Za-z0-9._-]{4,128}$")
DISPATCH_PATH = "/usr/local/sbin/extorq-collect-dispatch"
MAX_EMBED_BYTES = 512 * 1024


class RenderError(Exception):
    pass


def read_pubkey(path: Path) -> str:
    text = path.read_text(encoding="ascii").strip()
    if not _PUBKEY.match(text):
        raise RenderError(f"{path.name}: not a single ssh-ed25519 public key")
    return text


def read_private_key(path: Path) -> str:
    text = path.read_text(encoding="ascii")
    if not _PRIVATE_KEY.match(text):
        raise RenderError(f"{path.name}: not an unencrypted OpenSSH private key")
    return text if text.endswith("\n") else text + "\n"


def render(template: str, values: dict[str, str], roots: dict[str, Path]) -> str:
    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name.startswith("B64:"):
            rel = name[4:]
            prefix, _, rest = rel.partition("/")
            root = roots.get(prefix)
            if root is None or not rest or ".." in Path(rest).parts:
                raise RenderError(f"illegal embed path {rel!r}")
            target = (root / rest).resolve()
            if root.resolve() not in target.parents:
                raise RenderError(f"embed path escapes its root: {rel!r}")
            data = target.read_bytes()
            if len(data) > MAX_EMBED_BYTES:
                raise RenderError(f"{rel} is too large to embed")
            return json.dumps(base64.b64encode(data).decode("ascii"))
        if name not in values:
            raise RenderError(f"unknown placeholder @@{name}@@")
        return json.dumps(values[name])

    rendered = _PLACEHOLDER.sub(substitute, template)
    leftovers = sorted(set(re.findall(r"@@[^@\s]*@@", rendered)))
    if leftovers:
        raise RenderError(f"unreplaced placeholders: {leftovers}")
    return rendered


def build_values(args: argparse.Namespace) -> dict[str, str]:
    if not _HOSTNAME.match(args.hostname):
        raise RenderError("invalid hostname")
    if not _INSTANCE_ID.match(args.instance_id):
        raise RenderError("invalid instance id")
    collector_pub = read_pubkey(Path(args.collector_pubkey))
    host_pub = read_pubkey(Path(args.host_key + ".pub"))
    return {
        "HOSTNAME": args.hostname,
        "INSTANCE_ID": args.instance_id,
        "ADMIN_PUBKEY": read_pubkey(Path(args.admin_pubkey)),
        # Key options duplicate the sshd Match block (defence in depth).
        "COLLECTOR_AUTHORIZED_KEY_LINE": (
            f'restrict,command="{DISPATCH_PATH}" {collector_pub}\n'
        ),
        "HOST_KEY_PRIVATE": read_private_key(Path(args.host_key)),
        "HOST_KEY_PUBLIC": host_pub,
    }


def write_private(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--template-dir", required=True)
    parser.add_argument("--files-dir", required=True)
    parser.add_argument("--lab-portal-dir", required=True)
    parser.add_argument("--admin-pubkey", required=True)
    parser.add_argument("--collector-pubkey", required=True)
    parser.add_argument("--host-key", required=True, help="private key path; .pub must exist")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    try:
        values = build_values(args)
        roots = {"files": Path(args.files_dir), "lab-portal": Path(args.lab_portal_dir)}
        template_dir = Path(args.template_dir)
        out_dir = Path(args.out_dir)
        out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        user_data = render((template_dir / "user-data.yaml.tmpl").read_text("utf-8"), values, roots)
        meta_data = render((template_dir / "meta-data.tmpl").read_text("utf-8"), values, roots)
        if not user_data.startswith("#cloud-config\n"):
            raise RenderError("user-data must start with #cloud-config")
        write_private(out_dir / "user-data", user_data)
        write_private(out_dir / "meta-data", meta_data)
    except (RenderError, OSError, UnicodeDecodeError) as exc:
        print(f"render_cloud_init: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
