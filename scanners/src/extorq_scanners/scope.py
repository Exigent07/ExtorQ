"""Deterministic scan scopes (``ScanRun.scope``) for configured targets.

The scope hash decides which scans may resolve which findings: the lifecycle
view only lets a SUCCEEDED scan with the SAME (asset_id, scanner, scope_hash)
resolve a finding. Changing any string below therefore starts a new lifecycle
scope (old findings then stay in their old scope until it is scanned again).

* paths: ``<mode>:<repository-relative path>`` per path;
* images: ``image:<repository>`` (tag and digest excluded on purpose): the scope
  is "the image of this repository that the asset runs", so a rebuilt or bumped
  image resolves the findings it no longer has. The exact reference, image id
  and repo digests of every scan are kept in ``ScanRun.attributes``;
* Linux packages: ``sbom:<asset_id>:dpkg``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from extorq.contracts import ScanScope
from extorq.contracts.identity import scope_hash

if TYPE_CHECKING:
    from extorq_scanners.config import TargetConfig


def scope_for(target: TargetConfig) -> ScanScope:
    if target.mode == "image":
        targets = [f"image:{target.image_repository}"]
    elif target.mode == "sbom":
        targets = [f"sbom:{target.asset_id}:dpkg"]
    else:
        targets = [f"{target.mode}:{p}" for p in target.paths]
    targets = sorted(targets)
    if target.description:
        description = target.description
    elif target.kind == "trivy" and target.mode in {"fs", "image"}:
        description = f"trivy {target.mode} scanners={','.join(sorted(set(target.scanners)))}"
    elif target.mode == "config":
        description = "trivy config misconfiguration"
    elif target.mode == "sbom":
        description = "trivy sbom of dpkg inventory (ssh dispatch packages)"
    elif target.kind == "gitleaks":
        description = f"gitleaks {target.mode} default+extorq rules"
    else:
        description = f"semgrep rulesets={','.join(sorted(target.rulesets))}"
    return ScanScope(
        targets=targets, description=description, scope_hash=scope_hash(targets, description)
    )
