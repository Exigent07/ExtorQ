"""Scanner runner configuration (``config/scanners.yaml``). Contains no secrets.

Paths are relative to the repository root and are confined to it: absolute
paths, ``..`` components, symlink escapes and characters that would break
``docker --mount`` syntax are rejected. Images must be pinned by digest.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from extorq.contracts import Severity

_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]{1,128})?@sha256:[0-9a-f]{64}$")
_LOCAL_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$")
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_ASSET = re.compile(r"^[a-z0-9][a-z0-9._:/-]{2,199}$")
_REL_PATH = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./ -]{0,511}$")
_REGISTRY_ID = re.compile(r"^p/[a-z0-9][a-z0-9-]{0,63}$")

ScanKind = Literal["trivy", "gitleaks", "semgrep", "linux-packages"]
KIND_MODES: dict[str, set[str]] = {
    "trivy": {"fs", "config", "image"},
    "linux-packages": {"sbom"},
    "gitleaks": {"dir", "git"},
    "semgrep": {"scan"},
}
TOOL_BY_KIND = {"trivy": "trivy", "linux-packages": "trivy", "gitleaks": "gitleaks", "semgrep": "semgrep"}


class ConfigError(ValueError):
    """Configuration is invalid (message names the problem, never secret values)."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


def validate_rel_path(value: str) -> str:
    text = value.strip()
    if (
        not text
        or not _REL_PATH.match(text)
        or text.startswith("/")
        or any(part in {"..", ""} for part in text.rstrip("/").split("/"))
        or "," in text
    ):
        raise ValueError(f"path {value!r} must be a plain repository-relative path")
    return text.rstrip("/")


class GatewayConfig(_Model):
    url: str = "https://127.0.0.1:8443"
    token_file: str = "var/secrets/tokens/scanner-runner.token"
    ca_file: str = "var/tls/ca.crt"
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    @field_validator("token_file", "ca_file")
    @classmethod
    def _rel(cls, v: str) -> str:
        return validate_rel_path(v)


class DockerConfig(_Model):
    binary: str = "docker"
    container_prefix: str = "extorq-c3-scan"
    memory: str = Field(default="2g", pattern=r"^[0-9]{1,5}[mg]$")
    cpus: str = Field(default="4", pattern=r"^[0-9]{1,2}(\.[0-9])?$")
    pids_limit: int = Field(default=512, ge=64, le=8192)
    tmpfs_mb: int = Field(default=512, ge=64, le=4096)
    #: Semgrep publishes linux/amd64 images only (emulated on Apple Silicon).
    semgrep_platform: str | None = "linux/amd64"

    @field_validator("container_prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9][a-z0-9-]{2,40}$", v):
            raise ValueError("container_prefix must be a short lower-case slug")
        return v


class ImagesConfig(_Model):
    trivy: str
    gitleaks: str
    semgrep: str

    @field_validator("trivy", "gitleaks", "semgrep")
    @classmethod
    def _pinned(cls, v: str) -> str:
        if not _IMAGE.match(v):
            raise ValueError(f"image {v!r} must be pinned as name[:tag]@sha256:<digest>")
        return v


class TrivyConfig(_Model):
    cache_dir: str = "var/cache/trivy"
    db_max_age_hours: int = Field(default=24, ge=1, le=24 * 30)
    timeout_seconds: int = Field(default=900, ge=30, le=7200)
    db_update_timeout_seconds: int = Field(default=900, ge=30, le=7200)
    max_output_mb: int = Field(default=128, ge=1, le=1024)

    @field_validator("cache_dir")
    @classmethod
    def _rel_paths(cls, v: str) -> str:
        return validate_rel_path(v)


class GitleaksConfig(_Model):
    config_file: str = "scanners/rules/gitleaks/extorq-gitleaks.toml"
    timeout_seconds: int = Field(default=600, ge=30, le=7200)
    max_output_mb: int = Field(default=16, ge=1, le=512)
    max_target_megabytes: int = Field(default=10, ge=1, le=1024)
    default_severity: Severity = Severity.HIGH
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)

    @field_validator("config_file")
    @classmethod
    def _rel_paths(cls, v: str) -> str:
        return validate_rel_path(v)


class RulesetConfig(_Model):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9/_.-]{1,63}$")
    source: Literal["registry", "local"]
    #: registry: Semgrep registry pack id (e.g. p/python), fetched host-side and cached.
    registry_id: str | None = None
    #: local: repository-relative rule file.
    path: str | None = None
    max_age_hours: int = Field(default=168, ge=1, le=24 * 90)

    @model_validator(mode="after")
    def _check(self) -> RulesetConfig:
        if self.source == "registry":
            if not self.registry_id or not _REGISTRY_ID.match(self.registry_id):
                raise ValueError("registry rulesets need registry_id like 'p/python'")
        else:
            if not self.path:
                raise ValueError("local rulesets need a path")
            self.path = validate_rel_path(self.path)
        return self


class SemgrepConfig(_Model):
    timeout_seconds: int = Field(default=900, ge=30, le=7200)
    max_output_mb: int = Field(default=64, ge=1, le=1024)
    per_rule_timeout_seconds: int = Field(default=30, ge=1, le=600)
    max_target_bytes: int = Field(default=1_000_000, ge=1000, le=100_000_000)
    jobs: int = Field(default=4, ge=1, le=16)
    registry_url: str = "https://semgrep.dev/c/"
    cache_dir: str = "var/cache/semgrep"
    fetch_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    rulesets: dict[str, RulesetConfig] = Field(default_factory=dict)

    @field_validator("cache_dir")
    @classmethod
    def _rel_paths(cls, v: str) -> str:
        return validate_rel_path(v)


class InventoryConfig(_Model):
    #: B1's collector config holding the ``ssh:`` block (reused, not duplicated).
    linux_collector_config: str = "config/collectors/linux.yaml"
    timeout_seconds: int = Field(default=120, ge=5, le=1800)

    @field_validator("linux_collector_config")
    @classmethod
    def _rel_paths(cls, v: str) -> str:
        return validate_rel_path(v)


class TargetConfig(_Model):
    name: str
    kind: ScanKind
    mode: str
    asset_id: str
    paths: list[str] = Field(default_factory=list, max_length=64)
    image: str | None = None
    #: trivy fs/image: scanner modules (vuln, misconfig).
    scanners: list[Literal["vuln", "misconfig"]] = Field(default_factory=lambda: ["vuln"])
    #: semgrep: names of rulesets defined under semgrep.rulesets.
    rulesets: list[str] = Field(default_factory=list)
    description: str | None = Field(default=None, max_length=200)
    when_missing: Literal["skip", "fail"] = "fail"
    enabled: bool = True
    interval_seconds: int = Field(default=86400, ge=60, le=7 * 86400)

    @model_validator(mode="after")
    def _check(self) -> TargetConfig:
        if not _SLUG.match(self.name):
            raise ValueError(f"target name {self.name!r} must be a lower-case slug")
        if not _ASSET.match(self.asset_id):
            raise ValueError(f"target {self.name}: invalid asset_id {self.asset_id!r}")
        if self.mode not in KIND_MODES[self.kind]:
            raise ValueError(f"target {self.name}: mode {self.mode!r} invalid for kind {self.kind}")
        self.paths = [validate_rel_path(p) for p in self.paths]
        needs_paths = self.mode in {"fs", "config", "dir", "git", "scan"}
        if needs_paths and not self.paths:
            raise ValueError(f"target {self.name}: mode {self.mode} needs at least one path")
        if self.mode in {"fs", "dir", "git"} and len(self.paths) != 1:
            raise ValueError(f"target {self.name}: mode {self.mode} takes exactly one path")
        if self.mode == "image":
            if not self.image or not _LOCAL_IMAGE.match(self.image):
                raise ValueError(f"target {self.name}: image mode needs a valid image reference")
        elif self.image is not None:
            raise ValueError(f"target {self.name}: image is only valid for mode image")
        if self.kind == "semgrep" and not self.rulesets:
            raise ValueError(f"target {self.name}: semgrep targets need rulesets")
        return self

    @property
    def tool(self) -> str:
        return TOOL_BY_KIND[self.kind]


class ScannersConfig(_Model):
    version: Literal[1]
    producer_id: str = Field(default="scanner-runner", pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")
    work_dir: str = "var/cache/scanners"
    state_dir: str = "var/state/scanners"
    emit_health: bool = True
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    images: ImagesConfig
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    inventory: InventoryConfig = Field(default_factory=InventoryConfig)
    targets: list[TargetConfig] = Field(min_length=1, max_length=200)

    @field_validator("work_dir", "state_dir")
    @classmethod
    def _rel_paths(cls, v: str) -> str:
        return validate_rel_path(v)

    @model_validator(mode="after")
    def _check(self) -> ScannersConfig:
        names = [t.name for t in self.targets]
        if len(names) != len(set(names)):
            raise ValueError("target names must be unique")
        for target in self.targets:
            missing = [r for r in target.rulesets if r not in self.semgrep.rulesets]
            if missing:
                raise ValueError(f"target {target.name}: unknown rulesets {missing}")
        return self

    def select(self, kind: str, names: list[str] | None = None) -> list[TargetConfig]:
        """Targets for ``run <kind>`` (``all`` = every kind), optionally by name."""
        pool = [t for t in self.targets if t.enabled and (kind == "all" or t.kind == kind)]
        if names:
            unknown = sorted(set(names) - {t.name for t in pool})
            if unknown:
                raise ConfigError(f"unknown or disabled targets for '{kind}': {', '.join(unknown)}")
            pool = [t for t in pool if t.name in set(names)]
        return pool


def load_config(path: Path) -> ScannersConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {type(exc).__name__}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path.name}: {exc}") from None
    try:
        return ScannersConfig.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10]
        )
        raise ConfigError(f"invalid {path.name}: {details}") from None


def resolve_in_root(root: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``root``; reject anything that escapes it (incl. via symlinks)."""
    root_resolved = root.resolve()
    candidate = (root_resolved / rel).resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ConfigError(f"path {rel!r} resolves outside the repository root")
    return candidate
