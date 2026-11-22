"""Collector configuration: ``config/collectors/*.yaml`` (no secrets in these files).

Each file holds one collector mapping, a list of mappings, or ``{collectors: [...]}``::

    collectors:
      - collector_id: linux-lab-vm-01
        producer_id: linux-ssh-lab-vm-01
        asset_id: linux:lab-vm-01
        module: extorq_collectors.linux.collector:LinuxSSHCollector
        interval_seconds: 60
        enabled: true
        settings: {ssh: {host: 127.0.0.1, port: 2222}}

Tokens are never configured here: the runner reads
``var/secrets/tokens/<producer_id>.token``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from extorq.contracts.common import AssetId, Identifier


class CollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: Identifier
    producer_id: Identifier
    asset_id: AssetId
    module: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
    interval_seconds: int = Field(ge=1, le=86400)
    enabled: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)
    #: Path of the YAML file this entry came from (set by the loader).
    source_file: str | None = None

    @field_validator("settings")
    @classmethod
    def _no_secret_values(cls, value: dict[str, Any]) -> dict[str, Any]:
        paths = secret_setting_paths(value)
        if paths:
            from extorq.common.redaction import redact_text

            shown = ", ".join(redact_text(p)[0] for p in paths[:5])
            raise ValueError(
                f"collector settings appear to contain a secret ({shown}); "
                "reference it by path with a *_file setting instead"
            )
        return value


def secret_setting_paths(value: Any, path: str = "", key: str = "") -> list[str]:
    """Dotted paths of settings whose STRING value (or key) looks like a secret.

    Each string is checked together with its own key (``"<key>: <value>"``), so key-based
    rules (``password: x``) still apply, but booleans, numbers, dates and nulls are never
    candidates. The result contains only setting paths.
    """
    from extorq.common.redaction import contains_secret

    found: list[str] = []
    if isinstance(value, dict):
        for raw_key, item in value.items():
            child_key = str(raw_key)
            child = f"{path}.{child_key}" if path else child_key
            if contains_secret(child_key):
                found.append(child)
            found.extend(secret_setting_paths(item, child, child_key))
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            found.extend(secret_setting_paths(item, f"{path}[{index}]", key))
    elif isinstance(value, str) and contains_secret(f"{key or 'value'}: {value}"):
        found.append(path or "value")
    return found


class ConfigLoadError(ValueError):
    pass


def _describe(exc: ValidationError, max_errors: int = 5) -> str:
    """Field locations and messages only: pydantic's ``str(exc)`` embeds the input values,
    which may be the very secret the check refused."""
    errors = exc.errors(include_url=False, include_input=False, include_context=False)
    parts = [
        f"{'.'.join(str(p) for p in err.get('loc', ())) or 'entry'}: {err.get('msg', '')}"
        for err in errors[:max_errors]
    ]
    if len(errors) > max_errors:
        parts.append(f"(+{len(errors) - max_errors} more)")
    return "; ".join(parts)


def _entries(document: Any, path: Path) -> list[dict[str, Any]]:
    if document is None:
        return []
    if isinstance(document, dict) and "collectors" in document:
        document = document["collectors"]
    if isinstance(document, dict):
        return [document]
    if isinstance(document, list) and all(isinstance(item, dict) for item in document):
        return list(document)
    raise ConfigLoadError(f"{path.name}: expected a mapping, a list or {{collectors: [...]}}")


def load_collector_configs(
    directory: Path, *, include_disabled: bool = False
) -> list[CollectorConfig]:
    """Load every ``*.yaml``/``*.yml`` in ``directory`` (sorted); collector ids must be unique."""
    if not directory.is_dir():
        raise ConfigLoadError(f"collector config directory not found: {directory}")
    paths = sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")])
    return load_collector_files(paths, include_disabled=include_disabled)


def load_collector_files(
    paths: list[Path], *, include_disabled: bool = False
) -> list[CollectorConfig]:
    """Load the given YAML files in order; collector ids must be unique across them."""
    configs: list[CollectorConfig] = []
    seen: dict[str, str] = {}
    for path in paths:
        if not path.is_file():
            raise ConfigLoadError(f"collector config file not found: {path}")
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigLoadError(f"{path.name}: unreadable ({type(exc).__name__})") from None
        for index, entry in enumerate(_entries(document, path)):
            try:
                config = CollectorConfig.model_validate({**entry, "source_file": path.name})
            except ValidationError as exc:
                raise ConfigLoadError(f"{path.name}[{index}]: {_describe(exc)}") from None
            if config.collector_id in seen:
                raise ConfigLoadError(
                    f"duplicate collector_id {config.collector_id} in {path.name} "
                    f"and {seen[config.collector_id]}"
                )
            seen[config.collector_id] = path.name
            if config.enabled or include_disabled:
                configs.append(config)
    return configs
