"""Asset and inventory contracts (schema 1.0)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    AssetType,
    Attributes,
    ContractModel,
    Criticality,
    Environment,
    Identifier,
    Labels,
    MediumStr,
    SchemaVersion,
    ShortStr,
    UtcDatetime,
)


class Asset(ContractModel):
    """A monitored asset. Upserted by collectors; latest ``updated_at`` wins."""

    schema_version: SchemaVersion = SCHEMA_VERSION
    asset_id: AssetId
    asset_type: AssetType
    name: ShortStr
    display_name: ShortStr | None = None
    parent_asset_id: AssetId | None = None
    environment: Environment = Environment.LAB
    criticality: Criticality = Criticality.MEDIUM
    owner: ShortStr | None = None
    labels: Labels = Field(default_factory=dict)
    #: e.g. os_name, os_version, kernel, k8s_version, default_branch, visibility.
    attributes: Attributes = Field(default_factory=dict)
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    observed_by: Identifier


class InventoryItemType(StrEnum):
    PACKAGE = "package"
    PROCESS = "process"
    LISTENER = "listener"
    SERVICE = "service"
    SYSTEMD_UNIT = "systemd_unit"
    LAUNCH_ITEM = "launch_item"
    SOFTWARE = "software"
    USER = "user"
    GROUP = "group"
    CONFIG_FILE = "config_file"
    K8S_NAMESPACE = "k8s_namespace"
    K8S_WORKLOAD = "k8s_workload"
    K8S_POD = "k8s_pod"
    K8S_SERVICE_ACCOUNT = "k8s_service_account"
    K8S_ROLE = "k8s_role"
    K8S_BINDING = "k8s_binding"
    GITHUB_WORKFLOW = "github_workflow"
    GITHUB_BRANCH = "github_branch"


class InventoryItem(ContractModel):
    """One item of an asset inventory snapshot.

    Collectors send changed items (``present=True``) and tombstones for removed
    items (``present=False``), plus periodic full snapshots. ``item_key`` is
    stable within ``item_type`` for the asset (e.g. package name, unit path,
    ``<proto>:<addr>:<port>`` for listeners, ``<kind>/<ns>/<name>`` for k8s).
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    asset_id: AssetId
    item_type: InventoryItemType
    item_key: MediumStr
    attributes: Attributes = Field(default_factory=dict)
    snapshot_id: ShortStr
    observed_at: UtcDatetime
    present: bool = True
    collector_id: Identifier
