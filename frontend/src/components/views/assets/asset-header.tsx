import { cn } from "cn";
import Link from "next/link";
import type { ReactNode } from "react";

import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AssetDetailResponse } from "@/lib/api/schemas";
import { assetTypeLabel, DASH } from "@/lib/format";
import { assetHref, isAssetId } from "@/lib/security/ids";

import { AssetIconTile } from "./asset-icon";

function Fact({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 min-w-0 truncate text-sm text-fg-2">{children}</dd>
    </div>
  );
}

const PARENT_LABEL: Record<string, string> = {
  kubernetes_node: "Cluster",
  github_repository: "Owner account",
};

/** The asset's title for the page header: its type icon and display name (telemetry: plain text). */
export function AssetTitle({ assetType, name }: { assetType: string; name: string }) {
  return (
    <span className="flex min-w-0 items-center gap-3">
      <AssetIconTile assetType={assetType} size="lg" />
      <span className="min-w-0">
        <UntrustedText value={name} limit={80} />
      </span>
    </span>
  );
}

/**
 * Identity of the asset under the page title, shown on every tab: type, id, environment,
 * criticality, owner, parent, first seen, latest inventory report and the reporting producer.
 * Every value is as reported (telemetry rendered as text); missing values are a dash.
 */
export function AssetHeaderCard({ detail, now }: { detail: AssetDetailResponse; now: string }) {
  const a = detail.asset;
  const parent = a.parent_asset_id && isAssetId(a.parent_asset_id) ? a.parent_asset_id : null;
  return (
    <section aria-label="Asset identity" className="mb-6 rounded-xl bg-card shadow-card ring-1 ring-hairline">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 px-5 py-4 sm:grid-cols-3 lg:grid-cols-5">
        <Fact label="Type">{assetTypeLabel(a.asset_type)}</Fact>
        <Fact label="Asset id" className="col-span-2">
          <span className="font-mono text-xs text-foreground">
            <UntrustedText value={a.asset_id} oneLine mono />
          </span>
        </Fact>
        <Fact label="Environment">
          <UntrustedText value={a.environment} plain limit={32} />
        </Fact>
        <Fact label="Criticality">
          <UntrustedText value={a.criticality} plain limit={32} />
        </Fact>
        <Fact label={PARENT_LABEL[a.asset_type] ?? "Parent"}>
          {parent ? (
            <Link href={assetHref(parent)} className="font-mono text-xs text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
              <UntrustedText value={parent} plain limit={48} />
            </Link>
          ) : (
            <span className="text-muted-foreground">{DASH}</span>
          )}
        </Fact>
        <Fact label="Owner">
          <UntrustedText value={a.owner} plain limit={48} />
        </Fact>
        <Fact label="Observed by">
          <span className="font-mono text-xs">
            <UntrustedText value={a.observed_by} oneLine mono />
          </span>
        </Fact>
        <Fact label="First seen">
          <Timestamp value={a.first_seen} className="text-fg-2" />
        </Fact>
        <Fact label="Last inventory">
          <RelativeTime value={a.last_seen} now={now} />
        </Fact>
      </dl>
    </section>
  );
}
