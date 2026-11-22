import { cn } from "cn";
import { CornerDownRight } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/console/states";
import { LifecycleBadge, StatusDot } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ApiResult } from "@/lib/api/result";
import type { AssetDetailResponse, AssetListItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

import { AssetCard } from "./asset-card";
import { AssetIconTile, CLASS_ICON } from "./asset-icon";
import { type AssetClass, assetStatus, classStatus } from "./model";

/**
 * Owner accounts of a class (GitHub accounts): context for the repositories, never monitored
 * themselves (the API marks the type as not expected to have a collector). Listed with their
 * collector state stated plainly, so nothing is hidden and nothing reads as a coverage failure.
 */
function OwnerAccountsCard({ accounts, repositories }: { accounts: AssetListItem[]; repositories: AssetListItem[] }) {
  const rowLink =
    "flex min-h-9 items-center justify-between gap-3 px-3.5 py-1.5 transition-colors duration-150 outline-none hover:bg-hover focus-visible:bg-hover focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:ring-inset";
  return (
    // A context panel, not a monitored-asset card: no card fill, its own height (top-aligned
    // beside the repository cards), so it never stretches into a blank band.
    <article className="flex min-w-0 flex-col self-start rounded-xl bg-white/[0.012] ring-1 ring-hairline">
      <header className="flex items-start gap-3 px-5 pt-5 pb-4">
        <AssetIconTile assetType="github_account" />
        <div className="min-w-0 flex-1">
          <h3 className="text-base leading-5 font-semibold tracking-tight text-foreground">Owner accounts</h3>
          <p className="mt-1 text-xs text-muted-foreground">
            {formatCount(accounts.length)} GitHub account{accounts.length === 1 ? "" : "s"} · context, not monitored
          </p>
        </div>
      </header>
      <ul className="mx-5 divide-y divide-hairline-soft overflow-hidden rounded-lg ring-1 ring-hairline-soft ring-inset">
        {accounts.map((account) => {
          const owned = repositories.filter((r) => r.parent_asset_id === account.asset_id);
          return (
            <li key={account.asset_id} className="py-1">
              <Link href={assetHref(account.asset_id)} className={rowLink}>
                <span className="min-w-0 truncate text-sm font-medium text-fg-2">
                  <UntrustedText value={account.display_name ?? account.name} oneLine plain />
                </span>
                <span className="flex flex-none items-center gap-2">
                  {account.lifecycle_state && account.lifecycle_state !== "active" ? (
                    <LifecycleBadge state={account.lifecycle_state} plain />
                  ) : (
                    <StatusDot
                      tone={account.collectors_total > 0 ? (account.coverage_status === "ok" ? "ok" : "warn") : "off"}
                      label={
                        account.collectors_total > 0
                          ? `${formatCount(account.collectors_total)} collector${account.collectors_total === 1 ? "" : "s"}`
                          : "No collector"
                      }
                      className="text-xs text-muted-foreground"
                    />
                  )}
                </span>
              </Link>
              {owned.length > 0 ? (
                <ul aria-label="Repositories of this account">
                  {owned.map((repo) => {
                    const status = assetStatus(repo);
                    return (
                      <li key={repo.asset_id}>
                        <Link href={assetHref(repo.asset_id)} className={rowLink}>
                          <span className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                            <CornerDownRight className="size-3.5 flex-none text-fg-faint" aria-hidden="true" />
                            <span className="min-w-0 truncate font-mono">
                              <UntrustedText value={repo.display_name ?? repo.name} oneLine plain />
                            </span>
                          </span>
                          <span className="flex flex-none items-center gap-2">
                            {status.kind === "lifecycle" ? (
                              <LifecycleBadge state={status.state} plain />
                            ) : (
                              <StatusDot tone={status.health.tone} label={status.health.label} className="text-xs text-muted-foreground" />
                            )}
                          </span>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              ) : null}
            </li>
          );
        })}
      </ul>
      <footer className="px-5 pt-3 pb-4 text-xs leading-relaxed text-muted-foreground">
        Accounts own the repositories. ExtorQ monitors repositories, not accounts, so no collector is expected for an
        account.
      </footer>
    </article>
  );
}

/**
 * One asset class: a heading with the class status (API rule, from the rows) and how many of its
 * assets report, then its asset cards. A class with one card takes one column of the page grid;
 * larger classes take the full row with cards side by side.
 */
export function AssetClassGroup({
  cls,
  assets,
  context,
  details,
  now,
}: {
  cls: AssetClass;
  /** Monitored assets of the class, in display order. */
  assets: AssetListItem[];
  /** Context assets of the class (owner accounts). */
  context: AssetListItem[];
  details: Map<string, ApiResult<AssetDetailResponse>>;
  now: string;
}) {
  const Icon = CLASS_ICON[cls.key];
  const status = classStatus(assets);
  const tiles = assets.length + (context.length > 0 ? 1 : 0);
  const wide = tiles > 1;
  const titleId = `class-${cls.key}`;
  // Short names (e.g. "extorq-lab") for the relationship line of child assets.
  const names = new Map(assets.map((a) => [a.asset_id, a.name]));

  return (
    <section aria-labelledby={titleId} className={cn("grid min-w-0 content-start gap-3", wide && "lg:col-span-2")}>
      <div className="flex min-h-7 flex-wrap items-center gap-x-3 gap-y-1">
        <h2 id={titleId} className="flex items-center gap-2 text-lg font-semibold tracking-tight text-foreground">
          <Icon className="size-4 text-muted-foreground" strokeWidth={1.75} aria-hidden="true" />
          {cls.title}
        </h2>
        {assets.length > 0 ? (
          <>
            <StatusDot tone={status.tone} label={status.label} className="text-xs" />
            <span className="text-xs text-muted-foreground tabular-nums">{status.summary}</span>
          </>
        ) : null}
      </div>
      {tiles === 0 ? (
        <EmptyState compact={false} className="min-h-40 bg-card/40">
          {cls.empty}
        </EmptyState>
      ) : (
        <div className={cn("grid gap-4", wide && "lg:grid-cols-2")}>
          {assets.map((asset) => {
            const parentName = asset.parent_asset_id ? names.get(asset.parent_asset_id) : undefined;
            const context =
              asset.asset_type === "kubernetes_node" && asset.parent_asset_id ? (
                <>
                  Node of <UntrustedText value={parentName ?? asset.parent_asset_id} plain limit={40} />
                </>
              ) : undefined;
            return (
              <AssetCard
                key={asset.asset_id}
                asset={asset}
                detail={details.get(asset.asset_id) ?? null}
                now={now}
                context={context}
              />
            );
          })}
          {context.length > 0 ? <OwnerAccountsCard accounts={context} repositories={assets} /> : null}
        </div>
      )}
    </section>
  );
}
