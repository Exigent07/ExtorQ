import { Archive, ChevronDown } from "lucide-react";
import Link from "next/link";

import { ErrorState } from "@/components/console/states";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiFailure } from "@/lib/api/result";
import type { AssetListItem } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount } from "@/lib/format";
import { humanizeLifecycleReason } from "@/lib/lifecycle";
import { assetHref } from "@/lib/security/ids";

import { AssetIconTile } from "./asset-icon";

/** Anchor of the section (the Overview and the page notice link here). */
export const RETIRED_SECTION_ID = "retired-assets";

/**
 * Retired assets, apart from the monitored classes: collapsed by default, counted in the
 * header so nothing disappears silently. The API retires an asset when no collector covering it
 * reports and it was not observed within the retirement window; retired assets are kept (their
 * pages, alerts and findings stay reachable) and left out of coverage, KPIs and health rollups.
 * Rows are muted: no health colour, the API's own reason in words.
 */
export function RetiredAssetsSection({
  count,
  assets,
  error,
  defaultOpen,
  now,
}: {
  /** Retired assets the API left out of the default list (`retired_excluded`). */
  count: number;
  /** The retired assets (from `include_retired=true`); null when that read failed. */
  assets: AssetListItem[] | null;
  error: Pick<ApiFailure, "message" | "requestId" | "kind"> | null;
  defaultOpen: boolean;
  now: string;
}) {
  const shown = assets?.length ?? count;
  return (
    <section id={RETIRED_SECTION_ID} aria-labelledby="retired-assets-title" className="mt-12 scroll-mt-20">
      <Collapsible defaultOpen={defaultOpen} className="rounded-xl bg-card/40 ring-1 ring-hairline">
        <div className="flex items-start gap-3 px-5 py-4">
          <span
            aria-hidden="true"
            className="flex size-9 flex-none items-center justify-center rounded-lg bg-white/[0.03] text-muted-foreground ring-1 ring-hairline ring-inset"
          >
            <Archive className="size-4" strokeWidth={1.75} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
              <h2 id="retired-assets-title" className="text-base font-semibold tracking-tight text-fg-2">
                Retired assets
              </h2>
              <span className="inline-flex h-5 items-center rounded-md px-1.5 text-xs text-muted-foreground tabular-nums ring-1 ring-hairline-strong ring-inset">
                {formatCount(shown)}
              </span>
            </div>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              No collector reports for them and they were not observed within the retirement window. Kept, never deleted;
              left out of coverage, KPIs and health.
            </p>
          </div>
          <CollapsibleTrigger asChild>
            <Button variant="ghost" size="sm" className="group mt-0.5 flex-none text-muted-foreground">
              <span className="group-data-[state=open]:hidden">
                Show<span className="sr-only"> retired assets</span>
              </span>
              <span className="hidden group-data-[state=open]:inline">
                Hide<span className="sr-only"> retired assets</span>
              </span>
              <ChevronDown
                data-icon="inline-end"
                className="transition-transform duration-150 group-data-[state=open]:rotate-180"
                aria-hidden="true"
              />
            </Button>
          </CollapsibleTrigger>
        </div>
        <CollapsibleContent className="border-t border-hairline-soft">
          {error || !assets ? (
            <div className="px-5 py-4">
              <ErrorState
                what="the retired assets"
                error={error ?? { kind: "server", message: "The list was not returned.", requestId: "-" }}
              />
            </div>
          ) : (
            <div className="pt-1 pb-2 [--table-edge:1.25rem]">
              <Table aria-label="Retired assets">
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead className="hidden md:table-cell">Type</TableHead>
                    <TableHead className="hidden lg:table-cell">Why retired (API)</TableHead>
                    <TableHead className="text-right">Last observed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => {
                    const reason = humanizeLifecycleReason(asset.lifecycle_reason);
                    return (
                      <TableRow key={asset.asset_id}>
                        <TableCell className="max-w-0 min-w-56">
                          <Link
                            href={assetHref(asset.asset_id)}
                            className="flex min-w-0 items-center gap-3 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
                          >
                            <AssetIconTile assetType={asset.asset_type} size="sm" className="opacity-70" />
                            <span className="min-w-0">
                              <span className="block truncate text-sm font-medium text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
                                <UntrustedText value={asset.display_name ?? asset.name} plain limit={80} />
                              </span>
                              <span className="block truncate font-mono text-xs text-muted-foreground">
                                <UntrustedText value={asset.asset_id} plain limit={120} />
                              </span>
                            </span>
                          </Link>
                        </TableCell>
                        <TableCell className="hidden text-xs text-muted-foreground md:table-cell">
                          {assetTypeLabel(asset.asset_type)}
                        </TableCell>
                        <TableCell className="hidden max-w-0 w-[40%] text-xs text-muted-foreground lg:table-cell">
                          <span className="block truncate">{reason ?? "No reason given by the API"}</span>
                        </TableCell>
                        <TableCell className="text-right">
                          <RelativeTime
                            value={asset.last_observed_at ?? asset.last_seen}
                            now={now}
                            className="text-xs text-muted-foreground"
                          />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              {assets.length < count ? (
                <p className="px-5 pt-2 text-xs text-muted-foreground">
                  The API counted {formatCount(count)} retired assets but returned {formatCount(assets.length)}.
                </p>
              ) : null}
            </div>
          )}
        </CollapsibleContent>
      </Collapsible>
    </section>
  );
}
