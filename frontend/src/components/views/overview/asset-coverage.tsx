import { cn } from "cn";
import { Boxes, FolderGit2, Laptop, type LucideIcon, Server, Waypoints } from "lucide-react";
import Link from "next/link";

import { CardLink, SectionCard } from "@/components/console/section-card";
import { StatusDot } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AssetClassCoverage } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount } from "@/lib/format";
import { retiredHiddenText } from "@/lib/lifecycle";
import { CLASS_NOUN, type ClassRow, plural } from "@/lib/overview";
import { assetHref } from "@/lib/security/ids";

const CLASS_ICON: Record<string, LucideIcon> = {
  macos_host: Laptop,
  linux_host: Server,
  kubernetes_cluster: Boxes,
  github_repository: FolderGit2,
};

const STATUS_WORD: Record<string, string> = { ok: "healthy", degraded: "degraded", stale: "stale", missing: "missing" };

/**
 * Coverage of the four monitored asset classes: one row each with its icon, the assets of
 * the class (from the asset list), how many report, when the last event arrived, and the
 * status with the reason built from the API counts. Nothing is hidden or softened: a class
 * with a stale or collector-less asset reads "Degraded" and says why.
 */
export function AssetCoverageCard({
  rows,
  others,
  now,
  assetsUnavailable,
  retiredHidden = 0,
  className,
}: {
  rows: ClassRow[];
  others: AssetClassCoverage[];
  now: string;
  assetsUnavailable: boolean;
  /** Retired assets the API left out of the rollups (overview `lifecycle.retired`). */
  retiredHidden?: number;
  className?: string;
}) {
  const retiredText = retiredHiddenText(retiredHidden, { one: "asset", many: "assets" });
  return (
    <SectionCard
      title="Asset coverage"
      titleId="coverage-title"
      icon={Waypoints}
      description="The four monitored asset classes"
      className={className}
      flush
      action={
        <Link href="/assets" className="group/link">
          <CardLink>Assets</CardLink>
        </Link>
      }
      footer={
        others.length > 0 || assetsUnavailable || retiredText ? (
          <span>
            {others.length > 0 ? (
              <>
                Also reported:{" "}
                {others
                  .map(
                    (c) =>
                      `${plural(c.assets_total, assetTypeLabel(c.asset_type), `${assetTypeLabel(c.asset_type)}s`)} (${c.assets_without_collector === c.assets_total ? "no collector" : STATUS_WORD[c.status] ?? c.status})`,
                  )
                  .join(" · ")}
                .
              </>
            ) : null}
            {assetsUnavailable ? " Asset names could not be loaded." : null}
            {retiredText ? (
              <>
                {" "}
                <Link href="/assets?retired=1" className="text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
                  {retiredText}
                </Link>{" "}
                (no collector reports, not observed within the retirement window).
              </>
            ) : null}
          </span>
        ) : undefined
      }
    >
      <ul className="divide-y divide-hairline-soft border-t border-hairline-soft">
        {rows.map((row) => {
          const Icon = CLASS_ICON[row.assetType] ?? Server;
          const noun = CLASS_NOUN[row.assetType] ?? { one: "asset", many: "assets" };
          const names = row.assets ?? [];
          const first = names[0];
          const href = names.length === 1 && first ? assetHref(first.asset_id) : "/assets";
          return (
            <li key={row.assetType} className="group/row relative transition-colors duration-150 hover:bg-hover">
              <Link
                href={href}
                className="flex items-start gap-3.5 px-5 py-3 outline-none focus-visible:bg-hover focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:ring-inset"
              >
                <span
                  aria-hidden="true"
                  className="mt-0.5 flex size-8 flex-none items-center justify-center rounded-lg bg-white/[0.04] text-fg-2 ring-1 ring-hairline ring-inset"
                >
                  <Icon className="size-4" strokeWidth={1.75} />
                </span>
                <span className="grid min-w-0 flex-1 gap-0.5">
                  <span className="flex items-center justify-between gap-3">
                    <span className="truncate text-sm font-medium text-foreground">{row.label}</span>
                    <StatusDot tone={row.tone} label={row.statusLabel} className="text-xs" />
                  </span>
                  <span className="flex min-w-0 items-center justify-between gap-3 text-sm text-muted-foreground">
                    <span className="min-w-0 truncate">
                      {names.length > 0 ? (
                        <span className="font-mono text-fg-2">
                          <UntrustedText value={names.map((a) => a.name).join(", ")} oneLine plain />
                        </span>
                      ) : row.total === 0 ? (
                        `No ${noun.one} reporting`
                      ) : (
                        plural(row.total, noun.one, noun.many)
                      )}
                    </span>
                    <span className="flex-none text-xs">
                      {row.coverage?.last_event_at ? (
                        <>
                          last event <RelativeTime value={row.coverage.last_event_at} now={now} plain className="text-xs" />
                        </>
                      ) : (
                        "no event yet"
                      )}
                    </span>
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {row.coverage ? (
                      <span className="tabular-nums">
                        <span className="text-fg-2">{formatCount(row.reporting)}</span>/{formatCount(row.total)} reporting
                      </span>
                    ) : null}
                    {row.coverage ? " · " : null}
                    <span className={cn(row.reason && row.tone !== "ok" && "text-fg-2")}>{row.reason ?? "all collectors fresh"}</span>
                    {row.retired > 0 ? ` · ${formatCount(row.retired)} retired hidden` : null}
                  </span>
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </SectionCard>
  );
}
