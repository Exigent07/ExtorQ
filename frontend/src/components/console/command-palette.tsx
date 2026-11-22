"use client";

import { cn } from "cn";
import {
  Activity,
  ArrowUpRight,
  Boxes,
  ChartSpline,
  FileSearch,
  FolderGit2,
  Laptop,
  LayoutDashboard,
  Search,
  Server,
  ShieldAlert,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import type { Severity } from "@/lib/api/schemas";
import { analystStatusLabel, formatUtcShort } from "@/lib/format";
import { isHexId, isRuleId } from "@/lib/security/ids";
import type { PaletteData } from "@/lib/palette";

import { SEVERITY_LABEL, SeverityDot } from "./severity";

const PAGES = [
  { href: "/", label: "Overview", group: "Monitor", icon: LayoutDashboard },
  { href: "/assets", label: "Assets", group: "Monitor", icon: Server },
  { href: "/detections", label: "Detections", group: "Detect", icon: ShieldAlert },
  { href: "/health", label: "System health", group: "Operate", icon: Activity },
] as const;

const ASSET_ICON: Record<string, typeof Server> = {
  "macOS host": Laptop,
  "Linux VM": Server,
  "Kubernetes cluster": Boxes,
  "Kubernetes node": Boxes,
  "GitHub repository": FolderGit2,
  "GitHub account": FolderGit2,
};

const COVERAGE_DOT: Record<string, string> = {
  ok: "bg-health-ok",
  degraded: "bg-health-warn",
  stale: "bg-health-warn",
  missing: "bg-health-bad",
};

/**
 * Cmd/Ctrl-K palette: jump to pages, recent alerts (by rule, title or id) and assets.
 *
 * Every list arrives as props from server components (fetched through the API client and
 * sanitised there); this component never calls the API. Two quick actions are built from
 * what the analyst typed, after validation: a rule id opens the Detections filter, a 32-hex
 * alert id opens its investigation. `data === null` while the lists are still loading.
 */
export function CommandPalette({ data, grafanaUrl }: { data: PaletteData | null; grafanaUrl: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  function go(href: string) {
    setOpen(false);
    setQuery("");
    router.push(href);
  }

  const trimmed = query.trim();
  const ruleQuery = trimmed.toUpperCase();
  const asRule = isRuleId(ruleQuery) ? ruleQuery : null;
  const asAlertId = isHexId(trimmed.toLowerCase()) ? trimmed.toLowerCase() : null;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Search pages, alerts and assets"
        aria-keyshortcuts="Meta+K Control+K"
        className="group flex h-8 items-center gap-2 rounded-lg px-2 text-sm text-muted-foreground ring-1 ring-hairline transition-colors duration-150 ring-inset hover:bg-hover hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none lg:w-44 lg:justify-start xl:w-60 lg:bg-white/[0.02] lg:px-2.5"
      >
        <Search className="size-4 flex-none" aria-hidden="true" />
        <span className="hidden lg:inline">Search…</span>
        <kbd className="ml-auto hidden h-5 items-center gap-0.5 rounded-md px-1.5 font-mono text-xs leading-none text-muted-foreground ring-1 ring-hairline-strong ring-inset lg:inline-flex">
          ⌘K
        </kbd>
      </button>
      <CommandDialog
        open={open}
        onOpenChange={(value) => {
          setOpen(value);
          if (!value) setQuery("");
        }}
        title="Search ExtorQ"
        description="Jump to a page, a recent alert or an asset."
        className="max-w-[calc(100%-2rem)] sm:max-w-xl"
      >
        <Command className="rounded-none! bg-transparent p-0">
          <CommandInput value={query} onValueChange={setQuery} placeholder="Search pages, alerts by rule or id, assets…" />
          <CommandList className="max-h-[min(26rem,60vh)]">
            <CommandEmpty>No page, alert or asset matches.</CommandEmpty>

            {asRule || asAlertId ? (
              <CommandGroup heading="Quick actions">
                {asRule ? (
                  <CommandItem value={`${trimmed} rule filter`} onSelect={() => go(`/detections?rule=${asRule}&range=30d`)}>
                    <ShieldAlert aria-hidden="true" />
                    Show alerts of rule <span className="font-mono">{asRule}</span>
                    <span data-slot="command-shortcut" className="ml-auto text-xs text-muted-foreground">last 30 days</span>
                  </CommandItem>
                ) : null}
                {asAlertId ? (
                  <CommandItem value={`${trimmed} open investigation`} onSelect={() => go(`/investigations/${asAlertId}`)}>
                    <FileSearch aria-hidden="true" />
                    Open investigation <span className="truncate font-mono">{asAlertId.slice(0, 12)}…</span>
                  </CommandItem>
                ) : null}
              </CommandGroup>
            ) : null}

            <CommandGroup heading="Go to">
              {PAGES.map((page) => {
                const Icon = page.icon;
                return (
                  <CommandItem key={page.href} value={`${page.label} ${page.group} page`} onSelect={() => go(page.href)}>
                    <Icon aria-hidden="true" />
                    {page.label}
                    <span data-slot="command-shortcut" className="ml-auto text-xs text-muted-foreground">{page.group}</span>
                  </CommandItem>
                );
              })}
              <CommandItem
                value="Grafana dashboards analytics external"
                onSelect={() => {
                  setOpen(false);
                  window.open(grafanaUrl, "_blank", "noopener,noreferrer");
                }}
              >
                <ChartSpline aria-hidden="true" />
                Grafana
                <span data-slot="command-shortcut" className="ml-auto">
                  <ArrowUpRight className="size-3.5 text-muted-foreground" aria-hidden="true" />
                </span>
              </CommandItem>
            </CommandGroup>

            <CommandSeparator />
            <CommandGroup heading="Recent alerts · last 30 days">
              {data === null ? (
                <CommandItem disabled value="loading alerts">
                  Loading alerts…
                </CommandItem>
              ) : data.alerts === null ? (
                <CommandItem disabled value="alerts unavailable">
                  Alerts could not be loaded. Use Detections instead.
                </CommandItem>
              ) : data.alerts.length === 0 ? (
                <CommandItem disabled value="no alerts">
                  No alert in the last 30 days.
                </CommandItem>
              ) : (
                data.alerts.map((alert) => (
                  <CommandItem
                    key={alert.id}
                    value={`${alert.ruleId} ${alert.title} ${alert.id} ${alert.assetId} ${alert.severity}`}
                    onSelect={() => go(alert.href)}
                    className="gap-2.5"
                  >
                    <SeverityDot severity={alert.severity as Severity} />
                    <span className="sr-only">{SEVERITY_LABEL[alert.severity as Severity]}</span>
                    <span className="flex-none font-mono text-xs text-muted-foreground">{alert.ruleId}</span>
                    <span className="min-w-0 truncate">{alert.title}</span>
                    <span data-slot="command-shortcut" className="ml-auto hidden flex-none text-xs text-muted-foreground sm:inline">
                      {analystStatusLabel(alert.status)} · {formatUtcShort(alert.lastSeen)}
                    </span>
                  </CommandItem>
                ))
              )}
            </CommandGroup>

            <CommandSeparator />
            <CommandGroup heading="Assets">
              {data === null ? (
                <CommandItem disabled value="loading assets">
                  Loading assets…
                </CommandItem>
              ) : data.assets === null ? (
                <CommandItem disabled value="assets unavailable">
                  Assets could not be loaded. Use the Assets page instead.
                </CommandItem>
              ) : (
                data.assets.map((asset) => {
                  const Icon = ASSET_ICON[asset.typeLabel] ?? Server;
                  return (
                    <CommandItem
                      key={asset.id}
                      value={`${asset.label} ${asset.id} ${asset.typeLabel}`}
                      onSelect={() => go(asset.href)}
                      className="gap-2.5"
                    >
                      <Icon aria-hidden="true" />
                      <span className="min-w-0 truncate">{asset.label}</span>
                      <span className="hidden min-w-0 truncate font-mono text-xs text-muted-foreground sm:inline">{asset.id}</span>
                      <span data-slot="command-shortcut" className="ml-auto flex flex-none items-center gap-1.5 text-xs text-muted-foreground">
                        <span aria-hidden="true" className={cn("size-1.5 rounded-full", COVERAGE_DOT[asset.coverage] ?? "bg-health-off")} />
                        {asset.typeLabel}
                      </span>
                    </CommandItem>
                  );
                })
              )}
            </CommandGroup>
          </CommandList>
        </Command>
        <div className="flex items-center justify-between gap-4 border-t border-hairline px-3 py-2 text-xs text-muted-foreground">
          <span>
            <kbd className="font-mono">↑↓</kbd> to move · <kbd className="font-mono">↵</kbd> to open
          </span>
          <span>
            <kbd className="font-mono">esc</kbd> to close
          </span>
        </div>
      </CommandDialog>
    </>
  );
}
