import { cn } from "cn";
import { Box, Boxes, ChevronRight, Container, Cpu, type LucideIcon, Network, Workflow } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { DASH, formatCount } from "@/lib/format";

export type LevelKey = "cluster" | "nodes" | "workloads" | "services" | "pods" | "containers";

const LEVEL_ICON: Record<LevelKey, LucideIcon> = {
  cluster: Boxes,
  nodes: Cpu,
  workloads: Workflow,
  services: Network,
  pods: Box,
  containers: Container,
};

export interface Level {
  key: LevelKey;
  label: string;
  /** Count from the API (null: not reported, shown as a dash). */
  count: number | null;
  description: ReactNode;
  href?: string | null;
  /** The level this page is about. */
  current?: boolean;
}

/**
 * The Kubernetes hierarchy as distinct, labelled levels: cluster, nodes, workloads, Kubernetes
 * Services and Pods / containers. Counts come from the API; a Kubernetes Service is a level of
 * its own and never a host service.
 */
export function KubernetesLevels({ levels, label }: { levels: Level[]; label: string }) {
  return (
    <nav aria-label={label}>
      <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:flex lg:items-stretch lg:gap-0">
        {levels.map((level, index) => {
          const Icon = LEVEL_ICON[level.key];
          const body = (
            <>
              <span className="flex items-center gap-2 text-xs text-muted-foreground">
                <Icon className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                {level.label}
              </span>
              <span className="mt-1.5 block text-xl leading-7 font-semibold tracking-tight text-foreground tabular-nums">
                {level.count === null ? <span className="text-muted-foreground">{DASH}</span> : formatCount(level.count)}
              </span>
              <span className="mt-0.5 block text-xs leading-snug text-muted-foreground">{level.description}</span>
            </>
          );
          const tile = cn(
            "block h-full rounded-xl px-4 py-3 ring-1 ring-inset transition-colors duration-150",
            level.current ? "bg-active ring-hairline-strong" : "bg-card ring-hairline",
            level.href && "outline-none hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring/60",
          );
          return (
            <li key={level.key} className="flex min-w-0 items-stretch lg:flex-1">
              {level.href ? (
                <Link href={level.href} className={cn(tile, "w-full")} aria-current={level.current ? "page" : undefined}>
                  {body}
                </Link>
              ) : (
                <div className={cn(tile, "w-full")} aria-current={level.current ? "page" : undefined}>
                  {body}
                </div>
              )}
              {index < levels.length - 1 ? (
                <ChevronRight className="mx-1 hidden size-4 flex-none self-center text-fg-faint lg:block" aria-hidden="true" />
              ) : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
