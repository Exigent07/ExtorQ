import { cn } from "cn";
import { Boxes, Cpu, FolderGit2, Laptop, type LucideIcon, Server } from "lucide-react";
import type { ReactNode } from "react";

import { analystStatusLabel, isClosedStatus } from "@/lib/format";

/**
 * Small marks of the investigation view. Server-renderable; values passed as `children` are
 * console text or UntrustedText elements (never raw telemetry strings in attributes).
 */

const STATUS_DOT: Record<string, string> = {
  new: "bg-foreground",
  acknowledged: "bg-fg-2",
  investigating: "bg-sev-medium",
};

/**
 * Analyst workflow state (same language as the Overview and Detections lists): open states
 * with a filled mark (new white, acknowledged grey, investigating amber), closed states with a
 * hollow ring. Not a severity and not a health status; the word is always shown.
 */
export function StatusMark({ status, className }: { status: string; className?: string }) {
  const closed = isClosedStatus(status);
  return (
    <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap", closed ? "text-muted-foreground" : "text-fg-2", className)}>
      <span
        aria-hidden="true"
        className={cn(
          "size-2 flex-none rounded-full",
          closed ? "bg-transparent ring-1 ring-fg-faint ring-inset" : (STATUS_DOT[status] ?? "bg-fg-2"),
        )}
      />
      {analystStatusLabel(status)}
    </span>
  );
}

/**
 * A neutral chip (lists of values, MITRE ids, bases). It wraps instead of clipping, so a long
 * value is never hidden by CSS; UntrustedText inside it bounds the length.
 */
export function Chip({ children, mono = false, className }: { children: ReactNode; mono?: boolean; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex min-h-6 max-w-full min-w-0 items-center rounded-md bg-white/[0.03] px-1.5 py-0.5 text-left text-xs leading-4 wrap-anywhere text-fg-2 ring-1 ring-hairline-strong ring-inset",
        mono && "font-mono",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** A two-part chip: muted key, value in the figure face (entities). */
export function KeyChip({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-7 max-w-full min-w-0 items-center overflow-hidden rounded-md text-xs ring-1 ring-hairline-strong ring-inset",
        className,
      )}
    >
      <span className="flex h-full flex-none items-center bg-white/[0.04] px-2 text-muted-foreground">{label}</span>
      <span className="flex h-full min-w-0 items-center px-2 font-mono text-foreground">{children}</span>
    </span>
  );
}

/** An eyebrow label above a block (12px, muted, sentence case). */
export function Eyebrow({ children, className }: { children: ReactNode; className?: string }) {
  return <p className={cn("text-xs font-medium text-muted-foreground", className)}>{children}</p>;
}

const ASSET_ICON: Record<string, LucideIcon> = {
  macos_host: Laptop,
  linux_host: Server,
  kubernetes_cluster: Boxes,
  kubernetes_node: Cpu,
  kubernetes_namespace: Boxes,
  kubernetes_workload: Boxes,
  github_repository: FolderGit2,
  github_account: FolderGit2,
};

/** The asset class of the alert as a 40px tile (icon only, neutral). */
export function AssetTile({ assetType, className }: { assetType: string; className?: string }) {
  const Icon = ASSET_ICON[assetType] ?? Server;
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex size-10 flex-none items-center justify-center rounded-lg bg-white/[0.04] text-fg-2 shadow-card ring-1 ring-hairline-strong ring-inset",
        className,
      )}
    >
      <Icon className="size-5" strokeWidth={1.6} />
    </span>
  );
}
