import { cn } from "cn";
import { Box, Boxes, Cpu, FolderGit2, Laptop, type LucideIcon, Server, UserRound } from "lucide-react";

import type { ClassKey } from "./model";

const TYPE_ICON: Record<string, LucideIcon> = {
  macos_host: Laptop,
  linux_host: Server,
  kubernetes_cluster: Boxes,
  kubernetes_node: Cpu,
  kubernetes_namespace: Box,
  kubernetes_workload: Box,
  github_repository: FolderGit2,
  github_account: UserRound,
};

export const CLASS_ICON: Record<ClassKey, LucideIcon> = {
  macos: Laptop,
  linux: Server,
  kubernetes: Boxes,
  github: FolderGit2,
  other: Box,
};

/** The asset type's icon on a quiet raised tile (cards, headers, rows). Decorative. */
export function AssetIconTile({
  assetType,
  size = "md",
  className,
}: {
  assetType: string;
  size?: "sm" | "md" | "lg";
  className?: string;
}) {
  const Icon = TYPE_ICON[assetType] ?? Box;
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex flex-none items-center justify-center rounded-lg bg-white/[0.04] text-fg-2 ring-1 ring-hairline ring-inset",
        size === "sm" && "size-7",
        size === "md" && "size-9",
        size === "lg" && "size-10 rounded-[10px]",
        className,
      )}
    >
      <Icon className={size === "sm" ? "size-3.5" : size === "lg" ? "size-5" : "size-4"} strokeWidth={1.75} />
    </span>
  );
}
