import { cn } from "cn";

/**
 * ExtorQ mark: a ring of four arcs, one per monitored asset class (macOS host, Linux VM,
 * Kubernetes cluster, GitHub), with the Q's tail leaving through the gap between them.
 */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="butt"
      aria-hidden="true"
      className={cn("size-6", className)}
    >
      <path d="M16.44 6.6A7 7 0 0 1 16.44 15.4" />
      <path d="M15.4 16.44A7 7 0 0 1 6.6 16.44" />
      <path d="M5.56 15.4A7 7 0 0 1 5.56 6.6" />
      <path d="M6.6 5.56A7 7 0 0 1 15.4 5.56" />
      <path d="M14.2 14.2L20 20" />
    </svg>
  );
}
