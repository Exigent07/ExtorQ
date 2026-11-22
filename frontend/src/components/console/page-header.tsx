import type { ReactNode } from "react";

import { Freshness } from "./freshness";

/**
 * Title row of every page: the h1 (a noun, 24px semibold, tight tracking), optional badges
 * beside it, a one-line subtitle computed from the data (the page's finding), and real actions
 * on the right. `freshness` (the API client's `receivedAt`) feeds the top bar's freshness
 * indicator instead of being repeated here. The top bar derives the breadcrumb trail from the
 * URL (detail pages name their object with PageCrumbs).
 */
export function PageHeader({
  title,
  subtitle,
  actions,
  titleMeta,
  freshness,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  titleMeta?: ReactNode;
  freshness?: string;
}) {
  return (
    <header className="flex flex-col gap-4 pt-7 pb-6 lg:flex-row lg:items-end lg:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <h1 className="min-w-0 text-2xl font-semibold tracking-tight text-balance text-foreground">{title}</h1>
          {titleMeta}
        </div>
        {subtitle ? <div className="mt-1.5 max-w-[90ch] text-base text-muted-foreground">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      {freshness ? <Freshness at={freshness} /> : null}
    </header>
  );
}
