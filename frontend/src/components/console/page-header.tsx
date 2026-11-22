import type { ReactNode } from "react";

import { Freshness } from "./freshness";

export interface Crumb {
  label: string;
  href?: string;
}

/**
 * Title row of every page: the h1 (a noun, 24px semibold, tight tracking), optional badges
 * beside it, a one-line subtitle computed from the data (the page's finding), and real actions
 * on the right. `freshness` (the API client's `receivedAt`) feeds the top bar's freshness
 * indicator instead of being repeated here.
 *
 * `crumbs` is accepted for compatibility with routes not rebuilt yet; the top bar derives
 * the breadcrumb trail from the URL.
 */
export function PageHeader({
  title,
  subtitle,
  finding,
  actions,
  titleMeta,
  freshness,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  /** Legacy name of `subtitle`. */
  finding?: ReactNode;
  actions?: ReactNode;
  titleMeta?: ReactNode;
  freshness?: string;
  crumbs?: Crumb[];
}) {
  const line = subtitle ?? finding;
  return (
    <header className="flex flex-col gap-4 pt-7 pb-6 lg:flex-row lg:items-end lg:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">{title}</h1>
          {titleMeta}
        </div>
        {line ? <div className="mt-1.5 max-w-[90ch] text-base text-muted-foreground">{line}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      {freshness ? <Freshness at={freshness} /> : null}
    </header>
  );
}
