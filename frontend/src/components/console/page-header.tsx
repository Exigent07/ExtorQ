import Link from "next/link";
import type { ReactNode } from "react";

export interface Crumb {
  label: string;
  href?: string;
}

/**
 * Title row: product/scope breadcrumb, the screen's h1 (a noun, 26px), an optional
 * one-line finding computed from the data, and real actions on the right.
 */
export function PageHeader({
  title,
  crumbs = [],
  finding,
  actions,
  titleMeta,
}: {
  title: ReactNode;
  crumbs?: Crumb[];
  finding?: ReactNode;
  actions?: ReactNode;
  titleMeta?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-4 pt-6 pb-6 lg:flex-row lg:items-end lg:justify-between lg:pt-8">
      <div className="min-w-0">
        <nav aria-label="Breadcrumb">
          <ol className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <li>
              <Link href="/" className="hover:text-ink">
                ExtorQ
              </Link>
            </li>
            <li aria-hidden="true">/</li>
            <li>Lab</li>
            {crumbs.map((crumb) => (
              <li key={crumb.label} className="flex items-center gap-1.5">
                <span aria-hidden="true">/</span>
                {crumb.href ? (
                  <Link href={crumb.href} className="hover:text-ink">
                    {crumb.label}
                  </Link>
                ) : (
                  <span>{crumb.label}</span>
                )}
              </li>
            ))}
          </ol>
        </nav>
        <div className="mt-1.5 flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="text-2xl font-semibold tracking-[-0.01em] text-ink">{title}</h1>
          {titleMeta}
        </div>
        {finding ? <div className="mt-1.5 max-w-[80ch] text-base text-ink-2">{finding}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-3">{actions}</div> : null}
    </header>
  );
}
