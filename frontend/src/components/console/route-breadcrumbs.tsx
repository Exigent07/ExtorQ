"use client";

import { cn } from "cn";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { createContext, Fragment, type ReactNode, useContext, useEffect, useState } from "react";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { type Crumb, routeCrumbs } from "@/lib/navigation";

/**
 * The top-bar trail is derived from the URL (ids validated, shown as text). A detail page may
 * name its object instead of showing a bare id: it renders <PageCrumbs> with labels built on
 * the server from validated, display-sanitised API values (an asset id, a service name, a rule
 * id), which replace the URL's object crumb for that path only.
 */
type Override = { path: string; crumbs: Crumb[] };
type CrumbsState = { override: Override | null; setOverride: (next: Override | null) => void };

const CrumbsContext = createContext<CrumbsState | null>(null);

export function CrumbsProvider({ children }: { children: ReactNode }) {
  const [override, setOverride] = useState<Override | null>(null);
  return <CrumbsContext.Provider value={{ override, setOverride }}>{children}</CrumbsContext.Provider>;
}

/** Names the current object in the trail; renders nothing itself. */
export function PageCrumbs({ crumbs }: { crumbs: Crumb[] }) {
  const setOverride = useContext(CrumbsContext)?.setOverride;
  const pathname = usePathname();
  const key = JSON.stringify(crumbs);
  useEffect(() => {
    setOverride?.({ path: pathname, crumbs: JSON.parse(key) as Crumb[] });
    return () => setOverride?.(null);
  }, [pathname, key, setOverride]);
  return null;
}

/** Top-bar trail: nav group › section › current object (the group, which the sidebar already shows, only from xl). */
export function RouteBreadcrumbs({ className }: { className?: string }) {
  const pathname = usePathname();
  const override = useContext(CrumbsContext)?.override ?? null;
  const base = routeCrumbs(pathname);
  const crumbs = override && override.path === pathname && base.length > 2 ? [...base.slice(0, -1), ...override.crumbs] : base;
  return (
    <Breadcrumb className={cn("min-w-0", className)}>
      <BreadcrumbList className="flex-nowrap text-sm">
        {crumbs.map((crumb, index) => {
          const last = index === crumbs.length - 1;
          return (
            <Fragment key={`${index}-${crumb.label}`}>
              {index > 0 ? (
                <BreadcrumbSeparator className={cn(index === 1 && "hidden xl:block", !last && index > 1 && "hidden md:block")} />
              ) : null}
              <BreadcrumbItem
                className={cn(
                  // Parents keep their (capped) width; only the current object's label truncates.
                  last ? "min-w-0" : "max-w-[16rem] flex-none",
                  index === 0 && "hidden xl:inline-flex",
                  !last && index > 1 && "hidden md:inline-flex",
                )}
              >
                {last ? (
                  <BreadcrumbPage className={cn("max-w-[28ch] truncate font-medium text-foreground", crumb.mono && "font-mono text-sm")}>
                    {crumb.label}
                  </BreadcrumbPage>
                ) : crumb.href ? (
                  <BreadcrumbLink
                    asChild
                    className={cn(
                      "max-w-[16rem] truncate text-muted-foreground transition-colors duration-150 hover:text-foreground",
                      crumb.mono && "font-mono text-sm",
                    )}
                  >
                    <Link href={crumb.href}>{crumb.label}</Link>
                  </BreadcrumbLink>
                ) : (
                  <span className={cn("truncate text-muted-foreground", crumb.mono && "font-mono text-sm")}>{crumb.label}</span>
                )}
              </BreadcrumbItem>
            </Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
