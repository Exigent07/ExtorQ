"use client";

import { cn } from "cn";
import { Activity, LogOut, Radar, Server, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { logoutAction } from "@/app/(console)/actions";

import { BrandMark } from "./brand-mark";

const NAV = [
  { href: "/", label: "Overview", short: "Overview", icon: Radar, match: (p: string) => p === "/" },
  {
    href: "/assets",
    label: "Assets",
    short: "Assets",
    icon: Server,
    match: (p: string) => p.startsWith("/assets"),
  },
  {
    href: "/detections",
    label: "Detections and alerts",
    short: "Detections",
    icon: ShieldAlert,
    match: (p: string) => p.startsWith("/detections") || p.startsWith("/investigations"),
  },
  {
    href: "/health",
    label: "System health",
    short: "Health",
    icon: Activity,
    match: (p: string) => p.startsWith("/health"),
  },
] as const;

/**
 * Icon rail (desktop) / bottom bar (phone). The active destination is marked the
 * data-terminal way: the icon turns to full ink and a 1px ink line sits on the rail's edge.
 */
export function NavRail({ user, roleLabel }: { user: string; roleLabel: string }) {
  const pathname = usePathname();

  return (
    <>
      <nav
        aria-label="Primary"
        className="fixed inset-y-0 left-0 z-30 hidden w-[var(--xq-rail)] flex-col items-center border-r border-border bg-ground md:flex"
      >
        <Link
          href="/"
          className="mt-4 mb-6 flex size-10 items-center justify-center rounded-md text-ink"
          aria-label="ExtorQ overview"
        >
          <BrandMark />
        </Link>
        <ul className="flex w-full flex-col gap-1">
          {NAV.map((item) => {
            const active = item.match(pathname);
            const Icon = item.icon;
            return (
              <li key={item.href} className="relative flex w-full justify-center">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Link
                      href={item.href}
                      aria-label={item.label}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "flex size-10 items-center justify-center rounded-md transition-colors",
                        active ? "text-ink" : "text-muted-foreground hover:text-ink",
                      )}
                    >
                      <Icon className="size-[18px]" strokeWidth={1.5} aria-hidden="true" />
                    </Link>
                  </TooltipTrigger>
                  <TooltipContent side="right">{item.label}</TooltipContent>
                </Tooltip>
                {active ? (
                  <span aria-hidden="true" className="absolute top-2 -right-px h-6 w-px bg-line" />
                ) : null}
              </li>
            );
          })}
        </ul>
        <div className="mt-auto mb-4 flex flex-col items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <span
                tabIndex={0}
                className="flex size-8 items-center justify-center rounded-full border border-control font-mono text-xs text-ink-2 uppercase"
                aria-label={`Signed in as ${user}, ${roleLabel}`}
              >
                {user.slice(0, 1)}
              </span>
            </TooltipTrigger>
            <TooltipContent side="right">
              {user} · {roleLabel}
            </TooltipContent>
          </Tooltip>
          <form action={logoutAction}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="submit"
                  aria-label="Sign out"
                  className="flex size-10 items-center justify-center rounded-md text-muted-foreground transition-colors hover:text-ink"
                >
                  <LogOut className="size-[18px]" strokeWidth={1.5} aria-hidden="true" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="right">Sign out</TooltipContent>
            </Tooltip>
          </form>
        </div>
      </nav>

      <nav
        aria-label="Primary"
        className="fixed inset-x-0 bottom-0 z-30 border-t border-border bg-ground pb-[env(safe-area-inset-bottom)] md:hidden"
      >
        <ul className="grid grid-cols-5">
          {NAV.map((item) => {
            const active = item.match(pathname);
            const Icon = item.icon;
            return (
              <li key={item.href} className="relative">
                {active ? (
                  <span aria-hidden="true" className="absolute inset-x-5 -top-px h-px bg-line" />
                ) : null}
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex h-14 flex-col items-center justify-center gap-1 text-2xs",
                    active ? "text-ink" : "text-muted-foreground",
                  )}
                >
                  <Icon className="size-[18px]" strokeWidth={1.5} aria-hidden="true" />
                  {item.short}
                </Link>
              </li>
            );
          })}
          <li>
            <form action={logoutAction} className="h-full">
              <button
                type="submit"
                className="flex h-14 w-full flex-col items-center justify-center gap-1 text-2xs text-muted-foreground"
              >
                <LogOut className="size-[18px]" strokeWidth={1.5} aria-hidden="true" />
                Sign out
              </button>
            </form>
          </li>
        </ul>
      </nav>
    </>
  );
}
