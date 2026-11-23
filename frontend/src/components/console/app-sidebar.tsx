"use client";

import { Activity, ArrowUpRight, ChartSpline, ChevronsUpDown, LayoutDashboard, LogOut, Server, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useRef } from "react";

import { logoutAction } from "@/app/(console)/actions";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebar,
} from "@/components/ui/sidebar";
import { activeNav, NAV_GROUPS, type NavKey } from "@/lib/navigation";

import { BrandLockup, BrandTile } from "./brand-mark";
import { RoleBadge } from "./badges";

const NAV_ICON: Record<NavKey, typeof Server> = {
  overview: LayoutDashboard,
  assets: Server,
  detections: ShieldAlert,
  health: Activity,
};

/**
 * The console sidebar: brand lockup, labelled nav groups (Monitor, Detect, Operate), the
 * external Grafana link and the signed-in user. Collapses to icons (Cmd/Ctrl+B or the rail)
 * and becomes a sheet on phones. The active item is marked by a lifted fill, full-ink label
 * and the brand-coloured icon.
 */
export function AppSidebar({
  user,
  role,
  roleLabel,
  grafanaUrl,
}: {
  user: string;
  role: "analyst" | "viewer";
  roleLabel: string;
  grafanaUrl: string;
}) {
  const pathname = usePathname();
  const active = activeNav(pathname);
  const { setOpenMobile } = useSidebar();

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="h-14 justify-center border-b border-sidebar-border px-3 group-data-[collapsible=icon]:px-2">
        <Link
          href="/"
          aria-label="ExtorQ overview"
          onClick={() => setOpenMobile(false)}
          className="flex min-w-0 items-center rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring"
        >
          <span className="group-data-[collapsible=icon]:hidden">
            <BrandLockup scope="Security console" />
          </span>
          <span className="hidden group-data-[collapsible=icon]:flex">
            <BrandTile />
          </span>
        </Link>
      </SidebarHeader>

      <SidebarContent className="pt-2">
        <nav aria-label="Primary" className="flex flex-col">
          {NAV_GROUPS.map((group) => (
            <SidebarGroup key={group.label} className="py-1.5">
              <SidebarGroupLabel className="h-7 text-xs font-normal text-muted-foreground">{group.label}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu className="gap-0.5">
                  {group.items.map((item) => {
                    const Icon = NAV_ICON[item.key];
                    const isActive = item.key === active;
                    return (
                      <SidebarMenuItem key={item.key}>
                        <SidebarMenuButton
                          asChild
                          isActive={isActive}
                          tooltip={item.label}
                          className="h-8 text-sm text-fg-2 transition-colors duration-150 hover:text-foreground data-active:font-medium data-active:text-foreground data-active:[&_svg]:text-brand"
                        >
                          <Link href={item.href} aria-current={isActive ? "page" : undefined} onClick={() => setOpenMobile(false)}>
                            <Icon strokeWidth={1.75} aria-hidden="true" />
                            <span>{item.label}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}

          <SidebarGroup className="py-1.5">
            <SidebarGroupLabel className="h-7 text-xs font-normal text-muted-foreground">Analytics</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    asChild
                    tooltip="Grafana (opens in a new tab)"
                    className="group/ext h-8 text-sm text-fg-2 transition-colors duration-150 hover:text-foreground"
                  >
                    <a href={grafanaUrl} target="_blank" rel="noopener noreferrer">
                      <ChartSpline strokeWidth={1.75} aria-hidden="true" />
                      <span>Grafana</span>
                      <ArrowUpRight
                        aria-hidden="true"
                        className="ml-auto size-3.5! text-fg-faint transition-colors group-hover/ext:text-muted-foreground"
                      />
                      <span className="sr-only">(opens in a new tab)</span>
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </nav>
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border p-2">
        <UserMenu user={user} role={role} roleLabel={roleLabel} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

function UserMenu({ user, role, roleLabel }: { user: string; role: "analyst" | "viewer"; roleLabel: string }) {
  const { isMobile } = useSidebar();
  const formRef = useRef<HTMLFormElement>(null);
  const initial = user.slice(0, 1).toUpperCase();
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        {/* Sign-out is a real form (server action); the menu item submits it. */}
        <form ref={formRef} action={logoutAction} className="hidden" aria-hidden="true" />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              aria-label={`Account: ${user}, ${roleLabel}`}
              className="h-11 data-[state=open]:bg-sidebar-accent data-[state=open]:text-foreground"
            >
              <Avatar className="size-7 rounded-lg after:rounded-lg">
                <AvatarFallback className="rounded-lg bg-brand-soft text-xs font-medium text-brand">{initial}</AvatarFallback>
              </Avatar>
              <span className="grid flex-1 text-left leading-tight">
                <span className="truncate text-sm font-medium text-foreground">{user}</span>
                <span className="truncate text-xs text-muted-foreground">{role === "viewer" ? "Viewer · read-only" : "Analyst"}</span>
              </span>
              <ChevronsUpDown className="ml-auto size-4 text-muted-foreground" aria-hidden="true" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent side={isMobile ? "top" : "right"} align="end" sideOffset={8} className="w-60">
            <DropdownMenuLabel className="flex items-center gap-2.5 py-2 font-normal">
              <Avatar className="size-8 rounded-lg after:rounded-lg">
                <AvatarFallback className="rounded-lg bg-brand-soft text-sm font-medium text-brand">{initial}</AvatarFallback>
              </Avatar>
              <span className="grid min-w-0 flex-1 gap-1 leading-tight">
                <span className="truncate text-sm font-medium text-foreground">{user}</span>
                <RoleBadge role={role} />
              </span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <div className="grid gap-1 px-2 py-1.5 text-xs text-muted-foreground">
              <span className="flex items-center justify-between">
                Search and jump <kbd className="font-mono text-fg-2">⌘K</kbd>
              </span>
              <span className="flex items-center justify-between">
                Collapse sidebar <kbd className="font-mono text-fg-2">⌘B</kbd>
              </span>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => formRef.current?.requestSubmit()}>
              <LogOut aria-hidden="true" />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
