import { cookies } from "next/headers";
import { Suspense } from "react";

import { AppSidebar } from "@/components/console/app-sidebar";
import { EnvironmentPill } from "@/components/console/badges";
import { CommandPalette } from "@/components/console/command-palette";
import { FreshnessIndicator, FreshnessProvider } from "@/components/console/freshness";
import { CrumbsProvider, RouteBreadcrumbs } from "@/components/console/route-breadcrumbs";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { ROLE_LABEL } from "@/lib/auth/roles";
import type { Session } from "@/lib/auth/token";
import { grafanaUrl } from "@/lib/server/config";
import { requireSession } from "@/lib/server/session";
import { getPaletteData } from "@/lib/server/shell";

/**
 * The console shell: collapsible sidebar, a sticky top bar (breadcrumbs, Cmd/Ctrl-K palette,
 * environment, data freshness) and the page canvas. The session is re-checked here and on
 * every page. The palette's lists stream in behind a Suspense boundary so they never delay
 * the page itself.
 */
export default async function ConsoleLayout({ children }: LayoutProps<"/">) {
  const session = await requireSession();
  const store = await cookies();
  const sidebarOpen = store.get("sidebar_state")?.value !== "false";
  const grafana = grafanaUrl();
  const renderedAt = new Date().toISOString();

  return (
    <SidebarProvider defaultOpen={sidebarOpen}>
      <a
        href="#main"
        className="sr-only z-50 rounded-lg bg-primary px-3 py-2 text-sm text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Skip to content
      </a>
      <AppSidebar user={session.user} role={session.role} roleLabel={ROLE_LABEL[session.role]} grafanaUrl={grafana} />
      <SidebarInset className="min-w-0">
        <FreshnessProvider initial={renderedAt}>
          <CrumbsProvider>
            <header className="sticky top-0 z-30 flex h-14 flex-none items-center gap-2 border-b border-hairline-soft bg-background px-4 md:px-6">
              <SidebarTrigger className="-ml-1.5 size-8 text-muted-foreground hover:text-foreground" />
              <Separator orientation="vertical" className="mr-1.5 data-vertical:h-4 data-vertical:self-center" />
              <RouteBreadcrumbs />
              <div className="ml-auto flex flex-none items-center gap-2">
                <Suspense fallback={<CommandPalette data={null} grafanaUrl={grafana} />}>
                  <PaletteLoader session={session} grafanaUrl={grafana} />
                </Suspense>
                <EnvironmentPill className="hidden sm:inline-flex" />
                <FreshnessIndicator />
              </div>
            </header>
            <main id="main" className="mx-auto w-full max-w-[1600px] min-w-0 flex-1 px-4 pb-16 md:px-8">
              {children}
            </main>
          </CrumbsProvider>
        </FreshnessProvider>
      </SidebarInset>
    </SidebarProvider>
  );
}

async function PaletteLoader({ session, grafanaUrl }: { session: Session; grafanaUrl: string }) {
  const data = await getPaletteData(session);
  return <CommandPalette data={data} grafanaUrl={grafanaUrl} />;
}
