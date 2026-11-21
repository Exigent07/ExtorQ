import { NavRail } from "@/components/console/nav-rail";
import { ROLE_LABEL } from "@/lib/auth/roles";
import { requireSession } from "@/lib/server/session";

export default async function ConsoleLayout({ children }: LayoutProps<"/">) {
  const session = await requireSession();
  return (
    <div className="min-h-dvh md:pl-[var(--xq-rail)]">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Skip to content
      </a>
      <NavRail user={session.user} roleLabel={ROLE_LABEL[session.role]} />
      <main id="main" className="mx-auto max-w-[1680px] px-4 pb-24 md:px-8 md:pb-12">
        {children}
      </main>
    </div>
  );
}
