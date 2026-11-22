import type { Metadata } from "next";

import { BrandTile } from "@/components/console/brand-mark";
import { safeNextPath } from "@/lib/security/redirect";

import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const params = await searchParams;
  const rawNext = Array.isArray(params.next) ? params.next[0] : params.next;
  const next = safeNextPath(rawNext);
  return (
    <main className="login-backdrop relative flex min-h-dvh flex-col items-center justify-center px-4 py-16">
      <div className="w-full max-w-[380px]">
        <div className="mb-8 flex flex-col items-center text-center">
          <BrandTile className="size-11 rounded-xl [&>svg]:size-[64%]" />
          <h1 className="mt-6 text-2xl font-semibold tracking-tight text-foreground">Sign in to ExtorQ</h1>
          <p className="mt-2 text-base text-muted-foreground">Security console for the lab environment</p>
        </div>

        <section
          aria-label="Sign in"
          className="rounded-xl bg-card p-6 shadow-card ring-1 ring-hairline"
        >
          <LoginForm next={next} />
        </section>

        <p className="mt-6 text-center text-sm leading-relaxed text-muted-foreground">
          Local analyst and viewer accounts. Sessions last 8 hours;
          <br className="hidden sm:block" /> failed attempts are rate limited and logged.
        </p>
        <p className="mt-4 text-center text-xs text-muted-foreground">Monitors a macOS host, an Ubuntu VM, a kind cluster and GitHub.</p>
      </div>
    </main>
  );
}
