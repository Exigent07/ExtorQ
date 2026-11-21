import type { Metadata } from "next";

import { BrandMark } from "@/components/console/brand-mark";
import { safeNextPath } from "@/lib/security/redirect";

import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const params = await searchParams;
  const rawNext = Array.isArray(params.next) ? params.next[0] : params.next;
  const next = safeNextPath(rawNext);
  return (
    <main className="flex min-h-dvh items-center justify-center px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="mb-8 flex items-center gap-3 text-ink">
          <BrandMark className="size-8" />
          <div>
            <p className="text-lg font-semibold leading-tight">ExtorQ</p>
            <p className="text-xs text-muted-foreground">Security console · lab environment</p>
          </div>
        </div>
        <section
          aria-labelledby="signin-title"
          className="rounded-md border border-border bg-surface px-6 pt-6 pb-7"
        >
          <h1 id="signin-title" className="mb-1 text-xl font-semibold text-ink">
            Sign in
          </h1>
          <p className="mb-6 text-sm text-muted-foreground">
            Use your local analyst or viewer account. Sessions last 8 hours.
          </p>
          <LoginForm next={next} />
        </section>
      </div>
    </main>
  );
}
