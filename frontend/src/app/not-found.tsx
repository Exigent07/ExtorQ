import Link from "next/link";

import { BrandTile } from "@/components/console/brand-mark";

export default function NotFound() {
  return (
    <main className="login-backdrop flex min-h-dvh items-center justify-center px-4">
      <div className="max-w-md text-center">
        <BrandTile className="mx-auto size-9" />
        <h1 className="mt-6 text-2xl font-semibold tracking-tight text-foreground">Page not found</h1>
        <p className="mt-2 text-base text-muted-foreground">The console has no page at this address.</p>
        <Link
          href="/"
          className="mt-6 inline-flex h-9 items-center rounded-lg px-3.5 text-sm font-medium text-foreground ring-1 ring-hairline-strong transition-colors duration-150 ring-inset hover:bg-hover"
        >
          Go to the overview
        </Link>
      </div>
    </main>
  );
}
