import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-xl flex-col justify-center px-4">
      <h1 className="text-2xl font-semibold text-ink">Page not found</h1>
      <p className="mt-2 text-sm text-ink-2">The console has no page at this address.</p>
      <Link href="/" className="mt-4 text-sm text-ink underline-offset-2 hover:underline">
        Go to the overview
      </Link>
    </main>
  );
}
