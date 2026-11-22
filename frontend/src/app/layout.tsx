import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";

import { NonceProvider } from "@/components/console/nonce";
import { TooltipProvider } from "@/components/ui/tooltip";

import "./globals.css";

// Every page is rendered per request: the CSP nonce is per request, and all data is
// fetched server-side for the signed-in user.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: { default: "ExtorQ", template: "%s · ExtorQ" },
  description: "ExtorQ security console: telemetry coverage, detections and investigations.",
  robots: { index: false, follow: false },
  icons: { icon: [{ url: "/icon.svg", type: "image/svg+xml" }] },
  referrer: "no-referrer",
  formatDetection: { telephone: false, email: false, address: false },
};

export const viewport: Viewport = {
  themeColor: "#09090b",
  colorScheme: "dark",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // Set by src/proxy.ts for this request; library <style> elements must carry it (CSP).
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" className={`dark ${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <NonceProvider nonce={nonce}>
          <TooltipProvider delayDuration={200}>{children}</TooltipProvider>
        </NonceProvider>
      </body>
    </html>
  );
}
