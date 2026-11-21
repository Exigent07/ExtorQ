import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { Metadata, Viewport } from "next";

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
  themeColor: "#171719",
  colorScheme: "dark",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`dark ${GeistSans.variable} ${GeistMono.variable}`}>
      <body>
        <TooltipProvider>{children}</TooltipProvider>
      </body>
    </html>
  );
}
