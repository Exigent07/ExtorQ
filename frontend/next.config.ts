import type { NextConfig } from "next";

import { STATIC_SECURITY_HEADERS } from "./src/lib/security/csp";

/**
 * The per-request Content-Security-Policy (nonce-based) is set by src/proxy.ts. The
 * static headers below are repeated here so immutable assets served without the proxy
 * (/_next/static) carry them too.
 */
const nextConfig: NextConfig = {
  output: "standalone",
  // `next dev` would otherwise append a generated block to the hand-written AGENTS.md
  // whenever it detects an AI coding agent; the console's guide stays authored here.
  agentRules: false,
  poweredByHeader: false,
  reactStrictMode: true,
  productionBrowserSourceMaps: false,
  async headers() {
    return [{ source: "/:path*", headers: [...STATIC_SECURITY_HEADERS] }];
  },
};

export default nextConfig;
