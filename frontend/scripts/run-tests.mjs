#!/usr/bin/env node
/**
 * Unit test runner: Node's built-in test runner with tsx for TypeScript (no extra test
 * framework). Runs every `*.test.ts` under src/. The `react-server` condition lets the
 * server-only modules (API client, config) load outside Next.js, as they do on the server.
 */
import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const files = [];
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path);
    else if (/\.test\.ts$/.test(entry)) files.push(path);
  }
}
walk("src");
files.sort();

const result = spawnSync(
  process.execPath,
  ["--conditions=react-server", "--import", "tsx", "--test", "--test-reporter=spec", ...files],
  { stdio: "inherit", env: { ...process.env, NODE_ENV: "test", NEXT_TELEMETRY_DISABLED: "1" } },
);
process.exit(result.status ?? 1);
