#!/usr/bin/env node
/**
 * Full-page screenshots of console views with a local headless Chrome (DevTools protocol).
 * Nothing is installed: it drives the Chrome that is already on the machine.
 *
 * Signs in through the real login form (password read from a file, never printed), hands the
 * HttpOnly session cookie to the headless browser, then captures each page. Read-only.
 *
 * Usage (Node 22 has WebSocket built in; Node 20 needs --experimental-websocket):
 *   EXTORQ_SHOTS_PASSWORD_FILE=../var/secrets/analyst_password \
 *   node --experimental-websocket scripts/screenshots.mjs --base http://127.0.0.1:3000 \
 *     --out docs/screenshots overview=/ detections=/detections ...
 *
 * Optional: EXTORQ_SHOTS_USER (default analyst), CHROME_PATH (default: the macOS Google
 * Chrome app), EXTORQ_SHOTS_WIDTH (default 1440), EXTORQ_SHOTS_HEIGHT (viewport height,
 * default 900), EXTORQ_SHOTS_PACE_MS (default 1500; the API's ClickHouse quota is shared, see
 * scripts/smoke.mjs).
 *
 * Flags: --first-screen captures only the first viewport (WIDTH x HEIGHT) instead of the full
 * page; --anon captures without signing in (the login page); --scale 2 for a retina capture;
 * --press Meta+k presses a key combination after load (e.g. to open the command palette, or
 * Escape to close a sheet); --click "<css selector>" clicks the first matching element after
 * load (e.g. a range toggle); --clicks "<sel>[@@text]|||<sel>..." clicks several in order (the
 * first match whose text contains `text`); --focus "<css selector>" focuses an element (a hover
 * card trigger, a facet button); --hover "<css selector>" moves the mouse over an element (hover
 * cards, tooltips); --audit prints layout problems (horizontal page overflow, text under 12 px).
 *
 * Every page also reports console errors and warnings, uncaught exceptions and CSP violations
 * ("no console errors ..." when there were none), so a capture doubles as a runtime check.
 */
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
function option(name, fallback) {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  const value = args[i + 1];
  args.splice(i, 2);
  return value;
}
function flag(name) {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}
const BASE = new URL(option("--base", "http://127.0.0.1:3000"));
const OUT = option("--out", "docs/screenshots");
const SCALE = Number.parseFloat(option("--scale", "1")) || 1;
const FIRST_SCREEN = flag("--first-screen");
const ANON = flag("--anon");
const PRESS = option("--press", null);
const CLICK = option("--click", null);
const CLICKS = option("--clicks", null);
const FOCUS = option("--focus", null);
const HOVER = option("--hover", null);
const AUDIT = flag("--audit");
const WIDTH = Number.parseInt(process.env.EXTORQ_SHOTS_WIDTH ?? "1440", 10);
const HEIGHT = Number.parseInt(process.env.EXTORQ_SHOTS_HEIGHT ?? "900", 10);
const PACE_MS = Number.parseInt(process.env.EXTORQ_SHOTS_PACE_MS ?? "1500", 10);
const CHROME = process.env.CHROME_PATH ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9300 + Math.floor(Math.random() * 500);
const pages = args.map((spec) => {
  const eq = spec.indexOf("=");
  if (eq <= 0 || !/^[a-z0-9-]+$/.test(spec.slice(0, eq)) || !spec.slice(eq + 1).startsWith("/")) {
    throw new Error(`invalid page spec (expected name=/path): ${spec}`);
  }
  return { name: spec.slice(0, eq), path: spec.slice(eq + 1) };
});

if (typeof WebSocket === "undefined") {
  console.log("This Node version has no WebSocket client: run with node --experimental-websocket (Node 20) or Node 22+.");
  process.exit(2);
}
if (pages.length === 0) {
  console.log("Nothing to capture: pass name=/path arguments.");
  process.exit(2);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const problems = [];

/** Layout audit run in the page: horizontal overflow and text below the 12 px floor. */
const AUDIT_EXPRESSION = `(() => {
  const out = [];
  const doc = document.scrollingElement;
  if (doc.scrollWidth > window.innerWidth + 1) out.push("page scrolls sideways: " + doc.scrollWidth + "px wide in a " + window.innerWidth + "px viewport");
  const small = new Map();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const el = node.parentElement;
    if (!el || !node.textContent.trim()) continue;
    if (el.closest(".sr-only,[aria-hidden=true],svg,script,style,noscript")) continue;
    const box = el.getBoundingClientRect();
    if (box.width === 0 || box.height === 0) continue;
    const size = parseFloat(getComputedStyle(el).fontSize);
    if (size < 12) small.set(el.tagName.toLowerCase() + "." + (el.className.baseVal ?? el.className).toString().split(" ").slice(0, 3).join("."), size);
  }
  for (const [where, size] of [...small].slice(0, 8)) out.push("text at " + size + "px: " + where);
  return out;
})()`;

function attr(tag, name) {
  const match = tag.match(new RegExp(`${name}="([^"]*)"`));
  return match ? match[1].replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#x27;/g, "'") : null;
}

/** Session cookie value from the real login form (no-JS form post of the server action). */
async function signIn() {
  const passwordFile = process.env.EXTORQ_SHOTS_PASSWORD_FILE;
  if (!passwordFile) throw new Error("EXTORQ_SHOTS_PASSWORD_FILE is not set");
  const html = await (await fetch(new URL("/login", BASE), { signal: AbortSignal.timeout(30_000) })).text();
  const form = (html.match(/<form[\s\S]*?<\/form>/gi) ?? [])[0] ?? "";
  const body = new FormData();
  for (const tag of form.match(/<input[^>]*>/gi) ?? []) {
    const name = attr(tag, "name");
    if (attr(tag, "type") === "hidden" && name) body.append(name, attr(tag, "value") ?? "");
  }
  body.set("username", process.env.EXTORQ_SHOTS_USER ?? "analyst");
  body.set("password", readFileSync(passwordFile, "utf8").trim());
  body.set("next", "/");
  const response = await fetch(new URL("/login", BASE), {
    method: "POST",
    body,
    redirect: "manual",
    headers: { Origin: BASE.origin, Accept: "text/html" },
    signal: AbortSignal.timeout(30_000),
  });
  const cookie = response.headers.getSetCookie().find((c) => /^(__Host-)?extorq_session=[^;]/.test(c));
  if (!cookie) throw new Error(`sign-in failed (HTTP ${response.status})`);
  const [pair] = cookie.split(";");
  const eq = pair.indexOf("=");
  return { name: pair.slice(0, eq), value: pair.slice(eq + 1) };
}

/** Minimal DevTools-protocol session over the page target's WebSocket. */
async function connect(url) {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });
  let nextId = 1;
  const pending = new Map();
  const waiters = [];
  ws.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    } else if (message.method) {
      const params = message.params ?? {};
      if (message.method === "Log.entryAdded" && ["error", "warning"].includes(params.entry?.level)) {
        problems.push(`${params.entry.source} ${params.entry.level}: ${String(params.entry.text).slice(0, 300)}`);
      } else if (message.method === "Runtime.exceptionThrown") {
        const details = params.exceptionDetails ?? {};
        problems.push(`exception: ${String(details.exception?.description ?? details.text).slice(0, 300)}`);
      } else if (message.method === "Runtime.consoleAPICalled" && ["error", "warning", "assert"].includes(params.type)) {
        problems.push(`console ${params.type}: ${(params.args ?? []).map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 300)}`);
      }
      for (let i = waiters.length - 1; i >= 0; i -= 1) {
        if (waiters[i].method === message.method) waiters.splice(i, 1)[0].resolve(message.params);
      }
    }
  });
  return {
    send(method, params = {}) {
      const id = nextId++;
      ws.send(JSON.stringify({ id, method, params }));
      return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
    },
    once(method, timeoutMs = 30_000) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out waiting for ${method}`)), timeoutMs);
        waiters.push({ method, resolve: (params) => (clearTimeout(timer), resolve(params)) });
      });
    },
    close: () => ws.close(),
  };
}

async function main() {
  const cookie = ANON ? null : await signIn();
  const profile = mkdtempSync(join(tmpdir(), "extorq-shots-"));
  const chrome = spawn(
    CHROME,
    [
      "--headless=new",
      `--remote-debugging-port=${PORT}`,
      "--remote-debugging-address=127.0.0.1",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--hide-scrollbars",
      `--window-size=${WIDTH},${HEIGHT}`,
      "about:blank",
    ],
    { stdio: "ignore" },
  );
  let session = null;
  try {
    let target = null;
    for (let i = 0; i < 50 && !target; i += 1) {
      await sleep(200);
      try {
        const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
        target = list.find((t) => t.type === "page") ?? null;
      } catch {
        target = null;
      }
    }
    if (!target) throw new Error("headless Chrome did not start");
    session = await connect(target.webSocketDebuggerUrl);
    await session.send("Page.enable");
    await session.send("Network.enable");
    await session.send("Log.enable");
    await session.send("Runtime.enable");
    await session.send("Emulation.setDeviceMetricsOverride", {
      width: WIDTH,
      height: HEIGHT,
      deviceScaleFactor: SCALE,
      mobile: WIDTH < 600,
    });
    if (cookie) {
      await session.send("Network.setCookie", {
        name: cookie.name,
        value: cookie.value,
        domain: BASE.hostname,
        path: "/",
        httpOnly: true,
        sameSite: "Strict",
        secure: BASE.protocol === "https:",
      });
    }
    mkdirSync(OUT, { recursive: true });
    for (const { name, path } of pages) {
      const loaded = session.once("Page.loadEventFired");
      await session.send("Page.navigate", { url: new URL(path, BASE).toString() });
      await loaded;
      await sleep(2500); // client components (charts, expandable text) settle
      if (CLICK) {
        await session.send("Runtime.evaluate", {
          expression: `document.querySelector(${JSON.stringify(CLICK)})?.click()`,
        });
        await sleep(700);
      }
      if (CLICKS) {
        for (const step of CLICKS.split("|||")) {
          const [selector, text = ""] = step.split("@@");
          const result = await session.send("Runtime.evaluate", {
            expression: `(() => { const all = [...document.querySelectorAll(${JSON.stringify(selector)})]; const el = ${JSON.stringify(text)} ? all.find((x) => x.textContent.includes(${JSON.stringify(text)})) : all[0]; if (!el) return "missing"; el.scrollIntoView({ block: "center" }); el.click(); return "ok"; })()`,
            returnByValue: true,
          });
          if (result?.result?.value !== "ok") console.log(`click target not found: ${step}`);
          await sleep(900);
        }
      }
      if (FOCUS) {
        await session.send("Runtime.evaluate", { expression: `document.querySelector(${JSON.stringify(FOCUS)})?.focus()` });
        await sleep(900);
      }
      if (HOVER) {
        const result = await session.send("Runtime.evaluate", {
          expression: `(() => { const el = document.querySelector(${JSON.stringify(HOVER)}); if (!el) return null; el.scrollIntoView({ block: "center" }); const r = el.getBoundingClientRect(); return JSON.stringify({ x: r.left + Math.min(r.width / 2, 40), y: r.top + r.height / 2 }); })()`,
          returnByValue: true,
        });
        const point = result?.result?.value ? JSON.parse(result.result.value) : null;
        if (point) {
          await session.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: point.x, y: point.y });
          await sleep(1200);
        } else console.log(`hover target not found: ${HOVER}`);
      }
      if (PRESS) {
        const parts = PRESS.split("+");
        const key = parts.pop() ?? "";
        const modifiers =
          (parts.includes("Alt") ? 1 : 0) | (parts.includes("Control") ? 2 : 0) | (parts.includes("Meta") ? 4 : 0) | (parts.includes("Shift") ? 8 : 0);
        const code = /^[a-z]$/i.test(key) ? `Key${key.toUpperCase()}` : key;
        await session.send("Input.dispatchKeyEvent", { type: "keyDown", key, code, modifiers });
        await session.send("Input.dispatchKeyEvent", { type: "keyUp", key, code, modifiers });
        await sleep(700);
      }
      const viewport = { width: WIDTH, height: HEIGHT, deviceScaleFactor: SCALE, mobile: WIDTH < 600 };
      let height = HEIGHT;
      if (!FIRST_SCREEN) {
        // Grow the viewport to the page so fixed chrome (the sidebar) spans the whole capture.
        const metrics = await session.send("Page.getLayoutMetrics");
        height = Math.min(Math.ceil(metrics.cssContentSize.height), 8000);
        await session.send("Emulation.setDeviceMetricsOverride", { ...viewport, height });
        await sleep(800);
        const after = await session.send("Page.getLayoutMetrics");
        height = Math.min(Math.ceil(after.cssContentSize.height), 8000);
      }
      const shot = await session.send("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: !FIRST_SCREEN,
        clip: { x: 0, y: 0, width: WIDTH, height, scale: 1 },
      });
      writeFileSync(join(OUT, `${name}.png`), Buffer.from(shot.data, "base64"));
      if (!FIRST_SCREEN) await session.send("Emulation.setDeviceMetricsOverride", viewport);
      console.log(`saved ${join(OUT, `${name}.png`)} (${WIDTH}x${height}) from ${path}`);
      if (AUDIT) {
        const audit = await session.send("Runtime.evaluate", { expression: AUDIT_EXPRESSION, returnByValue: true });
        const found = audit?.result?.value ?? [];
        console.log(found.length ? `  layout: ${found.join("\n  layout: ")}` : "  layout: no sideways scroll, no text under 12px");
      }
      console.log(problems.length ? `  PROBLEMS:\n    ${problems.join("\n    ")}` : "  no console errors, warnings, exceptions or CSP violations");
      problems.length = 0;
      await sleep(PACE_MS);
    }
  } finally {
    session?.close();
    chrome.kill("SIGTERM");
    await sleep(500);
    rmSync(profile, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.log(`screenshots failed: ${error.message}`);
  process.exit(1);
});
