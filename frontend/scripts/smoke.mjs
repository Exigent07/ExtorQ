#!/usr/bin/env node
/**
 * ExtorQ console smoke test (read-only).
 *
 * Signs in through the real login form (the server action's no-JavaScript form post), then
 * fetches every view and asserts HTTP 200 plus key markers. It never changes alert state and
 * never requests AI summaries. Passwords are read from files and never printed.
 *
 * Usage:
 *   EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password \
 *   EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password \
 *   node scripts/smoke.mjs [--base http://127.0.0.1:3100]
 *
 * Optional: EXTORQ_SMOKE_PACE_MS (default 1500: delay between requests, see PACE_MS),
 * EXTORQ_SMOKE_ANALYST_USER / EXTORQ_SMOKE_VIEWER_USER (default analyst / viewer),
 * EXTORQ_SMOKE_ALLOW_ERRORS=1 to report (not fail on) blocks that show an API error state,
 * EXTORQ_SMOKE_ALERTS="VM-001=<alert id>,GH-001=<alert id>,..." to pin the investigation checked
 * for a mandatory rule (otherwise the newest alert of that rule in the last 30 days is used).
 *
 * Coverage (demo readiness): overview; every asset class (macOS host, Linux VM, kind cluster,
 * Kubernetes node, GitHub repository) with its overview / services / findings / events tabs;
 * a Kubernetes workload, a Kubernetes Service and a host service; the investigation of each
 * mandatory rule (VM-001, VM-002, K8S-001, K8S-002, GH-001) section by section, including the
 * honest state of the Jev and Gemini panels; detection filters; system health; viewer
 * read-only behaviour.
 * Exit code 0 when every check passed, 1 otherwise.
 */
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const baseArg = args.indexOf("--base");
const BASE = new URL(baseArg >= 0 && args[baseArg + 1] ? args[baseArg + 1] : "http://127.0.0.1:3100");
const ALLOW_ERRORS = process.env.EXTORQ_SMOKE_ALLOW_ERRORS === "1";
const TIMEOUT_MS = 30_000;
// Each console page costs the API about 10-20 ClickHouse queries and the read identity is
// limited to 1200 queries per minute (shared with every other API user): pace the requests
// so a full run never exhausts it (EXTORQ_SMOKE_PACE_MS, default 1500 ms between requests).
const PACE_MS = Math.max(0, Number.parseInt(process.env.EXTORQ_SMOKE_PACE_MS ?? "1500", 10) || 0);
let lastRequestAt = 0;

async function pace() {
  const wait = lastRequestAt + PACE_MS - Date.now();
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  lastRequestAt = Date.now();
}

const results = [];
function record(ok, name, detail = "") {
  results.push({ ok, name, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
}

function readPassword(envName) {
  const path = process.env[envName];
  if (!path) return null;
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    console.log(`SKIP  cannot read the file named by ${envName}`);
    return null;
  }
}

async function request(path, { cookie, method = "GET", body, headers = {} } = {}) {
  await pace();
  const url = new URL(path, BASE);
  const response = await fetch(url, {
    method,
    body,
    redirect: "manual",
    headers: { ...(cookie ? { Cookie: cookie } : {}), ...headers },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const text = await response.text();
  return { status: response.status, headers: response.headers, text };
}

/** Plain-text view of the HTML (tags removed, entities for quotes/ampersands decoded). */
function visibleText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ");
}

function attr(tag, name) {
  const match = tag.match(new RegExp(`${name}="([^"]*)"`));
  return match ? match[1].replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#x27;/g, "'") : null;
}

/**
 * Hidden inputs of the first <form> on the page whose markup contains `marker` (the server
 * action's progressive-enhancement fields).
 */
function formFields(html, marker = "") {
  const form = (html.match(/<form[\s\S]*?<\/form>/gi) ?? []).find((f) => f.includes(marker));
  if (!form) return null;
  const fields = [];
  for (const tag of form.match(/<input[^>]*>/gi) ?? []) {
    if (attr(tag, "type") !== "hidden") continue;
    const name = attr(tag, "name");
    if (name) fields.push([name, attr(tag, "value") ?? ""]);
  }
  return fields;
}

function sessionCookie(headers) {
  const all = headers.getSetCookie ? headers.getSetCookie() : [headers.get("set-cookie") ?? ""];
  const session = all.find((c) => /^(__Host-)?extorq_session=/.test(c) && !/^(__Host-)?extorq_session=;/.test(c));
  return session ? session.split(";")[0] : null;
}

async function login(user, password) {
  const page = await request("/login");
  const fields = formFields(page.text);
  if (page.status !== 200 || !fields) return { cookie: null, detail: `login page HTTP ${page.status}` };
  const form = new FormData();
  for (const [name, value] of fields) form.append(name, value);
  form.set("username", user);
  form.set("password", password);
  form.set("next", "/");
  const response = await request("/login", {
    method: "POST",
    body: form,
    headers: { Origin: BASE.origin, Accept: "text/html" },
  });
  const cookie = sessionCookie(response.headers);
  return { cookie, detail: `HTTP ${response.status}` };
}

function checkSecurityHeaders(name, headers) {
  const csp = headers.get("content-security-policy") ?? "";
  const problems = [];
  if (!csp.includes("frame-ancestors 'none'")) problems.push("CSP without frame-ancestors 'none'");
  if (csp.includes("unsafe-eval")) problems.push("CSP allows unsafe-eval");
  if (!/script-src [^;]*'nonce-/.test(csp)) problems.push("CSP script-src without nonce");
  if (headers.get("x-content-type-options") !== "nosniff") problems.push("no nosniff");
  if (headers.get("referrer-policy") !== "no-referrer") problems.push("referrer-policy");
  record(problems.length === 0, `${name}: security headers`, problems.join("; "));
}

async function page(name, path, cookie, markers, { expectErrorState = false } = {}) {
  let response;
  try {
    response = await request(path, { cookie });
  } catch (error) {
    record(false, `${name} ${path}`, `request failed: ${error.name}`);
    return null;
  }
  const text = visibleText(response.text);
  const missing = markers.filter((m) => !text.includes(m));
  const errorBlocks = (text.match(/Couldn't load [^.]*\./g) ?? []).slice(0, 3);
  const ok =
    response.status === 200 && missing.length === 0 && (ALLOW_ERRORS || expectErrorState || errorBlocks.length === 0);
  const detail = [
    `HTTP ${response.status}`,
    missing.length ? `missing: ${missing.join(", ")}` : "",
    errorBlocks.length ? `error states: ${errorBlocks.join(" ")}` : "",
  ]
    .filter(Boolean)
    .join("; ");
  record(ok, `${name} ${path}`, detail);
  return response;
}

function firstLink(html, prefix) {
  const match = html.match(new RegExp(`href="(${prefix}[^"?#]+)"`));
  return match ? match[1].replace(/&amp;/g, "&") : null;
}

function allLinks(html, prefix) {
  const out = new Set();
  for (const m of html.matchAll(new RegExp(`href="(${prefix}[^"?#]+)"`, "g"))) out.add(m[1].replace(/&amp;/g, "&"));
  return [...out];
}

/** HTML of the panel whose heading has `id`, up to the next panel heading (best effort). */
function section(html, id) {
  const start = html.indexOf(`id="${id}"`);
  if (start < 0) return "";
  const next = html.indexOf("<h2 id=", start + id.length + 5);
  return html.slice(start, next < 0 ? undefined : next);
}

const MANDATORY_RULES = ["VM-001", "VM-002", "K8S-001", "K8S-002", "GH-001"];
const SEVERITY_WORDS = ["Critical", "High", "Medium", "Low", "Info"];

function pinnedAlerts() {
  const pinned = {};
  for (const part of (process.env.EXTORQ_SMOKE_ALERTS ?? "").split(",")) {
    const [rule, id] = part.split("=").map((s) => s?.trim());
    if (rule && id && /^[0-9a-f]{32}$/.test(id)) pinned[rule] = id;
  }
  return pinned;
}

/** Rule ids shown in the alert-history table (not the filter form's options or the rules table). */
function tableRuleIds(html) {
  const history = section(html, "alert-history-title");
  const table = history.slice(Math.max(0, history.indexOf("<table")));
  return [...table.matchAll(/>([A-Z][A-Z0-9]{1,15}-\d{3})<\/span>/g)].map((m) => m[1]);
}

/**
 * Investigation of one mandatory rule: every section renders, the header carries severity,
 * evidence confidence and the simulation badge, and the AI panels are either real
 * assessments or their honest empty states.
 */
async function investigation(rule, cookie, pinned) {
  let path = pinned[rule] ? `/investigations/${pinned[rule]}` : null;
  if (!path) {
    const list = await page(`detections filtered by ${rule}`, `/detections?rule=${rule}&range=30d`, cookie, ["Alert history"]);
    path = list ? firstLink(list.text, "/investigations/") : null;
  }
  if (!path) {
    record(false, `investigation ${rule}`, "no alert of this rule in the last 30 days");
    return null;
  }
  const response = await page(`investigation ${rule}`, path, cookie, [
    rule,
    "Evidence confidence",
    "Why this rule fired",
    "Event timeline",
    "Supporting evidence",
    "Coverage and known gaps",
    "Involved services and assets",
    "Jev contextual assessment",
    "Gemini overview",
    "Correlated observations",
    "Analyst status",
  ]);
  if (!response) return path;
  const text = visibleText(response.text);
  const header = text.slice(0, text.indexOf("Evidence confidence"));
  record(SEVERITY_WORDS.some((w) => header.includes(w)), `investigation ${rule}: severity in the header`);
  record(header.includes("Simulation"), `investigation ${rule}: simulation badge (scenario telemetry)`);
  record(
    /Evidence confidence\s+(High|Medium|Low)/.test(text),
    `investigation ${rule}: evidence confidence shown`,
  );
  const timeline = visibleText(section(response.text, "timeline-title"));
  record(timeline.includes("Evidence"), `investigation ${rule}: timeline marks the evidence`);
  record(
    !/(\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+) \1\b/.test(timeline),
    `investigation ${rule}: timeline rows do not repeat the event type`,
  );
  const evidenceRows = (section(response.text, "evidence-title").match(/id="evidence-[0-9a-f]{32}"/g) ?? []).length;
  record(evidenceRows > 0, `investigation ${rule}: evidence table has rows`, `${evidenceRows} rows`);
  const jev = visibleText(section(response.text, "jev-title"));
  record(
    jev.includes("No Jev triage exists for this alert") || jev.includes("Recommendation") || jev.includes("did not"),
    `investigation ${rule}: Jev panel is an assessment or an honest empty state`,
  );
  const gemini = visibleText(section(response.text, "gemini-title"));
  record(
    gemini.includes("No overview has been generated for this alert") ||
      gemini.includes("What happened") ||
      gemini.includes("did not produce an overview"),
    `investigation ${rule}: Gemini panel is an overview or an honest empty state`,
  );
  return path;
}

/** Overview, services, findings and events tabs of one asset of each class. */
async function assetDrilldown(assetsHtml, cookie) {
  const links = allLinks(assetsHtml, "/assets/");
  const classes = [
    { name: "macOS host", test: (l) => l.startsWith("/assets/macos%3A"), services: ["Services", "Discovered"] },
    { name: "Linux VM", test: (l) => l.startsWith("/assets/linux%3A"), services: ["Services", "Discovered"] },
    {
      name: "kind cluster",
      test: (l) => l.startsWith("/assets/k8s%3A") && !l.includes("%2F"),
      services: ["Workloads and Services", "Workloads", "Kubernetes Services"],
    },
    {
      name: "Kubernetes node",
      test: (l) => l.startsWith("/assets/k8s%3A") && l.includes("%2Fnode%2F"),
      services: ["Workloads on node", "Workloads running on this node"],
      overview: ["via the cluster"],
    },
    { name: "GitHub repository", test: (l) => /^\/assets\/github%3A[^%]+%2F/.test(l), services: ["Services"] },
  ];
  const found = {};
  for (const c of classes) {
    const path = links.find(c.test);
    if (!path) {
      record(false, `asset drill-down: ${c.name}`, "no asset of this class is listed");
      continue;
    }
    await page(`${c.name} overview`, path, cookie, ["Telemetry sources", "Events by source", "Inventory", "Recent alerts", ...(c.overview ?? [])]);
    found[c.name] = await page(`${c.name} services`, `${path}?tab=services`, cookie, c.services);
    await page(`${c.name} findings`, `${path}?tab=findings`, cookie, ["Vulnerabilities and misconfigurations"]);
    await page(`${c.name} events`, `${path}?tab=events`, cookie, ["Recent events"]);
  }

  const cluster = found["kind cluster"]?.text ?? "";
  const workload = firstLink(section(cluster, "services-k8s_workload"), "/services/");
  const k8sService = firstLink(section(cluster, "services-k8s_service"), "/services/");
  const hostService = firstLink(found["Linux VM"]?.text ?? "", "/services/");
  const nodeWorkload = firstLink(section(found["Kubernetes node"]?.text ?? "", "hosted-title"), "/services/");
  if (workload) {
    await page("Kubernetes workload detail", workload, cookie, ["Coverage", "Telemetry", "Instances", "Pod", "Kubernetes workload"]);
  } else record(false, "Kubernetes workload detail", "the cluster lists no workload");
  if (k8sService) {
    await page("Kubernetes Service detail", k8sService, cookie, [
      "Kubernetes Service",
      "Ports and exposure",
      "has no process or container of its own",
    ]);
  } else record(false, "Kubernetes Service detail", "the cluster lists no Kubernetes Service");
  if (hostService) {
    await page("Linux host service detail", hostService, cookie, ["Coverage", "Telemetry", "Ports and exposure", "Instances", "Authentication activity"]);
  } else record(false, "Linux host service detail", "the VM lists no service");
  record(Boolean(nodeWorkload), "Kubernetes node links to the workloads running on it", nodeWorkload ?? "no link");
}

/** Detection filters reach the API and the table honours them. */
async function detectionFilters(cookie) {
  const byRule = await page("detections: rule filter", "/detections?rule=VM-001&range=30d", cookie, ["Alert history", "match the filters"]);
  if (byRule) {
    const ids = tableRuleIds(byRule.text);
    record(ids.length > 0 && ids.every((id) => id === "VM-001"), "detections: rule filter keeps only VM-001 rows", ids.join(" ") || "no rows");
  }
  const byAsset = await page("detections: asset filter", "/detections?asset=k8s%3Aextorq-lab&range=30d", cookie, ["Alert history"]);
  if (byAsset) {
    const ids = tableRuleIds(byAsset.text);
    record(ids.length > 0 && ids.every((id) => id.startsWith("K8S-") || id === "APP-001"), "detections: asset filter keeps cluster rows", [...new Set(ids)].join(" ") || "no rows");
  }
  await page("detections: severity filter", "/detections?severity=high&range=30d", cookie, ["Alert history", "match the filters"]);
  await page("detections: status filter", "/detections?status=new&range=30d", cookie, ["Alert history", "match the filters"]);
  await page("detections: rules table", "/detections", cookie, ["Detection rules", ...MANDATORY_RULES]);
}

async function main() {
  console.log(`ExtorQ console smoke test against ${BASE.origin}`);

  const health = await request("/healthz");
  record(health.status === 200 && health.text.trim() === "ok", "liveness /healthz", `HTTP ${health.status}`);

  const anon = await request("/assets");
  const location = anon.headers.get("location") ?? "";
  record(anon.status === 303 && location.startsWith("/login"), "unauthenticated page redirects to /login", `HTTP ${anon.status} -> ${location}`);
  checkSecurityHeaders("redirect", anon.headers);

  const anonPost = await request("/", { method: "POST", body: "x", headers: { "Content-Type": "text/plain" } });
  record(anonPost.status === 401, "unauthenticated POST is rejected", `HTTP ${anonPost.status}`);

  const loginPage = await request("/login");
  record(loginPage.status === 200 && visibleText(loginPage.text).includes("Sign in"), "login page renders", `HTTP ${loginPage.status}`);

  const badLogin = await login(process.env.EXTORQ_SMOKE_ANALYST_USER ?? "analyst", "definitely-not-the-password");
  record(badLogin.cookie === null, "wrong password gets no session", badLogin.detail);

  const analystPassword = readPassword("EXTORQ_SMOKE_ANALYST_PASSWORD_FILE");
  if (!analystPassword) {
    record(false, "analyst sign-in", "EXTORQ_SMOKE_ANALYST_PASSWORD_FILE not set or unreadable");
    return finish();
  }
  const analyst = await login(process.env.EXTORQ_SMOKE_ANALYST_USER ?? "analyst", analystPassword);
  record(Boolean(analyst.cookie), "analyst sign-in sets a session cookie", analyst.detail);
  if (!analyst.cookie) return finish();
  const cookie = analyst.cookie;

  const overview = await page("overview", "/", cookie, [
    "Overview",
    "Telemetry coverage",
    "Service coverage",
    "Detection alerts over time",
    "Security posture",
    "Recent important alerts",
    "Collection health",
  ]);
  if (overview) checkSecurityHeaders("overview", overview.headers);

  const assets = await page("assets", "/assets", cookie, ["Assets", "macOS hosts", "Linux VMs", "Kubernetes", "GitHub"]);
  if (assets) await assetDrilldown(assets.text, cookie);
  const assetPath = assets ? firstLink(assets.text, "/assets/") : null;
  if (assetPath) {
    await page("asset overview", assetPath, cookie, ["Telemetry sources", "Events by source", "Inventory", "Recent alerts"]);
    const services = await page("asset services", `${assetPath}?tab=services`, cookie, ["Overview", "Findings"]);
    await page("asset findings", `${assetPath}?tab=findings`, cookie, ["Vulnerabilities and misconfigurations"]);
    await page("asset events", `${assetPath}?tab=events`, cookie, ["Recent events"]);
    const servicePath = services ? firstLink(services.text, "/services/") : null;
    if (servicePath) {
      await page("service detail", servicePath, cookie, ["Coverage", "Telemetry", "Ports and exposure", "Instances", "Authentication activity", "Alerts", "Findings"]);
    } else {
      console.log("SKIP  service detail: the first asset lists no service");
    }
  } else {
    console.log("SKIP  asset detail: no asset is listed yet");
  }

  const detections = await page("detections", "/detections", cookie, ["Detections", "Alert history", "Detection rules"]);
  let investigationPath = detections ? firstLink(detections.text, "/investigations/") : null;
  const pinned = pinnedAlerts();
  for (const rule of MANDATORY_RULES) {
    const path = await investigation(rule, cookie, pinned);
    investigationPath ??= path;
  }
  await detectionFilters(cookie);
  await page("health", "/health", cookie, [
    "System health",
    "Ingestion spool",
    "Collectors",
    "Ingestion pipeline",
    "Rule execution",
    "Quarantine and rejections",
    "AI providers",
  ]);
  await page("filtered detections", "/detections?severity=high&range=24h", cookie, ["Alert history"]);
  await page("invalid alert id is refused before the API", "/investigations/not-an-id", cookie, ["The alert id in the address is not valid."], {
    expectErrorState: true,
  });

  const viewerPassword = readPassword("EXTORQ_SMOKE_VIEWER_PASSWORD_FILE");
  if (viewerPassword) {
    const viewer = await login(process.env.EXTORQ_SMOKE_VIEWER_USER ?? "viewer", viewerPassword);
    record(Boolean(viewer.cookie), "viewer sign-in sets a session cookie", viewer.detail);
    if (viewer.cookie && investigationPath) {
      await page("viewer investigation is read-only", investigationPath, viewer.cookie, [
        "Viewer accounts can read investigations but cannot change their status",
        "Viewer accounts cannot request AI overviews",
      ]);
      await forgedViewerStateChange(cookie, viewer.cookie, investigationPath);
    }
  }
  return finish();
}

/**
 * Server-side role enforcement: replay the analyst's state-change form as the viewer. The
 * server action must refuse it before calling the API, so nothing is written.
 */
async function forgedViewerStateChange(analystCookie, viewerCookie, path) {
  const analystPage = await request(path, { cookie: analystCookie });
  const fields = formFields(analystPage.text, 'name="status"');
  if (!fields) {
    record(false, "forged viewer state change", "analyst page has no status form");
    return;
  }
  const form = new FormData();
  for (const [name, value] of fields) form.append(name, value);
  form.set("status", "closed_benign");
  form.set("note", "smoke test: this change must be refused");
  // Read the streamed response only until the refusal appears: Next.js 16 keeps the no-JS
  // action response open after the page has been sent (JS clients use the RSC fetch path).
  const marker = "This action requires the analyst role.";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let status = 0;
  let refused = false;
  try {
    const response = await fetch(new URL(path, BASE), {
      method: "POST",
      body: form,
      redirect: "manual",
      headers: { Cookie: viewerCookie, Origin: BASE.origin, Accept: "text/html" },
      signal: controller.signal,
    });
    status = response.status;
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.includes(marker)) {
        refused = true;
        break;
      }
    }
  } catch {
    // aborted after the timeout: refused stays false
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  record(status === 200 && refused, "forged viewer state change is refused server-side", `HTTP ${status}`);
}

function finish() {
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length} passed, ${failed.length} failed`);
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((error) => {
  console.log(`FAIL  smoke test aborted: ${error.name}: ${error.message}`);
  process.exit(1);
});
