/**
 * Display hygiene, open-redirect protection, identifier validation and CSP.
 * Invisible and control characters are built with String.fromCodePoint so this source file
 * itself contains none of them.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildCsp, createNonce } from "../security/csp";
import { sanitizeForDisplay, shortId, truncateText } from "../security/display";
import {
  assetHref,
  investigationHref,
  isAssetId,
  isHexId,
  isRuleId,
  parseAssetIdSegment,
  parseHexIdSegment,
  serviceHref,
} from "../security/ids";
import { safeNextPath } from "../security/redirect";

const cp = (...codes: number[]) => String.fromCodePoint(...codes);

describe("sanitizeForDisplay", () => {
  it("makes a bidi override visible instead of applying it", () => {
    const input = `invoice${cp(0x202e)}fdp.exe`;
    const out = sanitizeForDisplay(input);
    assert.equal(out.replaced, 1);
    assert.ok(out.text.includes("⟨U+202E⟩"));
    assert.ok(!out.text.includes(cp(0x202e)));
  });

  it("marks zero-width, tag (ASCII smuggling) and line-separator characters", () => {
    const input = `a${cp(0x200b)}b${cp(0xe0041)}c${cp(0x2028)}d${cp(0xfeff)}`;
    const out = sanitizeForDisplay(input);
    assert.equal(out.replaced, 4);
    for (const marker of ["⟨U+200B⟩", "⟨U+E0041⟩", "⟨U+2028⟩", "⟨U+FEFF⟩"]) assert.ok(out.text.includes(marker), marker);
  });

  it("marks C0/C1 controls such as ANSI escape sequences", () => {
    const out = sanitizeForDisplay(`${cp(0x1b)}[31mred${cp(0x9b)}`);
    assert.equal(out.replaced, 2);
    assert.ok(out.text.startsWith("⟨U+001B⟩"));
  });

  it("keeps line breaks only in multiline mode and drops carriage returns", () => {
    assert.equal(sanitizeForDisplay("a\r\nb").text, "a ⏎ b");
    assert.equal(sanitizeForDisplay("a\r\nb", true).text, "a\nb");
    assert.equal(sanitizeForDisplay("a\tb").text, "a b");
  });

  it("leaves ordinary text, including non-Latin scripts, untouched", () => {
    const text = "Failed password for root from 10.0.2.2 port 51234 ssh2 · Größe · 東京";
    assert.deepEqual(sanitizeForDisplay(text), { text, replaced: 0 });
  });
});

describe("truncateText / shortId", () => {
  it("never splits a surrogate pair", () => {
    const emoji = cp(0x1f512);
    const out = truncateText(`${emoji}${emoji}${emoji}`, 2);
    assert.equal(out.truncated, true);
    assert.equal(out.text, `${emoji}${emoji}…`);
  });
  it("does not truncate short values", () => {
    assert.deepEqual(truncateText("short", 10), { text: "short", truncated: false });
  });
  it("shortens identifiers", () => {
    assert.equal(shortId("0123456789abcdef"), "01234567…");
    assert.equal(shortId("abc"), "abc");
  });
});

describe("safeNextPath", () => {
  it("accepts same-origin absolute paths", () => {
    assert.equal(safeNextPath("/detections?severity=high"), "/detections?severity=high");
    assert.equal(safeNextPath("/assets/k8s%3Aextorq-lab"), "/assets/k8s%3Aextorq-lab");
  });
  it("rejects open-redirect tricks", () => {
    for (const value of [
      "//evil.example",
      "/\\evil.example",
      "https://evil.example/",
      "javascript:alert(1)",
      "evil",
      `/x${cp(0x0a)}y`,
      "/login",
      "/login?next=/x",
      "/" + "a".repeat(600),
      42,
      null,
    ]) {
      assert.equal(safeNextPath(value), "/", String(value));
    }
  });
});

describe("identifier validation", () => {
  it("validates hex ids", () => {
    assert.ok(isHexId("0123456789abcdef0123456789abcdef"));
    assert.ok(!isHexId("0123456789ABCDEF0123456789ABCDEF"));
    assert.ok(!isHexId("../../etc/passwd"));
  });
  it("accepts contract asset ids, including Kubernetes node ids with slashes", () => {
    for (const id of ["macos:workstation-01", "linux:lab-vm-01", "k8s:extorq-lab", "k8s:extorq-lab/node/extorq-lab-control-plane", "github:owner/extorq-lab"]) {
      assert.ok(isAssetId(id), id);
    }
  });
  it("rejects path traversal and other shapes", () => {
    for (const id of ["k8s:extorq-lab/../x", "a/./b", "UPPER:case", "x", "github:owner/repo?x=1", "github:owner/repo#frag", "a b c"]) {
      assert.ok(!isAssetId(id), id);
    }
  });
  it("decodes a percent-encoded segment once and validates it", () => {
    assert.equal(parseAssetIdSegment("k8s%3Aextorq-lab%2Fnode%2Fworker"), "k8s:extorq-lab/node/worker");
    assert.equal(parseAssetIdSegment("%E0%A4%A"), null);
    assert.equal(parseAssetIdSegment("..%2F..%2Fadmin"), null);
    assert.equal(parseHexIdSegment("0123456789abcdef0123456789abcdef"), "0123456789abcdef0123456789abcdef");
    assert.equal(parseHexIdSegment("not-an-id"), null);
  });
  it("builds console links only for valid ids", () => {
    assert.equal(assetHref("github:owner/repo"), "/assets/github%3Aowner%2Frepo");
    assert.equal(investigationHref("nope"), null);
    assert.equal(serviceHref("0123456789abcdef0123456789abcdef"), "/services/0123456789abcdef0123456789abcdef");
    assert.equal(serviceHref("../x"), null);
    assert.ok(isRuleId("VM-001") && isRuleId("CORR-002") && !isRuleId("vm-001"));
  });
});

describe("Content-Security-Policy", () => {
  it("production policy: nonce scripts, no unsafe-eval, no framing", () => {
    const csp = buildCsp({ nonce: "abc123", dev: false, https: true });
    assert.ok(csp.includes("script-src 'self' 'nonce-abc123' 'strict-dynamic'"));
    assert.ok(!csp.includes("unsafe-eval"));
    assert.ok(!/script-src[^;]*unsafe-inline/.test(csp));
    assert.ok(csp.includes("frame-ancestors 'none'"));
    assert.ok(csp.includes("object-src 'none'"));
    assert.ok(csp.includes("base-uri 'none'"));
    assert.ok(csp.includes("upgrade-insecure-requests"));
  });
  it("development policy is the only one allowing eval", () => {
    assert.ok(buildCsp({ nonce: "n", dev: true, https: false }).includes("'unsafe-eval'"));
    assert.ok(!buildCsp({ nonce: "n", dev: false, https: false }).includes("upgrade-insecure-requests"));
  });
  it("creates 128-bit random nonces", () => {
    const a = createNonce();
    const b = createNonce();
    assert.notEqual(a, b);
    assert.equal(Buffer.from(a, "base64").length, 16);
  });
});
