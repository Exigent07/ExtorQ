/** Finding display rules: doubled title prefixes, one advisory listed by several scanners. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { advisoryKey, displayFindingTitle, scannersByAdvisory } from "../findings";

describe("displayFindingTitle", () => {
  it("drops a doubled package prefix, at the start or after a colon", () => {
    assert.equal(displayFindingTitle("urllib3: urllib3: HTTPS proxy leaks headers"), "urllib3: HTTPS proxy leaks headers");
    assert.equal(
      displayFindingTitle("CVE-2026-97689 in urllib3 1.26.12: urllib3: urllib3: Denial of service"),
      "CVE-2026-97689 in urllib3 1.26.12: urllib3: Denial of service",
    );
    assert.equal(displayFindingTitle("kernel: sctp: drop a chunk"), "kernel: sctp: drop a chunk");
    assert.equal(displayFindingTitle("Certifi: certifi: removal of roots"), "certifi: removal of roots");
  });
});

describe("advisoryKey / scannersByAdvisory", () => {
  const dependabot = { check_id: "dependabot:GHSA-6q48-6c7w-9gw2", cve_ids: [], package_name: "certifi", scanner: "github-dependabot" };
  const trivy = { check_id: "CVE-2026-1", cve_ids: ["ghsa-6q48-6c7w-9gw2"], package_name: "Certifi", scanner: "trivy" };
  const semgrep = { check_id: "python.lang.security.audit", cve_ids: [], package_name: null, scanner: "semgrep" };
  it("keys on the first advisory id and the package", () => {
    assert.equal(advisoryKey(dependabot), "GHSA-6Q48-6C7W-9GW2|certifi");
    assert.equal(advisoryKey(trivy), "GHSA-6Q48-6C7W-9GW2|certifi");
    assert.equal(advisoryKey(semgrep), null);
  });
  it("lists only advisories reported by more than one scanner", () => {
    assert.deepEqual([...scannersByAdvisory([dependabot, trivy, semgrep])], [["GHSA-6Q48-6C7W-9GW2|certifi", ["github-dependabot", "trivy"]]]);
    assert.equal(scannersByAdvisory([dependabot]).size, 0);
  });
});
