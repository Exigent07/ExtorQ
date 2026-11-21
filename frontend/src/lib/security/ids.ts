/**
 * Validation of identifiers that come from the URL before they reach the API.
 *
 * Patterns mirror backend/src/extorq/contracts/common.py. Anything that does not match
 * is treated as "not found" without calling the API, so a crafted path segment
 * (`..`, `%2e%2e`, query fragments) can never alter the upstream request path.
 */
const HEX_ID = /^[0-9a-f]{32}$/;
const ASSET_ID = /^[a-z0-9][a-z0-9._:/-]{2,199}$/;
const RULE_ID = /^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$/;

/** Decode a dynamic route segment once; Next.js may hand it over percent-encoded. */
export function decodeSegment(raw: string): string | null {
  if (!raw.includes("%")) return raw;
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

export function isHexId(value: string): boolean {
  return HEX_ID.test(value);
}

export function isAssetId(value: string): boolean {
  return ASSET_ID.test(value) && !value.split("/").some((part) => part === "." || part === "..");
}

export function isRuleId(value: string): boolean {
  return RULE_ID.test(value);
}

export function parseHexIdSegment(raw: string): string | null {
  const decoded = decodeSegment(raw);
  return decoded !== null && isHexId(decoded) ? decoded : null;
}

export function parseAssetIdSegment(raw: string): string | null {
  const decoded = decodeSegment(raw);
  return decoded !== null && isAssetId(decoded) ? decoded : null;
}

/** Console URL of an asset: the id is percent-encoded into a single path segment. */
export function assetHref(assetId: string): string {
  return `/assets/${encodeURIComponent(assetId)}`;
}

/** Console URL of an investigation. Returns null for ids that are not valid alert ids. */
export function investigationHref(alertId: string): string | null {
  return isHexId(alertId) ? `/investigations/${alertId}` : null;
}

/** Console URL of a service. Returns null for ids that are not valid service ids. */
export function serviceHref(serviceId: string): string | null {
  return isHexId(serviceId) ? `/services/${serviceId}` : null;
}
