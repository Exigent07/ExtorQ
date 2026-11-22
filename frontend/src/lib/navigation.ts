/**
 * Console navigation model (pure, unit-tested): the sidebar groups and the breadcrumb trail
 * derived from the current path. Identifiers taken from the path are validated and shown as
 * text only; an invalid one is never echoed back.
 */
import { decodeSegment, isAssetId, isHexId } from "@/lib/security/ids";
import { sanitizeForDisplay, shortId, truncateText } from "@/lib/security/display";

export type NavKey = "overview" | "assets" | "detections" | "health";

export interface NavItem {
  key: NavKey;
  href: string;
  label: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      { key: "overview", href: "/", label: "Overview" },
      { key: "assets", href: "/assets", label: "Assets" },
    ],
  },
  { label: "Detect", items: [{ key: "detections", href: "/detections", label: "Detections" }] },
  { label: "Operate", items: [{ key: "health", href: "/health", label: "System health" }] },
];

/** Which sidebar item a path belongs to (detail pages belong to their list). */
export function activeNav(pathname: string): NavKey | null {
  const first = pathname.split("/").filter(Boolean)[0] ?? "";
  switch (first) {
    case "":
      return "overview";
    case "assets":
    case "services":
      return "assets";
    case "detections":
    case "investigations":
      return "detections";
    case "health":
      return "health";
    default:
      return null;
  }
}

export interface Crumb {
  label: string;
  href?: string;
  /** Identifier crumbs are set in the figure face. */
  mono?: boolean;
}

function assetCrumb(raw: string | undefined): Crumb {
  const decoded = raw ? decodeSegment(raw) : null;
  return decoded && isAssetId(decoded) ? { label: decoded, mono: true } : { label: "Asset" };
}

function hexCrumb(noun: string, raw: string | undefined): Crumb {
  const decoded = raw ? decodeSegment(raw) : null;
  return decoded && isHexId(decoded) ? { label: `${noun} ${shortId(decoded, 8)}`, mono: true } : { label: noun };
}

/** Breadcrumb trail for the top bar: nav group, section, and the current object. */
export function routeCrumbs(pathname: string): Crumb[] {
  const parts = pathname.split("/").filter(Boolean);
  switch (parts[0]) {
    case undefined:
      return [{ label: "Monitor" }, { label: "Overview" }];
    case "assets":
      return parts.length > 1
        ? [{ label: "Monitor" }, { label: "Assets", href: "/assets" }, assetCrumb(parts[1])]
        : [{ label: "Monitor" }, { label: "Assets" }];
    case "services":
      return [{ label: "Monitor" }, { label: "Assets", href: "/assets" }, hexCrumb("Service", parts[1])];
    case "detections":
      return [{ label: "Detect" }, { label: "Detections" }];
    case "investigations":
      return [{ label: "Detect" }, { label: "Detections", href: "/detections" }, hexCrumb("Alert", parts[1])];
    case "health":
      return [{ label: "Operate" }, { label: "System health" }];
    default:
      return [{ label: "ExtorQ" }];
  }
}

/**
 * A crumb label from an API value (a service name, an asset id): display-sanitised (bidi,
 * invisible and control characters become visible markers) and capped, so a page can name its
 * object in the top bar without passing raw telemetry to it.
 */
export function crumbLabel(value: string, limit = 48): string {
  return truncateText(sanitizeForDisplay(value).text, limit).text;
}
