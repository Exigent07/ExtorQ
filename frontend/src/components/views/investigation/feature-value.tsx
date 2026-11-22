import { cn } from "cn";

import { KeyValueList } from "@/components/console/key-values";
import { EmptyState } from "@/components/console/states";
import { UntrustedText } from "@/components/console/untrusted-text";
import { DASH, formatCount } from "@/lib/format";

import { Chip } from "./marks";
import { type FeatureView, featureLabel, orderFeatures } from "./model";
import { MoreChips } from "./more-chips";

/** Chips shown before the rest of a list moves into the "+N more" hover card. */
const LIST_PREVIEW = 8;

/**
 * A list of untrusted values as chips: the first `preview` inline, the rest in a hover card.
 * Each value goes through UntrustedText (long values cut with the full value in a popover).
 */
export function ValueChips({
  values,
  title,
  preview = LIST_PREVIEW,
  mono = true,
  align = "end",
}: {
  values: readonly (string | number | boolean)[];
  /** Heading of the hover card that lists the remaining values. */
  title: string;
  preview?: number;
  mono?: boolean;
  align?: "start" | "end";
}) {
  const chip = (value: string | number | boolean, index: number) => (
    <Chip key={`${index}:${String(value)}`} mono={mono}>
      <UntrustedText value={String(value)} limit={64} />
    </Chip>
  );
  return (
    <span className={cn("inline-flex max-w-full flex-wrap gap-1", align === "end" ? "justify-end" : "justify-start")}>
      {values.slice(0, preview).map(chip)}
      {values.length > preview ? (
        <MoreChips count={values.length - preview} title={title}>
          {values.slice(preview).map((value, index) => chip(value, index + preview))}
        </MoreChips>
      ) : null}
    </span>
  );
}

/**
 * One feature value, never as raw JSON text: scalars as themselves (booleans as Yes/No,
 * numbers in the figure face, 0 as 0), lists as chips, flat objects as key/value pairs and
 * deeper structures as a count of fields. Strings are telemetry-derived: UntrustedText.
 */
export function FeatureValue({ view, label, align = "end" }: { view: FeatureView; label: string; align?: "start" | "end" }) {
  switch (view.kind) {
    case "unknown":
      return <span className="text-muted-foreground">{DASH}</span>;
    case "boolean":
      return <span className={view.value ? "text-foreground" : "text-fg-2"}>{view.value ? "Yes" : "No"}</span>;
    case "number":
      return <span className="font-mono text-foreground tabular-nums">{formatCount(view.value)}</span>;
    case "text":
      return <UntrustedText value={view.value} limit={96} mono className="text-foreground" />;
    case "list":
      return view.items.length === 0 ? (
        <span className="text-muted-foreground">None</span>
      ) : (
        <ValueChips values={view.items} title={`${label}: all ${formatCount(view.items.length)} values`} align={align} />
      );
    case "record":
      return (
        <span className={cn("inline-flex max-w-full flex-wrap gap-1", align === "end" ? "justify-end" : "justify-start")}>
          {view.entries.map(([key, value]) => (
            <Chip key={key}>
              <span className="text-muted-foreground">{featureLabel(key)}</span>
              <span className="ml-1.5 font-mono">{value === null ? DASH : <UntrustedText value={String(value)} limit={48} />}</span>
            </Chip>
          ))}
        </span>
      );
    case "structured":
      return <span className="text-muted-foreground">Structured value · {formatCount(view.size)} fields</span>;
  }
}

/** Text longer than this, lists and objects get a full-width row instead of a right-aligned value. */
const WIDE_TEXT = 28;

function isWide(view: FeatureView): boolean {
  return (
    view.kind === "list" ||
    view.kind === "record" ||
    view.kind === "structured" ||
    (view.kind === "text" && Array.from(view.value).length > WIDE_TEXT)
  );
}

/**
 * A set of features (detector, correlation layer, source attributes): short values as
 * key/value rows in two balanced columns on wide containers, then lists and long values as
 * full-width rows (label beside or above the chips), so nothing breaks mid-word.
 */
export function FeatureTable({
  features,
  empty,
  columns = 2,
}: {
  features: Record<string, unknown> | null | undefined;
  empty: string;
  /** 2: balanced columns when the container is wide; 1: always one column (sheets). */
  columns?: 1 | 2;
}) {
  const all = orderFeatures(features);
  if (all.length === 0) return <EmptyState className="mt-2">{empty}</EmptyState>;
  const rows = (items: typeof all) =>
    items.map(([key, view]) => ({ label: featureLabel(key), value: <FeatureValue view={view} label={featureLabel(key)} /> }));
  const scalars = all.filter(([, view]) => !isWide(view));
  const wide = all.filter(([, view]) => isWide(view));
  const half = columns === 2 ? Math.ceil(scalars.length / 2) : scalars.length;
  return (
    <div className="@container">
      {scalars.length > 0 ? (
        <div className={cn("grid gap-x-10", columns === 2 && "@3xl:grid-cols-2")}>
          <KeyValueList rows={rows(scalars.slice(0, half))} />
          {scalars.length > half ? (
            <KeyValueList rows={rows(scalars.slice(half))} className="border-t border-hairline-soft @3xl:border-t-0" />
          ) : null}
        </div>
      ) : null}
      {wide.length > 0 ? (
        <dl className={cn("divide-y divide-hairline-soft", scalars.length > 0 && "border-t border-hairline-soft")}>
          {wide.map(([key, view]) => (
            <div key={key} className="grid gap-1.5 py-2.5 @2xl:grid-cols-[13rem_minmax(0,1fr)] @2xl:gap-4">
              <dt className="pt-0.5 text-sm text-muted-foreground">{featureLabel(key)}</dt>
              <dd className="min-w-0 text-sm text-fg-2">
                <FeatureValue view={view} label={featureLabel(key)} align="start" />
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
    </div>
  );
}
