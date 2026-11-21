/**
 * Compile-time drift check between the console's zod schemas and the analyst API's
 * published OpenAPI document (docs/api/openapi.json → `pnpm gen:api` → openapi.d.ts).
 *
 * Each line asserts that a response typed by the OpenAPI document is accepted by the
 * corresponding zod schema's input type. If D1 removes or retypes a field the console
 * relies on, `pnpm typecheck` fails here instead of the page failing at runtime.
 * Nothing in this file is executed or bundled.
 */
import type { z } from "zod";

import type { components } from "./openapi";
import type * as S from "./schemas";

type Api = components["schemas"];

/** Resolves only when `From` is assignable to `To`. */
type Accepts<To, From extends To> = From;

export type ContractChecks = [
  Accepts<z.input<typeof S.zOverviewResponse>, Api["OverviewResponse"]>,
  Accepts<z.input<typeof S.zAssetListResponse>, Api["AssetListResponse"]>,
  Accepts<z.input<typeof S.zAssetDetailResponse>, Api["AssetDetailResponse"]>,
  Accepts<z.input<typeof S.zFindingListResponse>, Api["FindingListResponse"]>,
  Accepts<z.input<typeof S.zRuleListResponse>, Api["RuleListResponse"]>,
  Accepts<z.input<typeof S.zAlertListResponse>, Api["AlertListResponse"]>,
  Accepts<z.input<typeof S.zAlertDetailResponse>, Api["AlertDetailResponse"]>,
  Accepts<z.input<typeof S.zAlertStateResponse>, Api["AlertStateResponse"]>,
  Accepts<z.input<typeof S.zContextResponse>, Api["ContextResponse"]>,
  Accepts<z.input<typeof S.zAssessmentListResponse>, Api["AssessmentListResponse"]>,
  Accepts<z.input<typeof S.zSummaryResponse>, Api["SummaryResponse"]>,
  Accepts<z.input<typeof S.zEventListResponse>, Api["EventListResponse"]>,
  Accepts<z.input<typeof S.zEventDetailResponse>, Api["EventDetailResponse"]>,
  Accepts<z.input<typeof S.zHealthResponse>, Api["HealthResponse"]>,
  Accepts<z.input<typeof S.zTimeSeriesResponse>, Api["TimeSeriesResponse"]>,
];
