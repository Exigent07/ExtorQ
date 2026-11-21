import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

/**
 * Lint policy for the ExtorQ console. Besides the Next.js presets, the rules below
 * enforce the console's security invariants mechanically (frontend/AGENTS.md):
 * - no raw-HTML sink (`dangerouslySetInnerHTML`): all telemetry renders as text;
 * - no `NEXT_PUBLIC_*` variables: nothing configured on the server reaches the browser;
 * - no dynamic code evaluation.
 */
const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      "react/no-danger": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Raw HTML is banned: render telemetry as text (UntrustedText).",
        },
        {
          selector: "MemberExpression[property.name=/^NEXT_PUBLIC_/]",
          message: "Public build-time variables (NEXT_PUBLIC_ prefix) are banned: configuration stays server-side.",
        },
        {
          selector: "Literal[value=/^NEXT_PUBLIC_/]",
          message: "Public build-time variables (NEXT_PUBLIC_ prefix) are banned: configuration stays server-side.",
        },
      ],
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" },
      ],
    },
  },
  {
    // Node scripts (smoke test, test runner) run outside the bundle.
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: { process: "readonly", console: "readonly", URL: "readonly" } },
  },
  globalIgnores([".next/**", "out/**", "build/**", "next-env.d.ts", "src/lib/api/openapi.d.ts"]),
]);

export default eslintConfig;
