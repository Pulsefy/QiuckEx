import { dirname } from "path";
import { fileURLToPath } from "url";
import { FlatCompat } from "@eslint/eslintrc";
import jsxA11y from "eslint-plugin-jsx-a11y";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

// Payment/QR flows carry real deployment and money-movement risk (#766), so
// a11y rules are enforced there first as CI-breaking errors. The rest of the
// app isn't covered yet — enabling jsx-a11y repo-wide under the existing
// `--max-warnings 0` gate would fail CI on unrelated pre-existing findings;
// widen this list as those get addressed.
const paymentFlowGlobs = [
  "src/app/generator/**/*.{ts,tsx}",
  "src/app/pay/**/*.{ts,tsx}",
  "src/components/payment-states/**/*.{ts,tsx}",
  "src/components/QRPreview.tsx",
  "src/components/SigningSummary.tsx",
];

const eslintConfig = [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    // next/core-web-vitals already registers the jsx-a11y plugin, so this
    // override only sets rule severities and must not redeclare `plugins`.
    files: paymentFlowGlobs,
    rules: jsxA11y.flatConfigs.recommended.rules,
  },
  {
    ignores: [
      "node_modules/**",
      ".next/**",
      "out/**",
      "build/**",
      "next-env.d.ts",
    ],
  },
];

export default eslintConfig;
