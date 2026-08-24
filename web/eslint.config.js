import js from "@eslint/js";
import importPlugin from "eslint-plugin-import";
import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "coverage/**",
      "dist/**",
      ".storybook-static/**",
      "node_modules/**",
      ".vite/**",
      "vite.config.ts.timestamp-*.mjs",
      "src/i18n/extractedMessages.gen.ts",
      "src/lib/api-types.gen.ts",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  {
    settings: {
      react: { version: "detect" },
      "import/resolver": {
        typescript: { project: "./tsconfig.json" },
        node: { extensions: [".js", ".jsx", ".ts", ".tsx"] },
      },
    },
  },
  react.configs.flat.recommended,
  react.configs.flat["jsx-runtime"],
  reactHooks.configs.flat.recommended,
  jsxA11y.flatConfigs.recommended,
  {
    files: ["**/*.{js,mjs,ts,tsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.vitest,
      },
    },
    rules: {
      "import/no-duplicates": "error",
      "import/no-unresolved": "error",
      "import/no-named-as-default-member": "off",
      "react-hooks/exhaustive-deps": "error",
      "react-hooks/set-state-in-effect": "off",
      "react/prop-types": "off",
      "react/jsx-no-target-blank": ["error", { allowReferrer: false }],
      "react/no-unescaped-entities": "off",
    },
  },
  // WEB-APIPROBLEM-001 (AH-bc10425e): one error renderer. Eight page-local
  // copies of apiProblemMessage had drifted apart - Approvals and Identities
  // had lost the 429 Retry-After branch entirely - so the same rate-limited
  // response rendered differently depending on which page served it. Import
  // apiProblemMessage/apiProblemContext from @/lib/apiProblem instead; the
  // paired vitest guard is src/lib/apiProblem.test.ts.
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/lib/apiProblem.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "FunctionDeclaration[id.name=/^apiProblem(Message|Context)$/]",
          message:
            "Import apiProblemMessage/apiProblemContext from @/lib/apiProblem (WEB-APIPROBLEM-001): a page-local copy is how the 429 retry hint got lost.",
        },
        {
          selector: "VariableDeclarator[id.name=/^apiProblem(Message|Context)$/]",
          message:
            "Import apiProblemMessage/apiProblemContext from @/lib/apiProblem (WEB-APIPROBLEM-001): a page-local copy is how the 429 retry hint got lost.",
        },
      ],
    },
  },
);
