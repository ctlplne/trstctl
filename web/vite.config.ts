/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const webRoot = __dirname;
const repoRoot = path.resolve(webRoot, "..");
const webModules = path.resolve(webRoot, "node_modules");
const webDependencyAliases = {
  "@testing-library/jest-dom": path.resolve(webModules, "@testing-library/jest-dom"),
  "@testing-library/react": path.resolve(webModules, "@testing-library/react"),
  "@testing-library/user-event": path.resolve(webModules, "@testing-library/user-event"),
  "@vitest/coverage-v8": path.resolve(webModules, "@vitest/coverage-v8"),
  "class-variance-authority": path.resolve(webModules, "class-variance-authority"),
  clsx: path.resolve(webModules, "clsx"),
  "lucide-react": path.resolve(webModules, "lucide-react"),
  react: path.resolve(webModules, "react"),
  "react-dom": path.resolve(webModules, "react-dom"),
  "react/jsx-dev-runtime": path.resolve(webModules, "react/jsx-dev-runtime.js"),
  "react/jsx-runtime": path.resolve(webModules, "react/jsx-runtime.js"),
  "react-router-dom": path.resolve(webModules, "react-router-dom"),
  "tailwind-merge": path.resolve(webModules, "tailwind-merge"),
  vitest: path.resolve(webModules, "vitest"),
  "vitest-axe": path.resolve(webModules, "vitest-axe"),
};

// The production build is emitted into internal/webui/dist so the Go binary can
// embed it (//go:embed). During dev, /api and /auth are proxied to the control
// plane on :8080.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(webRoot, "src") } },
  build: {
    outDir: path.resolve(webRoot, "../internal/webui/dist"),
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // Route splitting otherwise emits one sub-kilobyte file per shared
        // Lucide glyph. Group only the tree-shaken glyph modules so those
        // files share one wrapper and compression dictionary.
        codeSplitting: {
          groups: [
            {
              name: "icons",
              test: /node_modules[\\/]lucide-react[\\/]/,
              priority: 2,
            },
            {
              name: "route-support",
              // Keep small route helpers lazy, but compress them as one shared
              // support asset instead of fourteen separately wrapped files.
              test: (id) =>
                [
                  "/src/components/IdentityPicker.tsx",
                  "/src/components/ScrollableTableRegion.tsx",
                  "/src/components/dashboard/index.tsx",
                  "/src/components/ui/checkbox.tsx",
                  "/src/components/ui/field.tsx",
                  "/src/components/ui/input.tsx",
                  "/src/components/ui/select.tsx",
                  "/src/components/ui/textarea.tsx",
                  "/src/lib/agentInstall.ts",
                  "/src/lib/apiProblem.ts",
                  "/src/lib/approvalQueue.ts",
                  "/src/lib/effectiveOwnership.ts",
                  "/src/lib/onboardingState.ts",
                  "/src/lib/optionalApi.ts",
                ].some((modulePath) => id.includes(modulePath)),
              includeDependenciesRecursively: false,
              priority: 1,
            },
          ],
        },
      },
    },
    // Pages remain lazy chunks. English is the only production catalog.
    // `npm run size` enforces the package.json Brotli ceilings for all shipped
    // JavaScript and the complete entry graph, including shared imports.
    // This raw-size warning is an additional signal, not the startup budget.
    chunkSizeWarningLimit: 1300,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/auth": "http://localhost:8080",
    },
  },
  test: {
    root: repoRoot,
    include: ["web/src/**/*.{test,spec}.{ts,tsx,js,jsx,mts,mtsx,mjs}"],
    environment: "jsdom",
    globals: true,
    // This suite is DOM-heavy: every worker owns a complete jsdom + React
    // graph and many files run axe. On the supported audit host, Vitest's
    // CPU-sized default produced 76 false failures, mostly five-second
    // timeouts; the same 156 files passed 670/670 with one worker. Keep the
    // release gate inside that measured memory/CPU envelope. CI can shard the
    // command across jobs later, but each shard must retain this bound.
    maxWorkers: 1,
    setupFiles: [path.resolve(webRoot, "src/test/setup.ts")],
    css: false,
    // The audit harness invokes npm --prefix web with web/src/... file filters.
    // Run Vitest from repo root for those filters, while resolving packages from
    // the web workspace where package.json and node_modules live.
    alias: webDependencyAliases,
    deps: {
      moduleDirectories: [path.resolve(webRoot, "node_modules"), "node_modules"],
    },
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      reportsDirectory: path.resolve(webRoot, "coverage"),
      include: ["web/src/**/*.{ts,tsx}", "web/scripts/gen-api-types.mjs"],
      exclude: [
        "web/src/**/*.gen.ts",
        // Vitest 4 passes `exclude` directly to picomatch's ignore list.
        // A negated ignore pattern excludes every non-matching file, so the
        // former `!security_sinks` re-include silently produced 0/0 coverage.
        // Express the exception positively: exclude all ordinary test/spec
        // files while retaining security_sinks.test.ts as measured code.
        "web/src/**/!(*security_sinks).{test,spec}.{ts,tsx}",
        "web/src/**/*.stories.tsx",
        "web/src/main.tsx",
        "web/src/vite-env.d.ts",
        "web/src/test/**",
      ],
      thresholds: {
        lines: 75,
        statements: 75,
        functions: 65,
        branches: 70,
        "web/src/lib/api.ts": {
          lines: 80,
          statements: 80,
          functions: 40,
          branches: 75,
        },
        "web/scripts/gen-api-types.mjs": {
          lines: 70,
          statements: 70,
          functions: 65,
          branches: 60,
        },
        "web/src/auth/AuthProvider.tsx": {
          lines: 80,
          statements: 80,
          functions: 60,
          branches: 70,
        },
        "web/src/components/AppShell.tsx": {
          lines: 95,
          statements: 95,
          functions: 95,
          branches: 95,
        },
        "web/src/pages/Identities.tsx": {
          lines: 90,
          statements: 90,
          functions: 90,
          branches: 70,
        },
        "web/src/__tests__/security_sinks.test.ts": {
          lines: 75,
          statements: 75,
          functions: 95,
          branches: 60,
        },
      },
    },
  },
});
