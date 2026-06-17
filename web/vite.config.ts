/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// The production build is emitted into internal/webui/dist so the Go binary can
// embed it (//go:embed). During dev, /api and /auth are proxied to the control
// plane on :8080.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  build: {
    outDir: path.resolve(__dirname, "../internal/webui/dist"),
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/auth": "http://localhost:8080",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      reportsDirectory: "./coverage",
      include: ["src/**/*.{ts,tsx}", "scripts/gen-api-types.mjs"],
      exclude: [
        "src/**/*.gen.ts",
        "src/**/*.test.{ts,tsx}",
        "src/main.tsx",
        "src/vite-env.d.ts",
        "src/test/**",
        "src/__tests__/**",
        "!src/__tests__/security_sinks.test.ts",
      ],
      thresholds: {
        lines: 75,
        statements: 75,
        functions: 65,
        branches: 70,
        "src/lib/api.ts": {
          lines: 80,
          statements: 80,
          functions: 40,
          branches: 75,
        },
        "scripts/gen-api-types.mjs": {
          lines: 70,
          statements: 70,
          functions: 65,
          branches: 60,
        },
        "src/auth/AuthProvider.tsx": {
          lines: 80,
          statements: 80,
          functions: 60,
          branches: 70,
        },
        "src/components/AppShell.tsx": {
          lines: 95,
          statements: 95,
          functions: 95,
          branches: 95,
        },
        "src/pages/Identities.tsx": {
          lines: 90,
          statements: 90,
          functions: 90,
          branches: 70,
        },
        "src/__tests__/security_sinks.test.ts": {
          lines: 75,
          statements: 75,
          functions: 95,
          branches: 60,
        },
      },
    },
  },
});
