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
  },
});
