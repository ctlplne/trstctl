import { defineConfig, devices } from "@playwright/test";

/** S-C4: browser end-to-end + visual regression for the console shell.
 *
 * Targets a RUNNING trstctl — by default the seeded demo compose stack
 * (deploy/demo/docker-compose.yml, self-signed TLS on :9443, local SSO signs
 * in automatically). Point TRSTCTL_E2E_URL elsewhere to run against another
 * deployment. One-time browser setup: `npm run e2e:install`; then
 * `npm run e2e`. Visual baselines are local-only and untracked: record them for
 * the machine you are on with `npm run e2e -- --update-snapshots`, read the diff
 * in review, and do not commit them — Playwright keys each file to the recording
 * platform and the one CI job that runs this suite is ubuntu-latest.
 *
 * These tests are additive to the 140+-file Vitest suite: Vitest owns
 * behavior; Playwright owns real-browser smoke (navigation, focus, rendering)
 * and pixels. Keep specs shallow — deep flows belong in Vitest where the API
 * seam is mockable. */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 30_000,
  expect: {
    // Font rasterization differs slightly across GPUs; a small ratio keeps
    // baselines stable without hiding real regressions.
    toHaveScreenshot: { maxDiffPixelRatio: 0.02, animations: "disabled" },
  },
  use: {
    baseURL: process.env.TRSTCTL_E2E_URL ?? "https://localhost:9443",
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
