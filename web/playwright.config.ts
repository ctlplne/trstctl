import { defineConfig, devices } from "@playwright/test";

/** S-C4: browser end-to-end + visual regression for the console shell.
 *
 * Targets a RUNNING trstctl — by default the seeded demo compose stack
 * (deploy/demo/docker-compose.yml, self-signed TLS on 127.0.0.1:9443, local SSO
 * signs in automatically). The host must match the demo OIDC callback exactly
 * so the host-scoped pre-login cookie survives the redirect. Point
 * TRSTCTL_E2E_URL elsewhere to run against another
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
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
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
    baseURL: process.env.TRSTCTL_E2E_URL ?? "https://127.0.0.1:9443",
    ignoreHTTPSErrors: true,
    // Authenticate once through the real demo IdP, then give each isolated
    // context the same encrypted session cookie. Re-authenticating 285 tests
    // would test the public-login abuse guard rather than the product routes.
    storageState: "test-results/.auth/demo-user.json",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 900 } } },
    { name: "webkit", use: { ...devices["Desktop Safari"], viewport: { width: 1440, height: 900 } } },
  ],
});
