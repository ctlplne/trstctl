import { expect, type Page } from "@playwright/test";
import type { DemoOperatorCredentials } from "./operator-credentials";

/** Sign in through the demo's real local SSO, using its generated operator
 * fixture in the untraced setup. A pre-authenticated deployment passes through. */
export async function signIn(page: Page, credentials?: DemoOperatorCredentials): Promise<void> {
  await page.goto("/");
  const sso = page.getByRole("button", {
    name: /(?:continue|sign in) with sso/i,
  });
  // The spaces rail is intentionally hidden behind a drawer on narrow
  // viewports, so it cannot be the sign-in oracle. Home's H1 is the
  // viewport-independent proof that the authenticated shell and its first
  // route have both rendered.
  const home = page.getByRole("heading", { level: 1, name: /^home$/i });
  // Wait for whichever face this deployment shows first — the local-SSO login
  // button or (pre-authenticated) the shell itself. A fixed-length peek for
  // the button is a race under parallel workers: a slow first paint made the
  // helper skip the click and then wait for a shell that never came.
  await expect(sso.or(home).first()).toBeVisible({ timeout: 20_000 });
  if (await sso.isVisible().catch(() => false)) {
    await sso.click();
    const operatorForm = page.getByRole("heading", { level: 1, name: "Evaluation operator sign-in" });
    await expect(operatorForm.or(home).first()).toBeVisible({ timeout: 20_000 });
    if (await operatorForm.isVisible()) {
      if (!credentials) throw new Error("Demo sign-in needs TRSTCTL_E2E_OPERATOR_CREDENTIALS_FILE pointing to the private generated operator file");
      if (new URL(page.url()).origin !== "http://127.0.0.1:19081")
        throw new Error("Refusing to send demo credentials outside the configured local evaluation IdP");
      try {
        await page.getByLabel("Operator ID", { exact: true }).fill(credentials.subject);
        await page.getByLabel("Password", { exact: true }).fill(credentials.password);
        await page.getByRole("button", { name: "Sign in", exact: true }).click();
        await expect(home).toBeVisible({ timeout: 20_000 });
      } catch {
        // The untraced setup owns sign-in. Discard Playwright argument/error
        // details here so a failed fill cannot print its password in CI.
        throw new Error("Evaluation operator sign-in failed; check the private fixture and local IdP");
      } finally {
        credentials.password = "";
      }
    }
  }
  await expect(home).toBeVisible({ timeout: 20_000 });
  // Firefox reports a font request canceled by the next page.goto as a
  // console error. `fonts.ready` only covers faces this page already asked
  // for, and Home does not always paint with DM Mono. Ask for that face
  // explicitly, then finish every requested self-hosted font before the
  // caller clears sign-in diagnostics and navigates to the route under test.
  // That keeps a canceled first-load request from being blamed on that route.
  await page.evaluate(async () => {
    await document.fonts.load('400 1em "DM Mono"');
    await document.fonts.ready;
  });
}

/** The six task-first tools and, for each, the sidebar row that proves the
 * scoped sidebar rendered. Labels mirror the space registry
 * (src/lib/navigation.ts); if the carve changes, this table changes with it. */
export const spaceSmoke = [
  { space: "Discover", row: "Discover" },
  { space: "Certificates", row: "Certificates" },
  { space: "Workloads & Machines", row: "Workloads & Machines" },
  { space: "Secrets", row: "Automatic secret sources" },
  { space: "Software Trust", row: "Software Trust" },
  { space: "Operations", row: "Operations" },
] as const;
