import { expect, type Page } from "@playwright/test";

/** Sign in through the demo stack's local SSO (one click; the sidecar
 * authenticates automatically) and wait for the shell to be interactive. A
 * pre-authenticated deployment passes straight through. */
export async function signIn(page: Page): Promise<void> {
  await page.goto("/");
  const sso = page.getByRole("button", { name: /sign in with sso/i });
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

/** The five spaces and, for each, the sidebar row that proves the scoped
 * sidebar rendered. Labels mirror the space registry (src/lib/navigation.ts);
 * if the carve changes, this table changes with it. */
export const spaceSmoke = [
  { space: "Certificates & PKI", row: "Certificate authorities" },
  { space: "Secrets", row: "Machine access" },
  { space: "Workload & SSH", row: "SSH trust" },
  { space: "Posture & response", row: "Credential graph" },
  { space: "Platform", row: "Audit" },
] as const;
