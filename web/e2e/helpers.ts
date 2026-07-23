import { expect, type Page } from "@playwright/test";

/** Sign in through the demo stack's local SSO (one click; the sidecar
 * authenticates automatically) and wait for the shell to be interactive. A
 * pre-authenticated deployment passes straight through. */
export async function signIn(page: Page): Promise<void> {
  await page.goto("/");
  const sso = page.getByRole("button", { name: /sign in with sso/i });
  if (await sso.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await sso.click();
  }
  await expect(page.getByRole("navigation", { name: /spaces/i })).toBeVisible({ timeout: 20_000 });
}

/** The five spaces and, for each, the sidebar row that proves the scoped
 * sidebar rendered. Labels mirror the space registry (src/lib/navigation.ts);
 * if the carve changes, this table changes with it. */
export const spaceSmoke = [
  { space: "Certificates & PKI", row: "CA hierarchy" },
  { space: "Secrets", row: "Machine access" },
  { space: "Workload & SSH", row: "SSH trust" },
  { space: "Posture & response", row: "Credential graph" },
  { space: "Platform", row: "Audit" },
] as const;
