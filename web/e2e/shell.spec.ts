import { expect, test } from "@playwright/test";
import { signIn, spaceSmoke } from "./helpers";

/** S-C4 shell smoke: the unified shell works in a real browser — rail
 * switching, scoped sidebars, the command palette, and the Secrets
 * legacy-redirect. Behavior depth lives in Vitest; this proves the shipped
 * bundle against a served backend. */

test.beforeEach(async ({ page }) => {
  await signIn(page);
});

test("Home shows the worklists and the rail lists every space", async ({ page }) => {
  const rail = page.getByRole("navigation", { name: /spaces/i });
  await expect(rail.getByRole("button", { name: "Home" })).toHaveAttribute("aria-current", "true");
  for (const { space } of spaceSmoke) {
    await expect(rail.getByRole("button", { name: space })).toBeVisible();
  }
  await expect(page.getByRole("navigation", { name: /primary/i }).getByRole("link", { name: /guided setup/i })).toBeVisible();
});

test("mobile shell groups account and preferences into one menu", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const account = page.getByRole("button", { name: "Account and preferences" });
  await expect(account).toBeVisible();
  await account.click();

  const menu = page.getByRole("dialog", { name: "Account and preferences" });
  await expect(menu).toBeVisible();
  await expect(menu).toContainText("demo-admin@trstctl.local");
  await expect(menu.getByRole("combobox", { name: "Language" })).toBeVisible();
  await expect(menu.getByRole("button", { name: /Theme:/ })).toBeVisible();
  await expect(menu.getByRole("button", { name: "Open keyboard shortcuts" })).toBeVisible();
  await expect(menu.getByRole("button", { name: "Sign out" })).toBeVisible();
});

test("mobile first-run shows only the current step and its nearest context", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/wizard");

  await expect(page.getByRole("heading", { level: 1, name: "Set up trstctl" })).toBeVisible();
  await expect(page).toHaveTitle(/^Set up trstctl · trstctl$/);
  await expect(page.getByTestId("full-step-progress")).toBeHidden();
  const compact = page.getByTestId("compact-step-progress");
  await expect(compact).toBeVisible();
  await expect(compact.getByRole("listitem")).toHaveCount(2);
  await expect(compact).toContainText("Connect issuer");
  await expect(compact).toContainText("Enable protocols");
  await expect(compact).not.toContainText("Complete");
});

for (const { space, row } of spaceSmoke) {
  test(`rail switch into ${space} scopes the sidebar`, async ({ page }) => {
    const rail = page.getByRole("navigation", { name: /spaces/i });
    await rail.getByRole("button", { name: space }).click();
    await expect(rail.getByRole("button", { name: space })).toHaveAttribute("aria-current", "true");
    await expect(page.getByRole("navigation", { name: /primary/i }).getByRole("link", { name: new RegExp(row, "i") })).toBeVisible();
  });
}

test("command palette opens, groups by space, and jumps", async ({ page }) => {
  await page.keyboard.press(process.platform === "darwin" ? "Meta+k" : "Control+k");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("searchbox").fill("ssh trust");
  await dialog
    .getByRole("button", { name: /ssh trust/i })
    .first()
    .click();
  await expect(page).toHaveURL(/\/ssh$/);
  await expect(page.getByRole("heading", { level: 1, name: /ssh trust/i })).toBeVisible();
});

test("legacy /secrets?tab= deep links redirect to the workspace routes", async ({ page }) => {
  await page.goto("/secrets?tab=engines");
  await expect(page).toHaveURL(/\/secrets\/engines$/);
  await expect(page.getByRole("heading", { level: 1, name: /secret engines/i })).toBeVisible();
});
