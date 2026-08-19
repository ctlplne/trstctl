import { expect, test, type Page } from "@playwright/test";
import { signIn, spaceSmoke } from "./helpers";

test.skip(process.env.TRSTCTL_VISUAL_E2E !== "1", "pixel baselines are an explicit opt-in review surface");
test.skip(({ browserName }) => browserName !== "chromium", "pixel baselines are recorded and reviewed in Chromium only");

/** S-C4 visual regression: pixel baselines for the shell and one page per
 * space in the calm light default, plus an explicit dark-theme Home proof.
 * Baselines are local-only and untracked:
 * `npm run e2e -- --update-snapshots` records them for THIS machine and a later
 * diff is a conscious design decision. Nothing is committed, because Playwright
 * keys each file to the recording platform and CI runs only on ubuntu-latest.
 * Dynamic regions (live counts, timestamps)
 * are masked so data drift never fails a visual check. */

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
});

function dynamicRegions(page: Page) {
  return [page.locator("main [role='status']"), page.locator("main time")];
}

test("Home (light default) matches the baseline", async ({ page }) => {
  await expect(page.getByRole("button", { name: "Theme: Light. Switch to Dark." })).toBeVisible();
  await expect(page).toHaveScreenshot("home-light.png", { fullPage: false, mask: dynamicRegions(page) });
});

test("Home (dark optional) matches the baseline", async ({ page }) => {
  await page.getByRole("button", { name: "Theme: Light. Switch to Dark." }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await expect(page).toHaveScreenshot("home-dark.png", { fullPage: false, mask: dynamicRegions(page) });
});

for (const { space } of spaceSmoke) {
  test(`${space} landing (dark) matches the baseline`, async ({ page }) => {
    await page
      .getByRole("navigation", { name: /spaces/i })
      .getByRole("button", { name: space })
      .click();
    await page.waitForLoadState("networkidle");
    await expect(page).toHaveScreenshot(`${space.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-light.png`, {
      fullPage: false,
      mask: dynamicRegions(page),
    });
  });
}
