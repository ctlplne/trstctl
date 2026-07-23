import { expect, test, type Page } from "@playwright/test";
import { signIn, spaceSmoke } from "./helpers";

/** S-C4 visual regression: pixel baselines for the shell and one page per
 * space, dark theme (the flagship). First run writes the baselines
 * (`npx playwright test --update-snapshots`); commit them and any later diff
 * is a conscious design decision. Dynamic regions (live counts, timestamps)
 * are masked so data drift never fails a visual check. */

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
});

function dynamicRegions(page: Page) {
  return [page.locator("main [role='status']"), page.locator("main time")];
}

test("Home (dark) matches the baseline", async ({ page }) => {
  await expect(page).toHaveScreenshot("home-dark.png", { fullPage: false, mask: dynamicRegions(page) });
});

for (const { space } of spaceSmoke) {
  test(`${space} landing (dark) matches the baseline`, async ({ page }) => {
    await page
      .getByRole("navigation", { name: /spaces/i })
      .getByRole("button", { name: space })
      .click();
    await page.waitForLoadState("networkidle");
    await expect(page).toHaveScreenshot(`${space.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-dark.png`, {
      fullPage: false,
      mask: dynamicRegions(page),
    });
  });
}
