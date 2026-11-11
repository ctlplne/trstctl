import { expect, test, type Page } from "@playwright/test";
import { appRoutePaths } from "../src/lib/navigation";

// MSP-1: on a white-labeled tenant "Powered by trstctl" is visible on the
// sign-in page and every console route, in both themes: in view without
// scrolling, at least the minimum size, and at least 4.5:1 contrast against
// its own background. The preview tenant's brand carries hostile token
// overrides that blank the page's colors and text sizes, so the mark must hold
// up on its own fixed styling.
const previewBaseURL = process.env.TRSTCTL_PREVIEW_E2E_URL;
test.skip(!previewBaseURL, "requires a bundle compiled with VITE_TRSTCTL_DEMO=1; production and local-SSO stacks are not preview mode");

function channel(value: number): number {
  const v = value / 255;
  return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

function luminance(rgb: string): number {
  const parts = rgb.match(/\d+(\.\d+)?/g)?.map(Number) ?? [];
  if (parts.length < 3) throw new Error(`not an rgb color: ${rgb}`);
  return 0.2126 * channel(parts[0]) + 0.7152 * channel(parts[1]) + 0.0722 * channel(parts[2]);
}

async function assertMark(page: Page, route: string, theme: string): Promise<void> {
  const where = `${route} (${theme})`;
  const mark = page.getByTestId("powered-by-trstctl").first();
  await expect(mark, where).toBeVisible({ timeout: 15_000 });
  await expect(mark, where).toHaveText("Powered by trstctl");
  const box = await mark.boundingBox();
  const viewport = page.viewportSize();
  expect(box, where).not.toBeNull();
  expect(viewport, where).not.toBeNull();
  if (!box || !viewport) return;
  expect(box.y, `${where}: above the top`).toBeGreaterThanOrEqual(0);
  expect(box.x, `${where}: left of the page`).toBeGreaterThanOrEqual(0);
  expect(box.y + box.height, `${where}: below the fold`).toBeLessThanOrEqual(viewport.height);
  expect(box.x + box.width, `${where}: right of the page`).toBeLessThanOrEqual(viewport.width);
  expect(box.height, `${where}: too small`).toBeGreaterThanOrEqual(20);
  const style = await mark.evaluate((el) => {
    const cs = getComputedStyle(el);
    return { color: cs.color, background: cs.backgroundColor, fontSize: parseFloat(cs.fontSize), opacity: cs.opacity, visibility: cs.visibility };
  });
  expect(style.fontSize, `${where}: font size`).toBeGreaterThanOrEqual(12);
  expect(style.opacity, where).toBe("1");
  expect(style.visibility, where).toBe("visible");
  const [light, dark] = [luminance(style.color), luminance(style.background)].sort((a, b) => b - a);
  expect((light + 0.05) / (dark + 0.05), `${where}: contrast`).toBeGreaterThanOrEqual(4.5);
}

for (const theme of ["light", "dark"] as const) {
  test(`a white-labeled tenant shows Powered by trstctl on the sign-in page and every route (${theme})`, async ({ page }) => {
    test.setTimeout(240_000);
    await page.addInitScript((selectedTheme) => {
      localStorage.setItem("trstctl-theme", selectedTheme);
    }, theme);
    for (const route of appRoutePaths) {
      const url = new URL(route, previewBaseURL);
      url.searchParams.set("preview_brand", "msp");
      await page.goto(url.href);
      await assertMark(page, route, theme);
    }
  });
}
