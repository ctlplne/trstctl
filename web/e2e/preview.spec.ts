import { expect, test, type Page } from "@playwright/test";

const previewRoutes = [
  { path: "/", heading: "Dashboard", proof: "api.preview-lab.example" },
  { path: "/certificates", heading: "Certificates", proof: "api.preview-lab.example" },
  { path: "/posture", heading: "Crypto posture", proof: "*.payments.preview-lab.example" },
  { path: "/risk", heading: "Credential risk", proof: "api.preview-lab.example" },
  { path: "/secrets", heading: "Secrets", proof: "payments/production/database" },
  { path: "/ssh", heading: "SSH trust", proof: "bastion.preview-lab.example" },
  { path: "/incidents", heading: "Incidents", proof: "incident-preview-001" },
  { path: "/ca-hierarchy", heading: "CA hierarchy", proof: "Preview Lab Root CA" },
] as const;

async function assertPreviewRoutes(page: Page, theme: "light" | "dark") {
  const escapedRequests: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/") || path.startsWith("/auth/")) escapedRequests.push(`${request.method()} ${path}`);
  });

  await page.addInitScript((selectedTheme) => {
    localStorage.setItem("trstctl-theme", selectedTheme);
  }, theme);

  for (const route of previewRoutes) {
    await page.goto(route.path);
    await expect(page.getByTestId("preview-read-only-banner")).toContainText("Changes are disabled and nothing leaves this browser");
    await expect(page.getByRole("heading", { level: 1, name: route.heading })).toBeVisible();
    await expect(page.getByText(route.proof, { exact: false }).first()).toBeVisible();
    if (theme === "dark") await expect(page.locator("html")).toHaveClass(/dark/);
    else await expect(page.locator("html")).not.toHaveClass(/dark/);

    const viewport = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      innerWidth: window.innerWidth,
      mainClientWidth: document.querySelector("main")?.clientWidth ?? 0,
      mainScrollWidth: document.querySelector("main")?.scrollWidth ?? 0,
    }));
    expect(viewport.clientWidth).toBe(viewport.innerWidth);
    expect(viewport.mainScrollWidth).toBeLessThanOrEqual(viewport.mainClientWidth);
  }

  await page.goto("/secrets");
  const createSecret = page.getByRole("form", { name: "Create secret" });
  await createSecret.getByLabel("Secret name").fill("blocked/preview/write");
  await createSecret.getByLabel("Secret value").fill("never leaves the browser");
  await createSecret.getByRole("button", { name: "Create secret" }).click();
  await expect(page.getByRole("alert")).toContainText("Preview uses sample data in this browser demo");

  expect(escapedRequests).toEqual([]);
}

test("desktop dark preview renders every evaluation route without tenant traffic", async ({ page }) => {
  test.setTimeout(60_000);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ colorScheme: "dark" });
  await assertPreviewRoutes(page, "dark");
});

test("mobile light preview renders every evaluation route without tenant traffic", async ({ page }) => {
  test.setTimeout(60_000);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "light" });
  await assertPreviewRoutes(page, "light");
});
