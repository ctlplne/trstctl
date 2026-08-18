import { expect, test, type ConsoleMessage, type Page, type Response, type TestInfo } from "@playwright/test";
import { appRoutePaths } from "../src/lib/navigation";
import { signIn } from "./helpers";

type RouteReceipt = {
  route: string;
  finalPath: string;
  heading: string;
  documentWidth: { client: number; scroll: number };
  mainWidth: { client: number; scroll: number };
  alerts: string[];
  apiFailures: Array<{ method: string; path: string; status: number }>;
};

const tenantRoutes = appRoutePaths.filter((path) => path !== "/login");
const viewports = [
  { name: "desktop-1440x900", width: 1440, height: 900 },
  { name: "mobile-390x844", width: 390, height: 844 },
] as const;

function sanitizedResponse(response: Response) {
  const url = new URL(response.url());
  return { method: response.request().method(), path: url.pathname, status: response.status() };
}

function expectedPath(route: string): RegExp {
  if (route === "/platform") return /^\/admin\/(?:access|system|editions)$/;
  return new RegExp(`^${route.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

async function auditRoute(page: Page, route: string): Promise<RouteReceipt> {
  const apiFailures: RouteReceipt["apiFailures"] = [];
  const onResponse = (response: Response) => {
    if (response.status() >= 400 && new URL(response.url()).pathname.startsWith("/api/")) {
      apiFailures.push(sanitizedResponse(response));
    }
  };
  page.on("response", onResponse);

  try {
    await page.goto(route, { waitUntil: "domcontentloaded" });
    const main = page.getByRole("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
    const heading = main.getByRole("heading", { level: 1 }).first();
    await expect(heading).toBeVisible({ timeout: 20_000 });
    await expect.poll(() => new URL(page.url()).pathname).toMatch(expectedPath(route));

    const widths = await page.evaluate(() => {
      const mainElement = document.querySelector("main");
      return {
        documentWidth: { client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth },
        mainWidth: { client: mainElement?.clientWidth ?? 0, scroll: mainElement?.scrollWidth ?? 0 },
      };
    });

    const alerts = (await main.getByRole("alert").allTextContents()).map((text) => text.replace(/\s+/g, " ").trim()).filter(Boolean);
    return {
      route,
      finalPath: new URL(page.url()).pathname,
      heading: (await heading.textContent())?.replace(/\s+/g, " ").trim() ?? "",
      ...widths,
      alerts,
      apiFailures,
    };
  } finally {
    page.off("response", onResponse);
  }
}

for (const viewport of viewports) {
  test(`every tenant route renders cleanly at ${viewport.name}`, async ({ page }, testInfo: TestInfo) => {
    test.setTimeout(180_000);
    await page.setViewportSize(viewport);

    const browserErrors: Array<{ route: string; kind: "console" | "page"; message: string }> = [];
    let activeRoute = "/";
    const onConsole = (message: ConsoleMessage) => {
      if (message.type() === "error") browserErrors.push({ route: activeRoute, kind: "console", message: message.text() });
    };
    page.on("console", onConsole);
    page.on("pageerror", (error) => browserErrors.push({ route: activeRoute, kind: "page", message: error.message }));

    await signIn(page);
    const receipts: RouteReceipt[] = [];
    for (const route of tenantRoutes) {
      activeRoute = route;
      receipts.push(await auditRoute(page, route));
    }

    await testInfo.attach(`live-route-receipts-${viewport.name}`, {
      body: Buffer.from(JSON.stringify(receipts, null, 2)),
      contentType: "application/json",
    });

    const serverErrors = receipts.flatMap((receipt) => receipt.apiFailures.filter((failure) => failure.status >= 500).map((failure) => ({ route: receipt.route, ...failure })));
    const documentOverflows = receipts
      .filter((receipt) => receipt.documentWidth.scroll > receipt.documentWidth.client)
      .map((receipt) => ({ route: receipt.route, ...receipt.documentWidth }));

    expect(browserErrors, "live routes must not emit browser console errors or uncaught exceptions").toEqual([]);
    expect(serverErrors, "live routes must not receive backend 5xx responses").toEqual([]);
    expect(documentOverflows, "live routes must not overflow the supported viewport").toEqual([]);
  });
}
