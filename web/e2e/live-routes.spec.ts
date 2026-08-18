import { expect, test, type ConsoleMessage, type Page, type Response, type TestInfo } from "@playwright/test";
import { appRoutePaths } from "../src/lib/navigation";
import { signIn } from "./helpers";

type RouteReceipt = {
  route: string;
  finalPath: string;
  heading: string;
  documentWidth: { client: number; scroll: number };
  mainWidth: { client: number; scroll: number };
  overflowSources: Array<{
    tag: string;
    className: string;
    role: string;
    text: string;
    left: number;
    right: number;
    width: number;
  }>;
  alerts: string[];
  capabilityDisclosures: string[];
  httpFailures: Array<{
    method: string;
    path: string;
    status: number;
    problem?: { type?: string; title?: string; status?: number; detail?: string };
  }>;
};

const tenantRoutes = appRoutePaths.filter((path) => path !== "/login");
const viewports = [
  { name: "desktop-1440x900", width: 1440, height: 900 },
  { name: "mobile-390x844", width: 390, height: 844 },
] as const;

async function sanitizedResponse(response: Response): Promise<RouteReceipt["httpFailures"][number]> {
  const url = new URL(response.url());
  const receipt: RouteReceipt["httpFailures"][number] = {
    method: response.request().method(),
    path: url.pathname,
    status: response.status(),
  };
  if (response.headers()["content-type"]?.includes("application/problem+json")) {
    const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    if (body) {
      receipt.problem = {
        type: typeof body.type === "string" ? body.type : undefined,
        title: typeof body.title === "string" ? body.title : undefined,
        status: typeof body.status === "number" ? body.status : undefined,
        detail: typeof body.detail === "string" ? body.detail : undefined,
      };
    }
  }
  return receipt;
}

function expectedPath(route: string): RegExp {
  if (route === "/platform") return /^\/admin\/(?:access|system|editions)$/;
  return new RegExp(`^${route.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

async function auditRoute(page: Page, route: string): Promise<RouteReceipt> {
  const httpFailures: RouteReceipt["httpFailures"] = [];
  const pendingResponseReceipts: Array<Promise<void>> = [];
  const onResponse = (response: Response) => {
    if (response.status() >= 400) {
      pendingResponseReceipts.push(
        sanitizedResponse(response).then((receipt) => {
          httpFailures.push(receipt);
        }),
      );
    }
  };
  page.on("response", onResponse);

  try {
    await page.goto(route, { waitUntil: "domcontentloaded" });
    const main = page.getByRole("main");
    await expect(main).toBeVisible({ timeout: 20_000 });
    const heading = main.getByRole("heading", { level: 1 }).first();
    await expect(heading).toBeVisible({ timeout: 20_000 });
    const headingText = (await heading.innerText()).replace(/\s+/g, " ").trim();
    await expect.poll(() => new URL(page.url()).pathname).toMatch(expectedPath(route));
    // The heading is deliberately allowed to render before its API calls
    // finish. Wait for the route to become quiet before grading its network
    // and layout receipts so a late 5xx or late table cannot escape the audit.
    await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => undefined);

    const widths = await page.evaluate(() => {
      const mainElement = document.querySelector("main");
      const viewportWidth = document.documentElement.clientWidth;
      const overflowSources = Array.from(document.querySelectorAll("body *"))
        .map((element) => {
          const rect = element.getBoundingClientRect();
          const text = (element.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 160);
          return {
            tag: element.tagName.toLowerCase(),
            className: (element.getAttribute("class") ?? "").slice(0, 240),
            role: element.getAttribute("role") ?? "",
            text,
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          };
        })
        .filter((element) => element.width > 0 && (element.left < -1 || element.right > viewportWidth + 1))
        .sort((a, b) => Math.max(b.right - viewportWidth, -b.left) - Math.max(a.right - viewportWidth, -a.left))
        .slice(0, 12);
      return {
        documentWidth: { client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth },
        mainWidth: { client: mainElement?.clientWidth ?? 0, scroll: mainElement?.scrollWidth ?? 0 },
        overflowSources,
      };
    });

    const alerts = (await main.getByRole("alert").allTextContents()).map((text) => text.replace(/\s+/g, " ").trim()).filter(Boolean);
    const capabilityDisclosures = (await main.locator('[data-state-primitive="unavailable"]').allTextContents())
      .map((text) => text.replace(/\s+/g, " ").trim())
      .filter(Boolean);
    await Promise.all(pendingResponseReceipts);
    return {
      route,
      finalPath: new URL(page.url()).pathname,
      heading: headingText,
      ...widths,
      alerts,
      capabilityDisclosures,
      httpFailures,
    };
  } finally {
    page.off("response", onResponse);
  }
}

for (const viewport of viewports) {
  for (const route of tenantRoutes) {
    test(`${route} renders cleanly at ${viewport.name}`, async ({ page }, testInfo: TestInfo) => {
      test.setTimeout(45_000);
      await page.setViewportSize(viewport);

      const browserErrors: Array<{ kind: "console" | "page"; message: string }> = [];
      const onConsole = (message: ConsoleMessage) => {
        // Chromium turns every HTTP 4xx/5xx into this URL-less console line.
        // auditRoute records the actual method, path, and status from the
        // response event, so keeping the generic duplicate would make an
        // intentional 404 capability disclosure indistinguishable from a
        // JavaScript exception.
        if (message.type() === "error" && !message.text().startsWith("Failed to load resource: the server responded with a status of")) {
          browserErrors.push({ kind: "console", message: message.text() });
        }
      };
      page.on("console", onConsole);
      page.on("pageerror", (error) => browserErrors.push({ kind: "page", message: error.message }));

      await signIn(page);
      // The sign-in journey has its own browser test. Route receipts begin
      // after authentication so an IdP diagnostic cannot be misattributed to
      // the product page under test.
      browserErrors.length = 0;
      const receipt = await auditRoute(page, route);
      await testInfo.attach(`live-route-receipt-${viewport.name}`, {
        body: Buffer.from(JSON.stringify(receipt, null, 2)),
        contentType: "application/json",
      });

      const explainedUnavailable = (failure: RouteReceipt["httpFailures"][number]) =>
        failure.status === 503 &&
        failure.problem?.title === "Service Unavailable" &&
        failure.problem.status === 503 &&
        Boolean(failure.problem.detail) &&
        [...receipt.alerts, ...receipt.capabilityDisclosures].some((disclosure) => disclosure.includes(failure.problem?.detail ?? ""));
      const serverErrors = receipt.httpFailures.filter((failure) => failure.status >= 500 && !explainedUnavailable(failure));
      const documentOverflow = receipt.documentWidth.scroll > receipt.documentWidth.client ? receipt.documentWidth : null;

      expect(browserErrors, "live route must not emit browser console errors or uncaught exceptions").toEqual([]);
      expect(serverErrors, "live route must not receive unexplained backend 5xx responses").toEqual([]);
      expect(
        documentOverflow,
        `live route must not overflow the supported viewport; widest DOM sources: ${JSON.stringify(receipt.overflowSources)}`,
      ).toBeNull();
    });
  }
}
