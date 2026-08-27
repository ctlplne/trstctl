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
  exposedFrameworkLabels: string[];
  forcedUppercaseTableHeaders: string[];
  mutatingRequests: Array<{ method: string; path: string }>;
  httpFailures: Array<{
    method: string;
    path: string;
    status: number;
    problem?: { type?: string; title?: string; status?: number; detail?: string };
  }>;
};

// The signed production image deliberately omits /styleguide; it remains a
// Vite-development and component-test instrument. Live qualification must
// grade the customer routes that the candidate actually serves, rather than
// treating the intentional production redirect as a broken product route.
const tenantRoutes = appRoutePaths.filter((path) => path !== "/login" && path !== "/styleguide");
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
    // A broken or streaming error response must not hold the entire route
    // audit open forever. Preserve the status/path receipt immediately and
    // give the optional problem body a small, explicit parsing budget.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const body = (await Promise.race([
      response.json().catch(() => null),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), 2_000);
      }),
    ]).finally(() => {
      if (timer) clearTimeout(timer);
    })) as Record<string, unknown> | null;
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
  return new RegExp(`^${route.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

async function auditRoute(page: Page, route: string): Promise<RouteReceipt> {
  const httpFailures: RouteReceipt["httpFailures"] = [];
  const mutatingRequests: RouteReceipt["mutatingRequests"] = [];
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
  const onRequest = (request: import("@playwright/test").Request) => {
    const method = request.method();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      mutatingRequests.push({ method, path: new URL(request.url()).pathname });
    }
  };
  page.on("response", onResponse);
  page.on("request", onRequest);

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

    // A response event fires when headers arrive, before fetch has necessarily
    // parsed the body and before React has painted the resulting disclosure or
    // table. Under concurrent browser load the old oracle sampled the DOM here,
    // then learned about the completed 503 below, producing a false
    // "unexplained" error and occasionally grading a one-frame layout. Drain
    // the bounded receipts first, then let fonts and two animation frames settle.
    // Repeat if draining a body exposed another response in the same turn.
    for (let pass = 0; pass < 3; pass += 1) {
      const receiptCount = pendingResponseReceipts.length;
      await Promise.all(pendingResponseReceipts);
      await page.evaluate(async () => {
        await document.fonts.ready;
        await new Promise<void>((resolve) => {
          requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
        });
      });
      if (pendingResponseReceipts.length === receiptCount) break;
    }

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
        exposedFrameworkLabels: Array.from(mainElement?.querySelectorAll("span") ?? [])
          .filter((element) => ["Answer", "Operate"].includes((element.textContent ?? "").trim()))
          .filter((element) => !element.classList.contains("sr-only"))
          .map((element) => (element.textContent ?? "").trim()),
        forcedUppercaseTableHeaders: Array.from(mainElement?.querySelectorAll("table.ui-table thead th") ?? [])
          .filter((element) => getComputedStyle(element).textTransform === "uppercase")
          .map((element) => (element.textContent ?? "").replace(/\s+/g, " ").trim()),
      };
    });

    const alerts = (await main.getByRole("alert").allTextContents()).map((text) => text.replace(/\s+/g, " ").trim()).filter(Boolean);
    // Include exact error primitives even when they live inside a collapsed
    // technical-details section. They remain user-discoverable, but role-based
    // locators intentionally exclude closed <details> descendants and would
    // otherwise misclassify a precisely explained 503 as unexplained.
    const capabilityDisclosures = (await main.locator('[data-state-primitive="unavailable"], [data-state-primitive="error"]').allTextContents())
      .map((text) => text.replace(/\s+/g, " ").trim())
      .filter(Boolean);
    return {
      route,
      finalPath: new URL(page.url()).pathname,
      heading: headingText,
      ...widths,
      alerts,
      capabilityDisclosures,
      mutatingRequests,
      httpFailures,
    };
  } finally {
    page.off("response", onResponse);
    page.off("request", onRequest);
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
      expect(receipt.mutatingRequests, "opening a route must not cause an accidental mutation").toEqual([]);
      expect(receipt.exposedFrameworkLabels, "Answer / Operate are an internal hierarchy, not visible product chrome").toEqual([]);
      expect(receipt.forcedUppercaseTableHeaders, "table headers use calm sentence case, not forced uppercase").toEqual([]);
      expect(
        documentOverflow,
        `live route must not overflow the supported viewport; widest DOM sources: ${JSON.stringify(receipt.overflowSources)}`,
      ).toBeNull();
    });
  }

  test(`task search stays inside ${viewport.name} and starts with tasks`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await signIn(page);
    await page.goto("/certificates", { waitUntil: "domcontentloaded" });

    await page.getByRole("button", { name: "Open task search" }).click();
    const dialog = page.getByRole("dialog", { name: "What do you need?" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("region", { name: "Actions" })).toBeVisible();
    await expect(dialog.getByRole("region", { name: "Home" })).toHaveCount(0);

    const bounds = await dialog.boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds?.x ?? -1).toBeGreaterThanOrEqual(0);
    expect((bounds?.x ?? viewport.width) + (bounds?.width ?? 1)).toBeLessThanOrEqual(viewport.width);

    await dialog.getByRole("searchbox", { name: "Search or start a task" }).fill("license");
    await expect(dialog.getByRole("button", { name: /Plan and license/ })).toBeVisible();
  });
}
