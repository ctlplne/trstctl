import { expect, test } from "@playwright/test";
import { signIn } from "./helpers";

// Deterministic, populated browser layout fixture. This proves rendering, not
// connector execution; qualification separately replays real installed evidence.
const fingerprint = "ab".repeat(32);
const certificate = {
  id: "drawer-history-leaf",
  tenant_id: "drawer-layout-tenant",
  subject: "CN=historical-database.example.test",
  issuer: "CN=Private certificate authority for historical workload evidence",
  sans: ["historical-database.example.test"],
  fingerprint,
  serial: "1234567890abcdef".repeat(3),
  key_algorithm: "ECDSA P-256",
  status: "superseded",
  identity_ids: ["drawer-history-identity"],
  not_before: "2026-08-20T10:00:00Z",
  not_after: "2026-08-21T10:00:00Z",
  key_origin: "agent",
  custody_summary: "The private key was generated on the agent and never entered the control plane.",
  source: "managed",
  deployment_location: "database.example.test:5432",
};
const delivery = {
  id: "drawer-delivery",
  tenant_id: certificate.tenant_id,
  identity_id: certificate.identity_ids[0],
  destination: "connector.deploy",
  connector: "postgresql",
  target: "historical-database.example.test:5432",
  fingerprint,
  status: "delivered",
  attempts: 4,
  outbox_id: 42,
  idempotency_key: "drawer-historical-renewal",
  detail: "The target independently served the exact historical certificate after reload.",
  created_at: "2026-08-20T10:00:00Z",
  updated_at: "2026-08-20T10:00:01Z",
};
const rotation = {
  id: "drawer-rotation",
  tenant_id: certificate.tenant_id,
  identity_id: certificate.identity_ids[0],
  status: "succeeded",
  trigger: "scheduled renewal after the configured certificate lifetime threshold",
  predecessor_fingerprint: "cd".repeat(32),
  successor_fingerprint: fingerprint,
  rollback_ref: "rollback:" + "0123456789abcdef".repeat(8),
  created_at: delivery.created_at,
  updated_at: delivery.updated_at,
};

test("populated historical certificate evidence fits every drawer breakpoint", async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  await signIn(page);
  const fixtureResponses = new Map<string, unknown>([
    ["/api/v1/certificates", { items: [certificate] }],
    [`/api/v1/certificates/${certificate.id}`, certificate],
    ["/api/v1/identities", { items: [] }],
    ["/api/v1/lifecycle/rotation-runs", { items: [rotation] }],
    [
      "/api/v1/connectors/deliveries",
      {
        items: [
          delivery,
          {
            ...delivery,
            id: "drawer-verification",
            outbox_id: undefined,
            idempotency_key: `${delivery.idempotency_key}:verified`,
            status: "verified",
            attempts: 1,
            detail: "Independent TLS readback matched the historical leaf fingerprint.",
          },
        ],
      },
    ],
  ]);
  const mutations: string[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== "GET") {
      mutations.push(`${request.method()} ${pathname}`);
      await route.abort();
    } else if (fixtureResponses.has(pathname)) {
      await route.fulfill({ json: fixtureResponses.get(pathname) });
    } else {
      await route.continue();
    }
  });

  await page.goto("/certificates");
  await page.getByRole("button", { name: "Review", exact: true }).click();
  const drawer = page.getByRole("dialog", { name: "Certificate details", exact: true });
  await expect(drawer.getByText(delivery.detail, { exact: true })).toBeVisible();
  await expect(drawer.getByText("Independent TLS readback matched the historical leaf fingerprint.", { exact: true })).toBeVisible();
  const cards = drawer.locator("section[aria-labelledby='credential-activity-timeline-heading'] ol > li");
  await expect(cards).toHaveCount(5);
  await expect(drawer.getByText(/historical evidence/i)).toBeVisible();

  for (const width of [390, 640, 767, 768, 1440]) {
    await page.setViewportSize({ width, height: 844 });
    await page.evaluate(() => document.fonts.ready);
    const clipped = await drawer.evaluate((panel) => {
      const bounds = panel.getBoundingClientRect();
      return Array.from(panel.querySelectorAll<HTMLElement>("dl, dl > div, dd, section, ol, li, p"))
        .filter((node) => node.getBoundingClientRect().width > 0 && getComputedStyle(node).position !== "absolute")
        .filter((node) => {
          const box = node.getBoundingClientRect();
          return box.left < bounds.left - 1 || box.right > bounds.right + 1 || node.scrollWidth > node.clientWidth + 1;
        })
        .map((node) => ({ tag: node.tagName, text: node.textContent?.trim().slice(0, 180), width: node.clientWidth, scrollWidth: node.scrollWidth }));
    });
    await testInfo.attach(`drawer-${width}-bounds`, { body: Buffer.from(JSON.stringify(clipped)), contentType: "application/json" });
    await testInfo.attach(`drawer-${width}`, { body: await drawer.screenshot(), contentType: "image/png" });
    expect.soft(clipped, `populated drawer content must fit at ${width}px`).toEqual([]);
    for (const card of await cards.all()) {
      await card.scrollIntoViewIfNeeded();
      await expect(card).toBeInViewport();
    }
    await expect(drawer.getByRole("link", { name: "Review identity lifecycle" })).toBeVisible();
  }
  expect(mutations, "reading certificate evidence must not issue mutations").toEqual([]);
});
