import { expect, test, type APIRequestContext, type Page, type TestInfo } from "@playwright/test";

type AuthMethods = {
  oidc: boolean;
  saml: boolean;
  ldap: boolean;
};

const supportedViewports = [
  { name: "desktop-1440x900", width: 1440, height: 900 },
  { name: "mobile-390x844", width: 390, height: 844 },
] as const;

async function readAuthMethods(request: APIRequestContext): Promise<AuthMethods> {
  const response = await request.get("/auth/methods");
  expect(response.status()).toBe(200);
  expect(response.headers()["cache-control"]).toBe("no-store");

  const methods = (await response.json()) as AuthMethods;
  expect(Object.keys(methods).sort()).toEqual(["ldap", "oidc", "saml"]);
  expect(typeof methods.oidc).toBe("boolean");
  expect(typeof methods.saml).toBe("boolean");
  expect(typeof methods.ldap).toBe("boolean");
  return methods;
}

async function assertLoginPage(page: Page, methods: AuthMethods, testInfo: TestInfo, viewport: (typeof supportedViewports)[number]) {
  await page.setViewportSize(viewport);
  await page.goto("/");

  const sso = page.getByRole("button", {
    name: /(?:continue|sign in) with sso/i,
  });
  if (methods.oidc) {
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(sso).toBeVisible();
  } else {
    await expect(page.getByRole("heading", { name: "Browser sign-in is not configured" })).toBeVisible();
    await expect(sso).toHaveCount(0);
    await expect(page.getByText(/control plane is running.*browser SSO is off/i)).toBeVisible();
    await expect(page.getByText(/scoped API token.*trstctl-cli/i)).toBeVisible();
  }

  const widths = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client);

  await testInfo.attach(`login-${viewport.name}`, {
    body: await page.screenshot({ fullPage: true }),
    contentType: "image/png",
  });
}

test("served login actions match the public capability oracle at supported viewports", async ({ page, request }, testInfo) => {
  const methods = await readAuthMethods(request);
  const login = await request.get("/auth/login", { failOnStatusCode: false, maxRedirects: 0 });
  expect(login.status()).toBe(methods.oidc ? 302 : 404);

  for (const viewport of supportedViewports) {
    await assertLoginPage(page, methods, testInfo, viewport);
  }
});
