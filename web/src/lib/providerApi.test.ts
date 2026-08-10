// SPDX-License-Identifier: MPL-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearProviderToken, providerApi, setProviderToken } from "./providerApi";

function response(status = 204, body: unknown = undefined): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => (body === undefined ? "" : JSON.stringify(body)),
    json: async () => body,
  } as Response;
}

describe("provider API idempotency", () => {
  beforeEach(() => {
    setProviderToken("signed-provider-token");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response()));
  });

  afterEach(() => {
    clearProviderToken();
    vi.unstubAllGlobals();
  });

  it("sends a non-empty Idempotency-Key on every provider mutation", async () => {
    await providerApi.provisionTenant({ slug: "acme", name: "Acme" });
    await providerApi.suspendTenant("tenant-acme");
    await providerApi.offboardTenant("tenant-acme");
    await providerApi.setQuota("tenant-acme", { tenant_id: "tenant-acme", max_agents: 4 });
    await providerApi.setBrand("tenant-acme", { product_name: "Acme Trust" });
    await providerApi.runIsolationDrill();
    await providerApi.requestBreakGlass({ tenant_id: "tenant-acme", reason: "incident", ttl: "15m" });
    await providerApi.consentBreakGlass("grant-1", "tenant-acme");
    await providerApi.breakGlassResults("grant-1");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls).toHaveLength(9);
    const keys = calls.map(([, init]) => (init?.headers as Record<string, string>)["Idempotency-Key"]);
    expect(keys.every((key) => typeof key === "string" && key.length > 0)).toBe(true);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("keeps provider reads free of mutation keys", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(response(200, { tenants: [] }));
    await providerApi.listTenants();
    vi.mocked(fetch).mockResolvedValueOnce(response(200, { items: [] }));
    await providerApi.listActivity();
    for (const [, init] of vi.mocked(fetch).mock.calls) {
      const headers = init?.headers as Record<string, string>;
      expect(headers["Idempotency-Key"]).toBeUndefined();
    }
  });
});
