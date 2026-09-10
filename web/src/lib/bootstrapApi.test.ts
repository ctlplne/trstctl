import { afterEach, describe, expect, it, vi } from "vitest";

// Exercise the real HTTP transport with a local fetch stub. No server or
// customer result is simulated as qualification by these unit regressions.
afterEach(async () => {
  const transport = await import("./apiTransport");
  transport.setPreviewTransportIsolation(false);
  transport.setAuthenticatedBrowserTenantID(null);
  document.cookie = "trstctl_csrf=; Max-Age=0; path=/";
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("startup and lazy route transport", () => {
  it("shares the error constructors and already-wrapped startup methods", async () => {
    const startup = await import("./bootstrapApi");
    const transport = await import("./apiTransport");
    const full = await import("./api");
    expect(full.ApiError).toBe(transport.ApiError);
    expect(full.UnauthorizedError).toBe(transport.UnauthorizedError);
    for (const name of ["me", "authMethods", "logout", "editions", "capabilities", "notifications"] as const) {
      expect(full.api[name]).toBe(startup.bootstrapApi[name]);
    }
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 401 })));
    await expect(startup.bootstrapApi.me()).rejects.toBeInstanceOf(full.UnauthorizedError);
  });

  it("retains CSRF, credentials, notification encoding, rate-limit detail and empty responses", async () => {
    const { bootstrapApi } = await import("./bootstrapApi");
    const { ApiError } = await import("./apiTransport");
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response('{"items":[]}', { status: 200 }))
      .mockResolvedValueOnce(new Response("slow", { status: 429, headers: { "Retry-After": "7" } }));
    vi.stubGlobal("fetch", fetchSpy);
    document.cookie = "trstctl_csrf=shared%20csrf; path=/";
    await expect(bootstrapApi.logout()).resolves.toBeUndefined();
    expect(fetchSpy.mock.calls[0]).toEqual([
      "/auth/logout",
      { method: "POST", credentials: "include", headers: { Accept: "application/json", "X-CSRF-Token": "shared csrf" } },
    ]);
    await bootstrapApi.notifications({ limit: 50, cursor: "a/b?", status: "read" });
    expect(fetchSpy.mock.calls[1][0]).toBe("/api/v1/notifications?limit=50&cursor=a%2Fb%3F&status=read");
    const error = await bootstrapApi.capabilities().catch((error: unknown) => error);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, retryAfterSeconds: 7 });
  });

  it("carries preview isolation into later route and audit imports before any fetch", async () => {
    const transport = await import("./apiTransport");
    transport.setPreviewTransportIsolation(true);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const { bootstrapApi } = await import("./bootstrapApi");
    const { api } = await import("./api");
    const { downloadAuditExport } = await import("./auditExport");
    await expect(bootstrapApi.me()).rejects.toBeInstanceOf(transport.ApiError);
    await expect(api.createSecret({ name: "refused", value: "never sent" })).rejects.toBeInstanceOf(transport.ApiError);
    await expect(transport.req("/api/v1/identities")).rejects.toBeInstanceOf(transport.ApiError);
    await expect(downloadAuditExport(undefined, "ndjson")).rejects.toBeInstanceOf(transport.ApiError);
    expect(fetchSpy).not.toHaveBeenCalled();
    transport.setPreviewTransportIsolation(false);
    fetchSpy.mockResolvedValue(new Response('{"subject":"operator","tenant_id":"owned-tenant"}', { status: 200 }));
    await expect(bootstrapApi.me()).resolves.toMatchObject({ tenant_id: "owned-tenant" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("uses only the authenticated tenant across a later machine-client import and refuses after clearing it", async () => {
    const { bootstrapApi } = await import("./bootstrapApi");
    const transport = await import("./apiTransport");
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce(new Response('{"subject":"operator","tenant_id":"owned-tenant"}', { status: 200 }))
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const principal = await bootstrapApi.me();
    transport.setAuthenticatedBrowserTenantID(principal.tenant_id);
    const { api } = await import("./api");
    await api.machineLogin({ method: "token", credential: "unit-fixture-only" });
    expect(fetchSpy.mock.calls[1][1].headers).toMatchObject({ "X-Tenant-ID": "owned-tenant", "Idempotency-Key": expect.any(String) });
    transport.setAuthenticatedBrowserTenantID(null);
    const serialize = vi.fn(() => {
      throw new Error("must not serialize");
    });
    await expect(
      api.machineLogin({ method: "token", credential: "refused", toJSON: serialize } as Parameters<typeof api.machineLogin>[0]),
    ).rejects.toMatchObject({ status: 0 });
    expect(serialize).not.toHaveBeenCalled();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});
