import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("managed tenant registration recovery", () => {
  it("binds the reviewed account without replacing the authenticated session", async () => {
    const input = { tenant_id: "33333333-3333-4333-8333-333333333333", name: "Reviewed customer" };
    const principal = { tenant_id: "11111111-1111-4111-8111-111111111111", subject: "operator+東京" };
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    await api.provisionManagedTenant(input, "reviewed-request", principal);
    const options = fetchMock.mock.calls[0][1];
    const headers = new Headers(options.headers);
    expect(options.credentials).toBe("include");
    expect(headers.get("X-Tenant-ID")).toBe(principal.tenant_id);
    expect(decodeURIComponent(headers.get("X-Trstctl-Expected-Subject")!)).toBe(principal.subject);
    expect(headers.get("Authorization")).toBeNull();
    expect(headers.get("Idempotency-Key")).toBe("reviewed-request");
    expect(JSON.parse(options.body)).toEqual(input);
  });

  it("carries the original request key through a failure and its retry", async () => {
    const input = { tenant_id: "22222222-2222-4222-8222-222222222222", name: "QA Beta" };
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError("response lost"))
      .mockResolvedValueOnce(new Response(JSON.stringify({ tenant_id: input.tenant_id, name: input.name }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.provisionManagedTenant(input, "managed-registration-recovery-1")).rejects.toBeDefined();
    await api.provisionManagedTenant(input, "managed-registration-recovery-1");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [path, options] of fetchMock.mock.calls) {
      expect(path).toBe("/api/v1/managed-offering/tenants");
      expect(new Headers(options.headers).get("Idempotency-Key")).toBe("managed-registration-recovery-1");
      expect(JSON.parse(options.body)).toEqual(input);
    }
  });
});
