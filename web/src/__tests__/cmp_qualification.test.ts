import { afterEach, describe, expect, it, vi } from "vitest";
import { api, setPreviewTransportIsolation } from "@/lib/api";

describe("CMP qualification transport", () => {
  afterEach(() => {
    setPreviewTransportIsolation(false);
    vi.restoreAllMocks();
  });

  it("posts an authenticated read with no enrollment material or idempotency key", async () => {
    const response = {
      checked_at: "2026-08-28T17:00:00Z",
      ready: true,
      effect_free: true,
      endpoint: "/cmp",
      profile: "default",
      binding_mode: "subject-bound",
      client_trust_anchor_count: 1,
      checks: [],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["in-memory posture only"],
      blockers: [],
    };
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(api.cmpQualification()).resolves.toEqual(response);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0] ?? [];
    expect(path).toBe("/api/v1/protocols/cmp/qualification");
    expect(init).toEqual(expect.objectContaining({ method: "POST", credentials: "include" }));
    expect(init?.body).toBeUndefined();
    expect(init?.headers).toMatchObject({ Accept: "application/json", "Content-Type": "application/json" });
    expect(init?.headers).not.toMatchObject({ "Idempotency-Key": expect.anything() });
    expect(JSON.stringify(init)).not.toMatch(/csr|pkimessage|private.key|client.cert|trust.anchor/i);
  });

  it("makes no request when product preview transport isolation is active", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    setPreviewTransportIsolation(true);

    await expect(api.cmpQualification()).rejects.toThrow("live tenant APIs are disabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
