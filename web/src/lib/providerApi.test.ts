// SPDX-License-Identifier: MPL-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  canonicalProviderUsageEvidence,
  clearProviderToken,
  providerApi,
  setProviderToken,
  verifyProviderUsageEvidence,
  type ProviderUsageEvidence,
} from "./providerApi";

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
    await providerApi.signOut();

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls).toHaveLength(10);
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

  it("pulls customer-path invoice evidence and public verification keys without a tenant session", async () => {
    const evidence = {
      customer_id: "tenant/acme",
      period_start: "2026-07-01T00:00:00Z",
      period_end: "2026-08-01T00:00:00Z",
      lines: [],
      signable: false,
      reason: "fixture",
      digest: "fixture-digest",
      guidance: "fixture",
    };
    vi.mocked(fetch)
      .mockResolvedValueOnce(response(200, evidence))
      .mockResolvedValueOnce(response(200, { keys: [{ kty: "RSA", kid: "audit-1", n: "n", e: "AQAB" }] }));

    await expect(providerApi.usageEvidence("tenant/acme", evidence.period_start, evidence.period_end)).resolves.toEqual(evidence);
    await providerApi.evidenceVerificationKeys();

    const [evidencePath, evidenceInit] = vi.mocked(fetch).mock.calls[0];
    expect(String(evidencePath)).toContain("/provider/v1/tenants/tenant%2Facme/usage-evidence?");
    expect(String(evidencePath)).toContain("period_start=2026-07-01T00%3A00%3A00Z");
    expect((evidenceInit?.headers as Record<string, string>)["Idempotency-Key"]).toBeUndefined();
    expect(vi.mocked(fetch).mock.calls[1][0]).toBe("/provider/v1/evidence/verification-keys");
  });

  it("verifies the exact displayed evidence bytes under the billing-invoice JWS domain", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const publicJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const document: ProviderUsageEvidence = {
      customer_id: "tenant-alpha",
      period_start: "2026-07-01T00:00:00Z",
      period_end: "2026-08-01T00:00:00Z",
      lines: [{ meter: "certificates_issued", kind: "counter", value: 3 }],
      signable: true,
      reason: "complete",
      observed_from: "2026-06-30T23:00:00Z",
      observed_to: "2026-08-01T01:00:00Z",
      reconciliation: [{ meter: "certificates_issued", metered: 3, event_history: 3, checked: true, matches: true }],
      digest: "",
      guidance: "verify before invoicing",
    };
    const payload = canonicalProviderUsageEvidence(document);
    document.digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", payload.slice().buffer as ArrayBuffer))]
      .map((part) => part.toString(16).padStart(2, "0"))
      .join("");
    const b64url = (bytes: Uint8Array) =>
      btoa(String.fromCharCode(...bytes))
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/, "");
    const header = new TextEncoder().encode(
      JSON.stringify({ alg: "RS256", typ: "JWT", kid: "audit-1", trstctl_artifact: "trstctl.audit-evidence/billing-invoice/v1" }),
    );
    const signingInput = `${b64url(header)}.${b64url(payload)}`;
    const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, new TextEncoder().encode(signingInput));
    document.signature = { alg: "RS256", key_id: "audit-1", jws: `${signingInput}.${b64url(new Uint8Array(signature))}` };
    const keys = { keys: [{ ...publicJWK, kid: "audit-1", alg: "RS256", use: "sig" }] };

    await expect(verifyProviderUsageEvidence(document, keys)).resolves.toEqual({ verified: true, keyId: "audit-1" });
    const tampered = { ...document, lines: [{ ...(document.lines ?? [])[0], value: 4 }] };
    await expect(verifyProviderUsageEvidence(tampered, keys)).resolves.toEqual({ verified: false, keyId: "audit-1" });
  });

  it("uses the separate SAML cookie session and double-submit CSRF without a JavaScript bearer", async () => {
    clearProviderToken();
    document.cookie = "trstctl_provider_csrf=csrf-proof; Path=/";
    vi.mocked(fetch).mockResolvedValueOnce(response(200, { id: "op-1", email: "admin@example.test", role: "admin", mfa: true, session: "sid-1" }));
    await providerApi.session();
    vi.mocked(fetch).mockResolvedValueOnce(response(204));
    await providerApi.suspendTenant("tenant-acme");

    const [, readInit] = vi.mocked(fetch).mock.calls[0];
    expect(readInit?.credentials).toBe("same-origin");
    expect((readInit?.headers as Record<string, string>).Authorization).toBeUndefined();
    const [, mutationInit] = vi.mocked(fetch).mock.calls[1];
    const headers = mutationInit?.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    expect(headers["X-Provider-CSRF-Token"]).toBe("csrf-proof");
    expect(headers["Idempotency-Key"]).toBeTruthy();
    document.cookie = "trstctl_provider_csrf=; Max-Age=0; Path=/";
  });
});
