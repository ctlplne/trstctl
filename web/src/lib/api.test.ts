import { describe, it, expect, vi, afterEach } from "vitest";
import { api, ApiError, firstCertificateIdentityRequest, UnauthorizedError } from "@/lib/api";

// Unit tests for the typed REST client's error handling, focused on the SURFACE-007
// 429/Retry-After path. We stub global fetch so no network is touched.

function mockFetch(status: number, body: string, headers: Record<string, string> = {}) {
  const h = new Headers(headers);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(status === 204 ? null : body, { status, headers: h })),
  );
}

function mockFetchSequence(responses: Array<{ status: number; body: string; headers?: Record<string, string> }>) {
  const queue = [...responses];
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      const next = queue.shift();
      if (!next) throw new Error("unexpected fetch call");
      return new Response(next.status === 204 ? null : next.body, {
        status: next.status,
        headers: new Headers(next.headers ?? {}),
      });
    }),
  );
}

function lastSentHeaders(): Record<string, string> {
  const init = vi.mocked(fetch).mock.calls.at(-1)?.[1] as RequestInit | undefined;
  return (init?.headers ?? {}) as Record<string, string>;
}

afterEach(() => {
  document.cookie = "trstctl_csrf=; Max-Age=0; path=/";
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("api error handling (SURFACE-007)", () => {
  it("maps 401 to UnauthorizedError", async () => {
    mockFetch(401, "no");
    await expect(api.certificates()).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it("surfaces a 429 as a rate-limited ApiError with Retry-After seconds", async () => {
    mockFetch(429, "slow down", { "Retry-After": "30" });
    const err = await api.certificates().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(429);
    expect((err as ApiError).isRateLimited).toBe(true);
    expect((err as ApiError).retryAfterSeconds).toBe(30);
    expect((err as ApiError).message).toMatch(/retry in 30s/);
  });

  it("parses a 429 Retry-After HTTP-date into seconds", async () => {
    const tenSecondsOut = new Date(Date.now() + 10_000).toUTCString();
    mockFetch(429, "slow down", { "Retry-After": tenSecondsOut });
    const err = (await api.certificates().catch((e) => e)) as ApiError;
    expect(err.status).toBe(429);
    // Allow a little clock slack around the 10s target.
    expect(err.retryAfterSeconds).toBeGreaterThanOrEqual(8);
    expect(err.retryAfterSeconds).toBeLessThanOrEqual(11);
  });

  it("a 429 without Retry-After is still rate-limited (no seconds)", async () => {
    mockFetch(429, "slow down");
    const err = (await api.certificates().catch((e) => e)) as ApiError;
    expect(err.isRateLimited).toBe(true);
    expect(err.retryAfterSeconds).toBeUndefined();
  });

  it("maps other non-2xx to a generic ApiError", async () => {
    mockFetch(500, "boom");
    const err = (await api.certificates().catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(500);
    expect(err.isRateLimited).toBe(false);
  });
});

describe("api compliance evidence packs", () => {
  it("reads framework evidence packs from the served compliance route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        format: "trstctl.compliance.evidence-pack.v1",
        framework: "soc2",
        signed_export: { manifest: { framework: "soc2", controls: [] }, signature: "sig" },
        public_key_der: "BASE64PUBLICKEY",
      }),
    );

    const pack = await api.complianceEvidencePack("soc2");

    expect(pack.framework).toBe("soc2");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/compliance/evidence-packs/soc2");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });
});

describe("api CA hierarchy and managed keys", () => {
  it("starts and approves CA ceremonies through the served mutation routes", async () => {
    mockFetchSequence([
      {
        status: 201,
        body: JSON.stringify({
          id: "ceremony-root-1",
          tenant_id: "tenant-1",
          purpose: "create_root:Trust Root CA",
          threshold: 2,
          status: "pending",
          approvals: 1,
          created_at: "2026-06-26T14:00:00Z",
        }),
      },
      {
        status: 200,
        body: JSON.stringify({
          id: "ceremony-root-1",
          tenant_id: "tenant-1",
          purpose: "create_root:Trust Root CA",
          threshold: 2,
          status: "approved",
          approvals: 2,
          created_at: "2026-06-26T14:00:00Z",
        }),
      },
    ]);

    await api.createCACeremony({
      operation: "create_root",
      threshold: 2,
      spec: { common_name: "Trust Root CA", signature_algorithm: "ECDSA-P256" },
    });
    await api.approveCACeremony("ceremony-root-1");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.map((call) => call[0])).toEqual(["/api/v1/ca/ceremonies", "/api/v1/ca/ceremonies/ceremony-root-1/approvals"]);
    for (const call of calls) {
      expect(call[1]?.method).toBe("POST");
      expect((call[1]?.headers as Record<string, string>)["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
    }
  });

  it("drives managed-key lifecycle actions through served mutation routes", async () => {
    mockFetchSequence([
      { status: 201, body: JSON.stringify({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 1, state: "active" }) },
      { status: 200, body: JSON.stringify({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "active" }) },
      { status: 200, body: JSON.stringify({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "revoked" }) },
      { status: 200, body: JSON.stringify({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "zeroized" }) },
    ]);

    await api.generateManagedKey({ algorithm: "ECDSA-P256" });
    await api.rotateManagedKey("kms/root-1");
    await api.revokeManagedKey("kms/root-1");
    await api.zeroizeManagedKey("kms/root-1");

    expect(vi.mocked(fetch).mock.calls.map((call) => call[0])).toEqual([
      "/api/v1/managed-keys",
      "/api/v1/managed-keys/rotate",
      "/api/v1/managed-keys/revoke",
      "/api/v1/managed-keys/zeroize",
    ]);
  });
});

describe("api CSRF contract (SEC-001)", () => {
  function sentHeaders(): Record<string, string> {
    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.length).toBeGreaterThan(0);
    return calls[0][1]?.headers as Record<string, string>;
  }

  it("echoes the CSRF cookie on mutating session requests", async () => {
    document.cookie = "trstctl_csrf=csrf-token-1; path=/";
    mockFetch(
      200,
      JSON.stringify({
        id: "owner-1",
        tenant_id: "tenant-1",
        kind: "team",
        name: "Platform",
      }),
    );

    await api.createOwner({ kind: "team", name: "Platform" });

    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-1");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });

  it("echoes the CSRF cookie on session read POST requests", async () => {
    document.cookie = "trstctl_csrf=csrf-token-2; path=/";
    mockFetch(200, JSON.stringify({ text: "answer", sufficient: true }));

    await api.aiQuery({ surfaces: ["certificates"], question: "which certs are risky?" });

    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-2");
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
  });

  it("posts logout to the served auth endpoint with the CSRF cookie", async () => {
    document.cookie = "trstctl_csrf=csrf-token-logout; path=/";
    mockFetch(204, "");

    await api.logout();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/auth/logout");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-logout");
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
  });

  it("sends certificate ingest through the served mutation with Idempotency-Key", async () => {
    document.cookie = "trstctl_csrf=csrf-token-3; path=/";
    mockFetch(
      201,
      JSON.stringify({
        id: "cert-1",
        tenant_id: "tenant-1",
        subject: "CN=svc",
        fingerprint: "sha256:abc",
        status: "active",
      }),
    );

    await api.ingestCertificate({ pem: "-----BEGIN CERTIFICATE-----\n..." });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/certificates");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-3");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });

  it("uses a distinct Idempotency-Key for each identity transition mutation", async () => {
    document.cookie = "trstctl_csrf=csrf-token-bulk; path=/";
    mockFetch(202, JSON.stringify({ id: "id-1", name: "svc", status: "revoked" }));

    await api.transitionIdentity("id-1", "revoked", "bulk revoke via UI");
    await api.transitionIdentity("id-2", "revoked", "bulk revoke via UI");

    const calls = vi.mocked(fetch).mock.calls;
    const firstHeaders = calls[0][1]?.headers as Record<string, string>;
    const secondHeaders = calls[1][1]?.headers as Record<string, string>;
    expect(firstHeaders["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
    expect(secondHeaders["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
    expect(firstHeaders["Idempotency-Key"]).not.toBe(secondHeaders["Idempotency-Key"]);
  });

  it("posts NHI decommission through the served mutation with Idempotency-Key", async () => {
    document.cookie = "trstctl_csrf=csrf-token-decommission; path=/";
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-GOV-04",
        coverage: ["departure", "vendor_term", "inactivity", "revoke", "retire"],
        reason: "vendor termination",
        summary: { total_matched: 1, revoked: 1, retired: 0, skipped: 0, failed: 0 },
        items: [],
      }),
    );

    await api.decommissionNHI({
      reason: "vendor termination",
      signals: [{ type: "vendor_term", vendor_name: "Acme SaaS", evidence_refs: ["ui:test"] }],
    });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/nhi/decommission");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-decommission");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toMatchObject({
      reason: "vendor termination",
      signals: [{ type: "vendor_term", vendor_name: "Acme SaaS" }],
    });
  });

  it("mints an enrollment token through the served mutation with Idempotency-Key", async () => {
    document.cookie = "trstctl_csrf=csrf-token-agent; path=/";
    mockFetch(201, JSON.stringify({ token: "BOOT-TOKEN-XYZ", enroll_path: "/enroll/bootstrap" }));

    const token = await api.createEnrollmentToken();

    expect(token.token).toBe("BOOT-TOKEN-XYZ");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/agents/enrollment-tokens");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-agent");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });

  it("drives dynamic lease issue, renew, and revoke through served mutations", async () => {
    document.cookie = "trstctl_csrf=csrf-token-lease; path=/";
    mockFetchSequence([
      {
        status: 201,
        body: JSON.stringify({
          id: "lease/one",
          provider: "postgres",
          role: "readonly",
          state: "active",
          credential: "user=lease password=secret",
          issued_at: "2026-06-24T12:00:00Z",
          expires_at: "2026-06-24T12:15:00Z",
        }),
      },
      {
        status: 200,
        body: JSON.stringify({
          id: "lease/one",
          provider: "postgres",
          role: "readonly",
          state: "active",
          issued_at: "2026-06-24T12:00:00Z",
          expires_at: "2026-06-24T12:30:00Z",
        }),
      },
      {
        status: 200,
        body: JSON.stringify({
          id: "lease/one",
          provider: "postgres",
          role: "readonly",
          state: "revoked",
          issued_at: "2026-06-24T12:00:00Z",
          expires_at: "2026-06-24T12:30:00Z",
        }),
      },
    ]);

    await api.issueDynamicLease({ provider: "postgres", role: "readonly", ttl_seconds: 900 });
    await api.renewDynamicLease("lease/one", { extend_seconds: 900 });
    await api.revokeDynamicLease("lease/one");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.map((call) => call[0])).toEqual([
      "/api/v1/secrets/leases",
      "/api/v1/secrets/leases/lease%2Fone/renew",
      "/api/v1/secrets/leases/lease%2Fone/revoke",
    ]);
    for (const call of calls) {
      const headers = call[1]?.headers as Record<string, string>;
      expect(call[1]?.method).toBe("POST");
      expect(headers["X-CSRF-Token"]).toBe("csrf-token-lease");
      expect(headers["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
    }
    expect(new Set(calls.map((call) => (call[1]?.headers as Record<string, string>)["Idempotency-Key"])).size).toBe(3);
  });

  it("reads dynamic lease metadata without replaying a credential or idempotency key", async () => {
    mockFetch(
      200,
      JSON.stringify({
        id: "lease/one",
        provider: "postgres",
        role: "readonly",
        state: "active",
        issued_at: "2026-06-24T12:00:00Z",
        expires_at: "2026-06-24T12:15:00Z",
      }),
    );

    const lease = await api.getDynamicLease("lease/one");

    expect(lease.id).toBe("lease/one");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/leases/lease%2Fone");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
  });

  it("builds the internal-CA first certificate identity request without an issuer", () => {
    expect(firstCertificateIdentityRequest({ name: "payments" }, "owner-1")).toEqual({
      kind: "x509_certificate",
      name: "payments",
      owner_id: "owner-1",
    });
  });

  it("keeps an explicit issuer only when the caller provides one", () => {
    expect(firstCertificateIdentityRequest({ name: "payments", issuerId: "issuer-1" }, "owner-1")).toEqual({
      kind: "x509_certificate",
      name: "payments",
      owner_id: "owner-1",
      issuer_id: "issuer-1",
    });
  });

  it("issues the first wizard certificate without posting a fake issuer_id", async () => {
    document.cookie = "trstctl_csrf=csrf-token-first-cert; path=/";
    mockFetchSequence([
      {
        status: 201,
        body: JSON.stringify({ id: "owner-1", tenant_id: "tenant-1", kind: "workload", name: "payments" }),
      },
      {
        status: 201,
        body: JSON.stringify({
          id: "identity-1",
          tenant_id: "tenant-1",
          kind: "x509_certificate",
          name: "payments",
          owner_id: "owner-1",
          status: "requested",
        }),
      },
      {
        status: 202,
        body: JSON.stringify({
          id: "identity-1",
          tenant_id: "tenant-1",
          kind: "x509_certificate",
          name: "payments",
          owner_id: "owner-1",
          status: "issued",
        }),
      },
    ]);

    await api.issueCertificate({ name: "payments" });

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.map((call) => call[0])).toEqual(["/api/v1/owners", "/api/v1/identities", "/api/v1/identities/identity-1/transitions"]);
    expect(JSON.parse(calls[1][1]?.body as string)).toEqual({
      kind: "x509_certificate",
      name: "payments",
      owner_id: "owner-1",
    });
    expect(JSON.stringify(calls[1][1]?.body)).not.toContain("issuer_id");
    expect((calls[1][1]?.headers as Record<string, string>)["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });
});

describe("agent contract", () => {
  it("lists agents from the served envelope", async () => {
    mockFetch(
      200,
      JSON.stringify({
        agents: [
          {
            id: "ag-1",
            name: "edge-01",
            status: "online",
            version: "0.4.0",
            last_seen_at: "2026-06-19T12:00:00Z",
          },
        ],
        next_cursor: "cursor-2",
      }),
    );

    const agents = await api.agents();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/agents");
    expect(agents).toEqual([
      {
        id: "ag-1",
        name: "edge-01",
        status: "online",
        version: "0.4.0",
        last_seen_at: "2026-06-19T12:00:00Z",
      },
    ]);
  });
});

describe("protocol responder status contract", () => {
  it("checks served protocol responder paths without mutation headers", async () => {
    mockFetchSequence([
      { status: 200, body: "{}" },
      { status: 404, body: "not mounted" },
      { status: 200, body: "GetCACaps\nPOSTPKIOperation" },
      { status: 405, body: "method not allowed" },
      { status: 200, body: "ssh-ed25519 AAAA..." },
      { status: 405, body: "method not allowed" },
    ]);

    const page = await api.protocolStatuses();

    expect(page.source).toBe("public_responder_probe");
    expect(page.items.map((item) => [item.protocol, item.enabled, item.served, item.status_code])).toEqual([
      ["acme", true, true, 200],
      ["est", false, false, 404],
      ["scep", true, true, 200],
      ["cmp", true, true, 405],
      ["ssh", true, true, 200],
      ["tsa", true, true, 405],
    ]);
    expect(vi.mocked(fetch).mock.calls.map((call) => call[0])).toEqual([
      "/directory",
      "/.well-known/est/cacerts",
      "/scep?operation=GetCACaps",
      "/cmp",
      "/ssh/ca",
      "/tsa",
    ]);
    for (const call of vi.mocked(fetch).mock.calls) {
      expect((call[1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeUndefined();
    }
  });
});

describe("secrets contract", () => {
  function sentHeaders(): Record<string, string> {
    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.length).toBeGreaterThan(0);
    return calls[0][1]?.headers as Record<string, string>;
  }

  it("lists secret metadata without values through the served store page", async () => {
    mockFetch(
      200,
      JSON.stringify({
        items: [{ name: "app/db/password", version: 3, updated_at: "2026-06-19T12:00:00Z" }],
        next_cursor: "cursor-2",
      }),
    );

    const page = await api.secretPage({ limit: 10, cursor: "cursor-1" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store?limit=10&cursor=cursor-1");
    expect(page.items[0]).toEqual({
      name: "app/db/password",
      version: 3,
      updated_at: "2026-06-19T12:00:00Z",
    });
    expect(JSON.stringify(page)).not.toContain("value");
  });

  it("reads and rotates URL-encoded secret names", async () => {
    mockFetchSequence([
      { status: 200, body: JSON.stringify({ name: "app/db/password", value: "read-once", version: 3 }) },
      { status: 200, body: JSON.stringify({ name: "app/db/dsn", value: "postgres://app:secret@db/internal", version: 1 }) },
    ]);

    await api.getSecret("app/db/password");

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store/app%2Fdb%2Fpassword");

    await api.getSecret("app/db/dsn", { resolve: true });

    expect(vi.mocked(fetch).mock.calls[1][0]).toBe("/api/v1/secrets/store/app%2Fdb%2Fdsn?resolve=true");

    document.cookie = "trstctl_csrf=csrf-secret-rotate; path=/";
    mockFetch(200, JSON.stringify({ name: "app/db/password", version: 4 }));

    await api.rotateSecret("app/db/password", { name: "app/db/password", value: "new-value" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store/app%2Fdb%2Fpassword");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("PUT");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-secret-rotate");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });

  it("imports a secret tree as an idempotent mutation", async () => {
    document.cookie = "trstctl_csrf=csrf-secret-import; path=/";
    mockFetch(
      201,
      JSON.stringify({
        items: [
          { name: "imported/api/token", version: 1 },
          { name: "imported/api/url", version: 1 },
        ],
      }),
    );

    const page = await api.importSecrets({
      prefix: "imported",
      values: {
        "api/token": "tok-1",
        "api/url": "https://svc.internal?token=${secret.imported/api/token}",
      },
    });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store/import");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-secret-import");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
    expect(JSON.stringify(page)).not.toContain("tok-1");
  });

  it("reads historical secret versions and recovers by timestamp", async () => {
    mockFetch(200, JSON.stringify({ name: "app/db/password", value: "old-value", version: 2 }));

    await api.getSecretVersion("app/db/password", 2);

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store/history/app%2Fdb%2Fpassword?version=2");

    document.cookie = "trstctl_csrf=csrf-secret-recover; path=/";
    mockFetch(200, JSON.stringify({ name: "app/db/password", version: 5 }));

    await api.recoverSecret("app/db/password", { at: "2026-06-25T12:00:00Z" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store/recover/app%2Fdb%2Fpassword");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-secret-recover");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });

  it("sends served secret creation, PKI issue, login, and sharing as idempotent mutations", async () => {
    document.cookie = "trstctl_csrf=csrf-secrets; path=/";
    mockFetch(201, JSON.stringify({ name: "app/api", version: 1 }));
    await api.createSecret({ name: "app/api", value: "stored" });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);

    mockFetch(201, JSON.stringify({ serial: "01", certificate: "CERT", private_key: "KEY" }));
    await api.issuePKISecret({ common_name: "svc.internal", ttl_seconds: 600 });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/pki");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);

    mockFetch(200, JSON.stringify({ session_id: "sess-1", principal: "svc", method: "token", scopes: ["secrets:read"], expires_at: "2026-06-19T13:00:00Z" }));
    await api.machineLogin({ method: "token", credential: "machine-token" });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/login");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);

    mockFetch(201, JSON.stringify({ token: "share-token", expires_at: "2026-06-19T13:00:00Z" }));
    await api.createShare({ value: "secret", ttl_seconds: 300 });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/shares");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);

    mockFetch(200, JSON.stringify({ value: "redeemed-once" }));
    await api.redeemShare({ token: "share-token" });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/shares/redeem");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });
});

describe("certificate inventory contract", () => {
  it("keeps next_cursor available through the cursor-aware page helper", async () => {
    mockFetch(
      200,
      JSON.stringify({
        items: [{ id: "cert-1", tenant_id: "tenant-1", subject: "CN=svc", fingerprint: "fp", status: "active" }],
        next_cursor: "cursor-2",
      }),
    );

    const page = await api.certificatePage({
      limit: 5,
      cursor: "cursor-1",
      expiringBefore: "2026-07-01T00:00:00.000Z",
    });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/certificates?limit=5&cursor=cursor-1&expiring_before=2026-07-01T00%3A00%3A00.000Z");
    expect(page.next_cursor).toBe("cursor-2");
  });

  it("fetches an individual certificate detail by id", async () => {
    mockFetch(
      200,
      JSON.stringify({
        id: "cert/unsafe",
        tenant_id: "tenant-1",
        subject: "CN=svc",
        fingerprint: "fp",
        status: "active",
      }),
    );

    await api.getCertificate("cert/unsafe");

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/certificates/cert%2Funsafe");
  });

  it("fetches an individual identity detail by id", async () => {
    mockFetch(
      200,
      JSON.stringify({
        id: "identity/unsafe",
        kind: "workload_identity",
        name: "svc",
        owner_id: "owner-1",
        status: "issued",
      }),
    );

    await api.getIdentity("identity/unsafe");

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/identities/identity%2Funsafe");
  });
});

describe("remediation playbook contract", () => {
  it("fetches the served playbook catalog", async () => {
    mockFetch(200, JSON.stringify({ capability: "CAP-REM-01", status: "served", generated_at: "2026-06-29T00:00:00Z", items: [] }));

    await api.remediationPlaybooks();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/remediation/playbooks");
  });

  it("runs a playbook with idempotency", async () => {
    mockFetch(
      201,
      JSON.stringify({
        id: "run-1",
        tenant_id: "tenant-1",
        playbook_id: "nhi-right-size",
        status: "queued",
        phase: "right_size_connector_intent_queued",
        action: "right_size",
        scope_delta: {},
        evidence_refs: [],
        rollback_refs: [],
        created_at: "2026-06-29T00:00:00Z",
        updated_at: "2026-06-29T00:00:00Z",
      }),
    );

    await api.runRemediationPlaybook("nhi-right-size", { target_identity_id: "id-1", reason: "right-size" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/remediation/playbooks/nhi-right-size/runs");
    expect(lastSentHeaders()["Idempotency-Key"]).toBeTruthy();
  });

  it("lists playbook runs by playbook id", async () => {
    mockFetch(200, JSON.stringify({ items: [], next_cursor: "" }));

    await api.remediationPlaybookRuns({ limit: 5, cursor: "run-0", playbookId: "nhi-right-size" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/remediation/playbook-runs?limit=5&cursor=run-0&playbook_id=nhi-right-size");
  });

  it("lists CAP-REM-02 owner-driven self-remediation actions", async () => {
    mockFetch(200, JSON.stringify({ capability: "CAP-REM-02", status: "served", generated_at: "2026-06-30T00:00:00Z", summary: {}, items: [] }));

    await api.ownerRemediationActions({ ownerId: "owner-1" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/remediation/owner-actions?owner_id=owner-1");
  });

  it("accepts a CAP-REM-02 owner action with idempotency", async () => {
    mockFetch(
      201,
      JSON.stringify({
        capability: "CAP-REM-02",
        status: "accepted",
        action: { id: "right-size-a", owner_id: "owner-1", owner_name: "payments", inventory_id: "identity/id-1", display_name: "payments", kind: "service_account", source: "managed", playbook_id: "nhi-right-size", action: "right_size", status: "accepted", severity: "high", risk_score: 80, connector: "aws-iam", target: "role/payments", reason: "owner accepted", recommendation: "remove admin", remove_scopes: ["admin:*"], recommended_scopes: ["secrets:read"], evidence_refs: [], rollback_ref: "restore" },
        remediation_run: {
          id: "run-1",
          tenant_id: "tenant-1",
          playbook_id: "nhi-right-size",
          status: "queued",
          phase: "right_size_connector_intent_queued",
          action: "right_size",
          scope_delta: {},
          evidence_refs: [],
          rollback_refs: [],
          created_at: "2026-06-30T00:00:00Z",
          updated_at: "2026-06-30T00:00:00Z",
        },
      }),
    );

    await api.acceptOwnerRemediationAction("right-size-a", { reason: "owner accepted" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/remediation/owner-actions/right-size-a/accept");
    expect(lastSentHeaders()["Idempotency-Key"]).toBeTruthy();
  });
});

describe("revocation CRL distribution contract", () => {
  it("fetches full, sharded, and delta CRL distribution status from the served route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        items: [
          {
            tenant_id: "tenant-1",
            ca_id: "ca-root",
            full_number: 42,
            full_url: "/crl/tenant-1",
            shard_count: 4,
            shards: [{ index: 0, revoked_count: 125000, url: "/crl/tenant-1/shards/0" }],
            delta_base_number: 41,
            delta_url: "/crl/tenant-1/delta/41",
            revoked_count: 125000,
            this_update: "2026-06-29T00:00:00Z",
            next_update: "2026-06-30T00:00:00Z",
          },
        ],
      }),
    );

    const result = await api.crlDistributions();

    expect(result.items[0]?.shards[0]?.url).toBe("/crl/tenant-1/shards/0");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/revocation/crls");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });
});

describe("scale orchestration contract", () => {
  it("fetches CAP-SCALE-01 orchestration posture from the served route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-SCALE-01",
        served: true,
        generated_at: "2026-06-29T00:00:00Z",
        target_credential_bands: [
          { id: "SCALE-1M", managed_credential: "1,000,000 managed credentials", capacity_tier: "CAP-LARGE", topology: "multi-replica enterprise" },
        ],
        selected_capacity_tier: {
          id: "CAP-LARGE",
          name: "multi-replica enterprise",
          tenants: 250,
          managed_credentials: 1000000,
          events_per_day: 10000000,
          postgres_gib_30_day: 700,
          jetstream_gib_30_day: 1200,
          control_plane_cpu: "16 vCPU",
          control_plane_memory_gib: 32,
          signer_cpu: "6 vCPU",
          signer_memory_gib: 8,
          estimated_monthly_cost_usd: 14500,
          estimated_cost_per_credential_usd: 0.0145,
          notes: "External HA PostgreSQL and JetStream.",
        },
        hot_path_slos: [],
        execution_lanes: [
          {
            id: "scale-signer",
            subsystem: "signer",
            worker_pool: "signer",
            queue: "signer",
            bulkhead_env: ["TRSTCTL_SIGNER_WORKERS"],
            failure_mode: "reject",
            external_side_effect: "signature",
            replay_source: "events",
            scale_trigger: "p95",
            hot_path_slo: "PERF-SLO-007",
            operator_control: "scale signer",
            backpressure_signal: "queue saturation",
            measurement: "perf live signer.rpc",
            architecture_invariant: "AN-3/AN-4/AN-7/AN-8",
          },
        ],
        shard_plan: [],
        backpressure_policy: [],
        release_gates: [
          { id: "perf-live", command: "scripts/perf/run-local.sh --profile live", artifact: "scripts/perf/artifacts/live-load-baseline.json", required: true },
        ],
        operator_actions: ["run perf-live"],
        residuals: ["customer pricing is operator-specific"],
        evidence_refs: ["internal/perf/contract.go"],
        measurement_artifacts: ["scripts/perf/artifacts/live-load-baseline.json"],
        estimated_daily_event_load: 10000000,
        estimated_monthly_cost_usd: 14500,
        unit_economics: { estimated_cost_per_credential_usd: 0.0145, postgres_gib_30_day: 700, jetstream_gib_30_day: 1200, events_per_day: 10000000 },
        tenant_isolation: { storage_enforcement: "RLS", query_rule: "tenant filter", evidence_refs: [] },
        datastore: { postgres: "external HA PostgreSQL", jetstream: "external JetStream", rls: "tenant_id", outbox: "transactional outbox" },
        signer: { process_model: "separate signer process", transport: "gRPC over UDS", scaling: "scale signer separately" },
        projection_replay: { replay_floor_events_per_second: 500, max_lag_events: 50, rebuild_source: "events" },
      }),
    );

    const result = await api.scaleOrchestration();

    expect(result.capability).toBe("CAP-SCALE-01");
    expect(result.selected_capacity_tier.managed_credentials).toBe(1000000);
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/scale/orchestration");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });

  it("fetches CAP-SCALE-02 regional HA issuance posture from the served route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-SCALE-02",
        served: true,
        generated_at: "2026-06-29T00:00:00Z",
        topology: "multi-region active ingress on a shared writer plane",
        write_model: "active regional API acceptance with idempotency and event append fencing",
        regions: [
          {
            id: "region-a",
            region: "primary-us-east",
            role: "active issuance ingress",
            writable_scope: "tenant issuance requests that commit in the shared writer plane",
            datastore: "external PostgreSQL",
            event_stream: "replicated JetStream",
            signer: "isolated signer",
            health_signal: "readyz and synthetic issue smoke",
          },
          {
            id: "region-b",
            region: "secondary-us-west",
            role: "active issuance ingress",
            writable_scope: "same idempotent writer plane",
            datastore: "external PostgreSQL",
            event_stream: "replicated JetStream",
            signer: "isolated signer",
            health_signal: "readyz and projection lag",
          },
        ],
        tenant_write_fences: [
          {
            id: "idempotency",
            scope: "every issuance mutation",
            mechanism: "Idempotency-Key recorded before execution",
            conflict_outcome: "retry returns original result",
            evidence: "AN-5",
          },
          {
            id: "event-log",
            scope: "issued certificate state",
            mechanism: "append event first",
            conflict_outcome: "one ordered event stream",
            evidence: "AN-2",
          },
        ],
        issuance_lanes: [
          {
            id: "issue-region-a",
            region: "primary-us-east",
            accepted_traffic: "interactive API and protocol enrollment",
            mutation_fence: "idempotency record plus tenant-scoped transaction",
            event_append: "certificate.issued appended before projection",
            outbox_mode: "connector delivery queued in transactional outbox",
            signer_mode: "isolated signer pool",
            backpressure_signal: "lifecycle queue saturation",
            recovery: "duplicate request returns idempotent result",
          },
          {
            id: "issue-region-b",
            region: "secondary-us-west",
            accepted_traffic: "same issuance APIs through regional ingress",
            mutation_fence: "same shared idempotency contract",
            event_append: "same replicated event stream",
            outbox_mode: "leader worker dispatches side effects",
            signer_mode: "isolated signer pool",
            backpressure_signal: "readyz degradation",
            recovery: "leader failover resumes workers",
          },
        ],
        failover_runbook: [
          { id: "verify", trigger: "traffic moved", action: "run synthetic issue and compare audit evidence", gate: "same result from every region" },
        ],
        release_gates: [
          { id: "regional-smoke", command: "regional smoke", artifact: "regional-issuance-smoke.json", required: true },
          { id: "failover-drill", command: "failover drill", artifact: "ha-failover-drill.json", required: true },
        ],
        rpo_seconds: 5,
        rto_seconds: 30,
        operator_actions: ["route only healthy regional ingress"],
        residuals: ["customer DNS and datastore promotion determine real RTO"],
        evidence_refs: ["internal/perf/contract.go"],
        architecture_invariants: ["AN-1", "AN-2", "AN-4", "AN-5", "AN-6", "AN-7", "AN-8"],
      }),
    );

    const result = await api.activeActiveIssuance();

    expect(result.capability).toBe("CAP-SCALE-02");
    expect(result.regions.length).toBeGreaterThanOrEqual(2);
    expect(result.tenant_write_fences.map((fence) => fence.id)).toContain("idempotency");
    expect(result.release_gates.map((gate) => gate.id)).toContain("regional-smoke");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/scale/ha-issuance");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });
});

describe("response integration dispatch contract", () => {
  it("dispatches response integrations with idempotency", async () => {
    mockFetch(
      202,
      JSON.stringify({
        id: "response-1",
        tenant_id: "tenant-1",
        status: "queued",
        idempotency_key: "evt-response",
        created_at: "2026-06-29T00:00:00Z",
        destinations: [
          { id: "splunk", provider: "splunk", destination: "response.splunk", status: "queued", outbox_id: 1, idempotency_key: "evt-response:splunk" },
        ],
      }),
    );

    await api.dispatchResponseIntegrations({
      title: "Contain compromised credential",
      severity: "critical",
      destinations: [
        {
          id: "splunk",
          provider: "splunk",
          endpoint_url: "https://splunk.example/services/collector",
          token_ref: "splunk-response-token",
        },
      ],
    });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/incidents/response-integrations/dispatch");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(lastSentHeaders()["Idempotency-Key"]).toMatch(/^idem-|[0-9a-f-]{36}/);
  });
});

describe("risk query contract", () => {
  it("fetches NHI over-privilege posture from the served CAP-POST-01 route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-POST-01",
        generated_at: "2026-06-29T00:00:00Z",
        coverage: ["managed_identities", "discovery_findings", "usage_driven_scope_delta", "least_privilege_recommendations"],
        summary: {
          total_analyzed: 0,
          overprivileged: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          least_privilege_plans: 0,
          unused_grants: 0,
          wildcard_grants: 0,
        },
        findings: [],
      }),
    );

    await api.nhiOverPrivilegePosture();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/nhi/posture/overprivilege");
  });

  it("fetches stale, unused, orphaned, and dormant NHI posture from the served CAP-POST-02 route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-POST-02",
        generated_at: "2026-06-29T00:00:00Z",
        coverage: ["managed_identities", "discovery_findings", "stale_activity", "unused_no_activity", "orphaned_detection", "dormant_detection"],
        thresholds: { stale_activity_days: 90, dormant_activity_days: 365, unused_no_activity_days: 90 },
        summary: { total_analyzed: 0, findings: 0, stale: 0, dormant: 0, unused: 0, orphaned: 0, critical: 0, high: 0, medium: 0, low: 0, recommendations: 0 },
        findings: [],
      }),
    );

    await api.nhiStalePosture();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/nhi/posture/stale");
  });

  it("fetches long-lived and static NHI credential posture from the served CAP-POST-03 route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-POST-03",
        generated_at: "2026-06-29T00:00:00Z",
        coverage: ["managed_identities", "discovery_findings", "long_lived_credentials", "static_credential_detection", "no_expiry_detection", "rotation_age"],
        thresholds: { long_lived_credential_days: 365, rotation_overdue_days: 180, no_expiry_minimum_age_days: 90 },
        summary: {
          total_analyzed: 0,
          findings: 0,
          long_lived: 0,
          static_credentials: 0,
          no_expiry: 0,
          rotation_overdue: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          recommendations: 0,
        },
        findings: [],
      }),
    );

    await api.nhiStaticPosture();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/nhi/posture/static-credentials");
  });

  it("fetches internet-exposed and insecurely deployed NHI posture from the served CAP-POST-04 route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-POST-04",
        generated_at: "2026-06-30T00:00:00Z",
        coverage: ["managed_identities", "discovery_findings", "internet_exposure", "insecure_transport", "weak_authentication", "network_policy"],
        summary: {
          total_analyzed: 0,
          findings: 0,
          internet_exposed: 0,
          insecure_transport: 0,
          weak_authentication: 0,
          public_callbacks: 0,
          missing_network_policy: 0,
          wildcard_reachability: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          recommendations: 0,
        },
        findings: [],
      }),
    );

    await api.nhiExposurePosture();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/nhi/posture/exposure");
  });

  it("fetches contextual blast-radius risk priorities from the served CAP-POST-05 route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-POST-05",
        generated_at: "2026-06-29T00:00:00Z",
        coverage: ["credential_risk_scores", "graph_blast_radius", "resource_reachability", "cbom_crypto_context", "owner_and_rotation_context"],
        summary: {
          total_analyzed: 0,
          priorities: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          high_blast_radius: 0,
          weak_crypto_context: 0,
          orphaned: 0,
          near_expiry: 0,
          recommendations: 0,
        },
        priorities: [],
      }),
    );

    await api.contextualRiskPriorities();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/risk/contextual-priorities");
  });

  it("does not pin risk to score and sends only requested server-side filters", async () => {
    mockFetch(200, JSON.stringify({ credentials: [] }));

    await api.risk();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/risk/credentials");

    mockFetch(200, JSON.stringify({ credentials: [] }));

    await api.risk({ sort: "expiry", minScore: 70, privilege: 3, owner: "platform" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/risk/credentials?sort=expiry&min_score=70&privilege=3&owner=platform");
  });
});

describe("profile contract", () => {
  it("fetches a concrete profile version by encoded name and number", async () => {
    mockFetch(
      200,
      JSON.stringify({
        id: "profile-1",
        name: "web/server",
        version: 2,
        active: true,
        spec: { max_validity: "2160h" },
      }),
    );

    await api.getProfileVersion("web/server", 2);

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/profiles/web%2Fserver/versions/2");
  });
});

describe("audit contract", () => {
  it("passes served audit filters through the event query", async () => {
    mockFetch(200, JSON.stringify({ events: [] }));

    await api.auditEvents({
      type: "identity.issued",
      since: "2026-06-17T00:00:00Z",
      until: "2026-06-18T00:00:00Z",
      asOf: 42,
      q: "payments",
      limit: 25,
    });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe(
      "/api/v1/audit/events?limit=25&type=identity.issued&since=2026-06-17T00%3A00%3A00Z&until=2026-06-18T00%3A00%3A00Z&as_of=42&q=payments",
    );
  });

  it("exports signed evidence for the same served audit filter shape", async () => {
    mockFetch(200, JSON.stringify({ format: "jws", bundle: "sealed.bundle" }));

    await api.exportAudit({ type: "identity.revoked", q: "revoked", limit: 10 });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/audit/export?limit=10&type=identity.revoked&q=revoked");
  });
});

describe("graph contract", () => {
  it("fetches reachable graph nodes by URL-safe id", async () => {
    mockFetch(200, JSON.stringify({ from: "cert/unsafe", nodes: [] }));

    await api.graphReachable("cert/unsafe");

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/graph/reachable/cert%2Funsafe");
  });

  it("posts read-only graph queries without an Idempotency-Key", async () => {
    document.cookie = "trstctl_csrf=csrf-token-graph; path=/";
    mockFetch(200, JSON.stringify({ rows: [{ name: "payments" }] }));

    await api.graphQuery("MATCH (a)-[e]->(b) RETURN a,b");

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/graph/query");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(JSON.parse(vi.mocked(fetch).mock.calls[0][1]?.body as string)).toEqual({
      query: "MATCH (a)-[e]->(b) RETURN a,b",
    });
    expect((vi.mocked(fetch).mock.calls[0][1]?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-token-graph");
    expect((vi.mocked(fetch).mock.calls[0][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeUndefined();
  });
});
