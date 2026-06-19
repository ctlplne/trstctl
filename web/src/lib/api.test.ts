import { describe, it, expect, vi, afterEach } from "vitest";
import { api, ApiError, UnauthorizedError } from "@/lib/api";

// Unit tests for the typed REST client's error handling, focused on the SURFACE-007
// 429/Retry-After path. We stub global fetch so no network is touched.

function mockFetch(status: number, body: string, headers: Record<string, string> = {}) {
  const h = new Headers(headers);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(status === 204 ? null : body, { status, headers: h }),
    ),
  );
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

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe(
      "/api/v1/certificates?limit=5&cursor=cursor-1&expiring_before=2026-07-01T00%3A00%3A00.000Z",
    );
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

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe(
      "/api/v1/audit/export?limit=10&type=identity.revoked&q=revoked",
    );
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
