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
  it("loads the current caller's server-derived capability posture", async () => {
    mockFetch(
      200,
      JSON.stringify({
        schema_version: 2,
        contract_schema_version: 3,
        license: { tier: "community", state: "community" },
        enforcement_note: "checked again at execution",
        operations: [],
        items: [],
      }),
    );
    const result = await api.capabilities();
    expect(result.schema_version).toBe(2);
    expect(vi.mocked(fetch).mock.calls[0]?.[0]).toBe("/api/v1/capabilities");
    expect(vi.mocked(fetch).mock.calls[0]?.[1]?.method).toBeUndefined();
  });

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

describe("first-class issuance requests (AUD-78)", () => {
  it("posts an effect-free preview without an Idempotency-Key", async () => {
    mockFetch(
      200,
      JSON.stringify({
        ready: true,
        subject: "payments-api",
        owner_id: "11111111-1111-4111-8111-111111111119",
        owner_name: "Payments platform",
        profile: "web-server:2",
        profile_name: "web-server",
        profile_version: 2,
        requester: "oidc|dev-1",
        csr_supplied: true,
        key_origin: "requester_csr",
        approval_required: true,
        approval_permission: "certs:issue",
        issuance_permissions: ["identities:write", "certs:issue"],
        preview_writes: [],
        preview_external_effects: [],
        submission_effects: ["Append one request event."],
        steps: ["Submit request", "Independent approval"],
        warnings: [],
        blockers: [],
        guidance: "This preview performed no write and contacted no certificate authority.",
      }),
    );

    await api.previewIssuanceRequest({
      subject: "payments-api",
      owner_id: "11111111-1111-4111-8111-111111111119",
      profile: "web-server:2",
      csr_pem: "public-csr",
      origin: "console",
    });

    const call = vi.mocked(fetch).mock.calls[0];
    expect(call[0]).toBe("/api/v1/issuance-requests/preview");
    expect(call[1]?.method).toBe("POST");
    expect(lastSentHeaders()["Idempotency-Key"]).toBeUndefined();
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({
      subject: "payments-api",
      owner_id: "11111111-1111-4111-8111-111111111119",
      profile: "web-server:2",
      csr_pem: "public-csr",
    });
  });

  it("posts the selected owner UUID through the idempotent request mutation", async () => {
    document.cookie = "trstctl_csrf=csrf-request; path=/";
    mockFetch(
      201,
      JSON.stringify({
        id: "request-1",
        tenant_id: "11111111-1111-4111-8111-111111111111",
        subject: "payments-api",
        owner_id: "11111111-1111-4111-8111-111111111119",
        requester: "oidc|dev-1",
        status: "requested",
        expires_at: "2026-08-20T00:00:00Z",
        created_at: "2026-08-13T00:00:00Z",
      }),
    );

    await api.createIssuanceRequest({
      subject: "payments-api",
      owner_id: "11111111-1111-4111-8111-111111111119",
      profile: "web-server:2",
      origin: "console",
    });

    const call = vi.mocked(fetch).mock.calls[0];
    expect(call[0]).toBe("/api/v1/issuance-requests");
    expect(call[1]?.method).toBe("POST");
    expect(lastSentHeaders()["X-CSRF-Token"]).toBe("csrf-request");
    expect(lastSentHeaders()["Idempotency-Key"]).toBeTruthy();
    expect(JSON.parse(String(call[1]?.body))).toEqual({
      subject: "payments-api",
      owner_id: "11111111-1111-4111-8111-111111111119",
      profile: "web-server:2",
      origin: "console",
    });
  });

  it("uses one stable request-derived key across prepare, guarded issue, and completion", async () => {
    mockFetchSequence([
      {
        status: 200,
        body: JSON.stringify({
          request: { id: "request-1", status: "approved" },
          identity: { id: "identity-1", status: "requested" },
          csr_pem: "public-csr",
          issue_idempotency_key: "issuance-request-issue:request-1",
        }),
      },
      { status: 200, body: JSON.stringify({ id: "identity-1", status: "issued" }) },
      { status: 200, body: JSON.stringify({ id: "request-1", status: "issued" }) },
    ]);

    const prepared = await api.prepareIssuanceRequest("request-1");
    await api.transitionIdentity(
      prepared.identity.id,
      "issued",
      "fulfill approved issuance request request-1",
      prepared.csr_pem,
      prepared.issue_idempotency_key,
    );
    await api.completeIssuanceRequest("request-1");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.map((call) => call[0])).toEqual([
      "/api/v1/issuance-requests/request-1/prepare",
      "/api/v1/identities/identity-1/transitions",
      "/api/v1/issuance-requests/request-1/complete",
    ]);
    expect((calls[0][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBe("issuance-request-prepare:request-1");
    expect((calls[1][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBe("issuance-request-issue:request-1");
    expect((calls[2][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBe("issuance-request-complete:request-1");
  });
});

describe("certificate-profile recovery (F53)", () => {
  it("keeps preview effect-free and confirmation idempotent on the exact version path", async () => {
    document.cookie = "trstctl_csrf=csrf-profile-restore; path=/";
    mockFetchSequence([
      {
        status: 200,
        body: JSON.stringify({
          capability: "certificate_profile_recovery",
          operation: "restore_as_new_version",
          ready: true,
          name: "web-server",
          source_version: 1,
          active_version: 2,
          next_version: 3,
          preview_writes: [],
          preview_external_effects: [],
        }),
      },
      { status: 201, body: JSON.stringify({ id: "profile-v3", name: "web-server", version: 3, active: true, spec: {} }) },
    ]);
    const input = { expected_active_version: 2, reason: "Recover the known-good web TLS rule" };

    await api.previewProfileRestore("web-server", 1, input);
    const previewCall = vi.mocked(fetch).mock.calls[0];
    expect(previewCall[0]).toBe("/api/v1/profiles/web-server/versions/1/restore/preview");
    expect(previewCall[1]?.method).toBe("POST");
    expect((previewCall[1]?.headers as Record<string, string>)?.["Idempotency-Key"]).toBeUndefined();
    expect(JSON.parse(String(previewCall[1]?.body))).toEqual(input);

    await api.restoreProfileVersion("web-server", 1, input);
    const restoreCall = vi.mocked(fetch).mock.calls[1];
    expect(restoreCall[0]).toBe("/api/v1/profiles/web-server/versions/1/restore");
    expect(restoreCall[1]?.method).toBe("POST");
    expect((restoreCall[1]?.headers as Record<string, string>)?.["X-CSRF-Token"]).toBe("csrf-profile-restore");
    expect((restoreCall[1]?.headers as Record<string, string>)?.["Idempotency-Key"]).toBeTruthy();
    expect(JSON.parse(String(restoreCall[1]?.body))).toEqual(input);
  });
});

describe("enrollment diagnostic verification (AUD-49)", () => {
  it("posts the exact diagnostic route with an Idempotency-Key", async () => {
    mockFetch(
      202,
      JSON.stringify({
        diagnostic_id: "diag/unsafe id",
        verification_endpoint_id: "verify-1",
        status: "queued",
        queued_at: "2026-08-13T04:00:00Z",
        result_path: "/api/v1/endpoints/verifications/verify-1",
      }),
    );

    await api.proveEnrollmentDiagnosticFixed("diag/unsafe id");

    const call = vi.mocked(fetch).mock.calls[0];
    expect(call[0]).toBe("/api/v1/enrollment/diagnostics/diag%2Funsafe%20id/prove-fixed");
    expect(call[1]?.method).toBe("POST");
    expect((call[1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
  });
});

describe("CA migration execution contract (AUD-40)", () => {
  it("keeps assessment read-only and sends idempotent run controls to exact paths", async () => {
    const run = { id: "run-1", status: "running", waves: [] };
    mockFetchSequence([
      { status: 200, body: JSON.stringify({ plan_id: "plan-1", members: 1, migratable: 1, guidance: "ready", unknowns: [], waves: [] }) },
      { status: 201, body: JSON.stringify(run) },
      { status: 200, body: JSON.stringify({ items: [run] }) },
      { status: 200, body: JSON.stringify({ ...run, status: "paused" }) },
      { status: 200, body: JSON.stringify(run) },
      { status: 200, body: JSON.stringify({ ...run, status: "rolling_back" }) },
    ]);
    const request = {
      plan_id: "plan-1",
      new_authority_id: "40400000-0000-4000-8000-000000000042",
      waves: [
        {
          id: "canary",
          ordinal: 1,
          members: [{ identity_id: "identity-1", agent_id: "40400000-0000-4000-8000-000000000040", trust_anchor_path: "/etc/trstctl/next.pem" }],
        },
      ],
    };

    await api.assessMigration({ plan_id: "plan-1", waves: [] });
    await api.startMigrationRun(request);
    await api.migrationRuns();
    await api.pauseMigrationRun("run-1");
    await api.resumeMigrationRun("run-1");
    await api.rollbackMigrationRun("run-1");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.map((call) => call[0])).toEqual([
      "/api/v1/migrations/assess",
      "/api/v1/migrations/runs",
      "/api/v1/migrations/runs",
      "/api/v1/migrations/runs/run-1/pause",
      "/api/v1/migrations/runs/run-1/resume",
      "/api/v1/migrations/runs/run-1/rollback",
    ]);
    expect((calls[0][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeUndefined();
    for (const index of [1, 3, 4, 5]) {
      expect((calls[index][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
    }
    expect(calls[2][1]?.method).toBeUndefined();
  });
});

describe("approval request contract (AUD-77)", () => {
  it("lists pending intents and approves by immutable request id plus digest", async () => {
    document.cookie = "trstctl_csrf=csrf-approval; path=/";
    mockFetchSequence([
      {
        status: 200,
        body: JSON.stringify({
          items: [
            {
              id: "approval/request-1",
              intent_digest: "sha256:8ec59a9c",
              resource_id: "identity-1",
              resource_name: "payments-api",
              resource_kind: "identity",
              action: "issue",
              requester: "requester@example.test",
              target_version: "transition:0",
              evidence_refs: [],
              approval_count: 0,
              required_approvals: 2,
              status: "pending",
              created_at: "2026-08-10T12:00:00Z",
              expires_at: "2026-08-10T12:15:00Z",
            },
          ],
        }),
      },
      {
        status: 200,
        body: JSON.stringify({ id: "approval/request-1", status: "pending", approval_count: 1, required_approvals: 2 }),
      },
    ]);

    const requests = await api.approvalRequests();
    await api.approveApprovalRequest(requests[0].id, requests[0].intent_digest);

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls[0][0]).toBe("/api/v1/approval-requests?status=pending&limit=100");
    expect(calls[1][0]).toBe("/api/v1/approval-requests/approval%2Frequest-1/approvals");
    expect(calls[1][1]?.method).toBe("POST");
    expect(JSON.parse(calls[1][1]?.body as string)).toEqual({ intent_digest: "sha256:8ec59a9c" });
    expect((calls[1][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
  });

  it("follows every approval queue cursor and posts immutable denials", async () => {
    document.cookie = "trstctl_csrf=csrf-approval; path=/";
    mockFetchSequence([
      {
        status: 200,
        body: JSON.stringify({
          items: [{ id: "request-1", intent_digest: "sha256:1", status: "pending" }],
          next_cursor: "page-2",
        }),
      },
      {
        status: 200,
        body: JSON.stringify({
          items: [{ id: "request-2", intent_digest: "sha256:2", status: "pending" }],
        }),
      },
      {
        status: 200,
        body: JSON.stringify({ id: "request-2", status: "denied", approval_count: 0, required_approvals: 2 }),
      },
    ]);

    const requests = await api.approvalRequests();
    await api.denyApprovalRequest(requests[1].id, requests[1].intent_digest, "unsafe rollout window");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls[0][0]).toBe("/api/v1/approval-requests?status=pending&limit=100");
    expect(calls[1][0]).toBe("/api/v1/approval-requests?status=pending&limit=100&cursor=page-2");
    expect(calls[2][0]).toBe("/api/v1/approval-requests/request-2/denials");
    expect(calls[2][1]?.method).toBe("POST");
    expect(JSON.parse(calls[2][1]?.body as string)).toEqual({
      intent_digest: "sha256:2",
      reason: "unsafe rollout window",
    });
  });

  it("keeps legacy secret and ephemeral decisions bound to an exact served request", async () => {
    document.cookie = "trstctl_csrf=csrf-approval; path=/";
    mockFetchSequence([
      { status: 200, body: JSON.stringify({ resource: "secret:app/db", action: "rotate", approver: "ra", approvals: 1 }) },
      {
        status: 200,
        body: JSON.stringify({
          id: "019fec49-6641-7131-ae7f-17f7ea4b5e02",
          intent_digest: "sha256:ephemeral-issue",
          resource: "ephemeral-1",
          action: "issue",
          approver: "ra",
          approvals: 1,
          approval_count: 1,
          required_approvals: 1,
          status: "approved",
        }),
      },
    ]);

    await api.approveSecretChange("app/db", {
      action: "rotate",
      request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e01",
      intent_digest: "sha256:secret-rotate",
    });
    await api.approveEphemeralCredential("019fec49-6641-7131-ae7f-17f7ea4b5e02", {
      action: "issue",
      request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e02",
      intent_digest: "sha256:ephemeral-issue",
    });

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls[0][0]).toBe("/api/v1/secrets/store/approvals/app%2Fdb");
    expect(JSON.parse(calls[0][1]?.body as string)).toEqual({
      action: "rotate",
      request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e01",
      intent_digest: "sha256:secret-rotate",
    });
    expect(calls[1][0]).toBe("/api/v1/ephemeral/019fec49-6641-7131-ae7f-17f7ea4b5e02/approvals");
    expect(JSON.parse(calls[1][1]?.body as string)).toEqual({
      action: "issue",
      request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e02",
      intent_digest: "sha256:ephemeral-issue",
    });
  });

  it("keeps the identity compatibility decision bound to the reviewed request", async () => {
    document.cookie = "trstctl_csrf=csrf-approval; path=/";
    mockFetch(
      200,
      JSON.stringify({
        id: "019fec49-6641-7131-ae7f-17f7ea4b5e03",
        intent_digest: "sha256:identity-rotate",
        resource: "identity-1",
        action: "rotate",
        approver: "ra",
        approvals: 1,
        approval_count: 1,
        required_approvals: 2,
        status: "pending",
      }),
    );

    await api.approveIdentityAction("identity-1", {
      action: "rotate",
      request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e03",
      intent_digest: "sha256:identity-rotate",
    });

    const call = vi.mocked(fetch).mock.calls[0];
    expect(call[0]).toBe("/api/v1/identities/identity-1/approvals");
    expect(call[1]?.method).toBe("POST");
    expect(JSON.parse(call[1]?.body as string)).toEqual({
      action: "rotate",
      request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e03",
      intent_digest: "sha256:identity-rotate",
    });
    expect((call[1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
  });
});

describe("exported API surface census", () => {
  it("drives every operation through the bounded same-origin transport and preserves mutation idempotency", async () => {
    document.cookie = "trstctl_csrf=csrf-census; path=/";
    // The census deliberately executes the streaming audit-download method as
    // well as JSON API calls. jsdom has no navigation/download implementation,
    // so pin the browser handoff without letting its temporary anchor navigate.
    const downloadClick = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const transport = vi.fn(async (target: RequestInfo | URL, init?: RequestInit) => {
      void target;
      void init;
      return new Response(
        JSON.stringify({
          id: "result-id",
          items: [],
          agents: [],
          events: [],
          protocols: [],
          status: "ok",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", transport);

    const optionBag = {
      limit: 2,
      cursor: "next/cursor",
      identityId: "identity/id",
      issuerId: "issuer/id",
      ownerId: "owner/id",
      playbookId: "playbook/id",
      runId: "run/id",
      subjectRef: "subject/ref",
      subject: "subject/ref",
      status: "pending",
      resolve: true,
      includeOffboarded: true,
      includeRevoked: true,
      expiringBefore: "2026-12-31T00:00:00Z",
    };
    const universalInput = {
      ...optionBag,
      id: "item/id",
      name: "service.example.test",
      ownerId: "owner/id",
      issuerId: "issuer/id",
      wildcardBlastRadiusAcknowledged: false,
      toString: () => "item/id",
      [Symbol.toPrimitive]: () => "item/id",
    };
    type GenericOperation = (...args: unknown[]) => Promise<unknown>;

    for (const [name, member] of Object.entries(api)) {
      const before = transport.mock.calls.length;
      const operation = member as unknown as GenericOperation;
      await expect(operation(universalInput, optionBag, "operator reason"), `api.${name}`).resolves.not.toBeUndefined();
      expect(transport.mock.calls.length, `api.${name} bypassed the shared fetch seam`).toBeGreaterThan(before);
    }

    expect(downloadClick).toHaveBeenCalledOnce();
    const downloadAnchor = downloadClick.mock.instances[0] as HTMLAnchorElement;
    expect(downloadAnchor.download).toBe("trstctl-audit.ndjson");
    expect(downloadAnchor.href).toMatch(/^blob:/);

    const readOnlyPosts = new Set([
      // H2: assess enumerates what a migration WOULD touch and writes nothing.
      // It is a POST only because the plan travels as a body; requiring an
      // idempotency key would imply a side effect it does not have.
      "/api/v1/migrations/assess",
      "/api/v1/agents/enrollment-tokens/preview",
      "/api/v1/issuance-requests/preview",
      "/api/v1/identities/item%2Fid/transitions/preview",
      // F56: the MDM policy and challenge-rotation planners run the same
      // readiness logic as execution but make no write, outside, or signer call.
      "/api/v1/mdm/scep/policies/preview",
      "/api/v1/mdm/scep/policies/item%2Fid/preview",
      "/api/v1/mdm/scep/policies/item%2Fid/rotate-challenge/preview",
      // F9: audit feed preview shares the execution validator but performs no
      // write, idempotency insert, outbox enqueue, credential read, or egress.
      "/api/v1/audit/feeds/item%2Fid/preview",
      "/api/v1/ca/ceremonies/preview",
      "/api/v1/ca/authorities/item%2Fid/rotate/preview",
      "/api/v1/managed-keys/preview",
      // F55: this POST reads assembled in-memory CMP posture. It carries no
      // body and performs no enrollment, write, signer call, or network call.
      "/api/v1/protocols/cmp/qualification",
      "/api/v1/ai/query",
      "/api/v1/ai/rca",
      "/api/v1/graph/query",
      "/api/v1/mcp/tools/item%2Fid",
      "/api/v1/pqc/migrations/plan",
      "/api/v1/privacy/subject-exports",
    ]);
    for (const [target, init] of transport.mock.calls) {
      const url = String(target);
      expect(url, "the browser API client attempted absolute egress").toMatch(/^\//);
      const method = init?.method ?? "GET";
      const headers = init?.headers as Record<string, string> | undefined;
      // F22's EST qualification POST is a negative control, not enrollment:
      // credentials are omitted, no CSR body exists, and a fail-closed 401 is
      // the only passing result. If a future caller adds any enrollment input,
      // it falls back under the mutation idempotency and CSRF requirements.
      const credentialFreeESTAuthProbe =
        url === "/.well-known/est/simpleenroll" && init?.credentials === "omit" && init?.body == null && headers?.Authorization == null;
      // F23's SCEP qualification POST is also a negative control. It is
      // read-only only at this exact route with cookie credentials omitted,
      // an absent body and Authorization header, and the SCEP wire MIME. Any
      // future request content falls back under the mutation protections.
      const credentialFreeSCEPEmptyProbe =
        url === "/scep?operation=PKIOperation" &&
        init?.credentials === "omit" &&
        init?.body == null &&
        headers?.Authorization == null &&
        headers?.["Content-Type"] === "application/x-pki-message";
      const readOnlyPost = readOnlyPosts.has(url) || url.endsWith("/restore/preview") || credentialFreeESTAuthProbe || credentialFreeSCEPEmptyProbe;
      if ((method === "POST" || method === "PUT" || method === "DELETE") && url !== "/auth/logout" && !readOnlyPost) {
        expect(headers?.["Idempotency-Key"], `${method} ${url} lacks mutation idempotency`).toBeTruthy();
        expect(headers?.["X-CSRF-Token"], `${method} ${url} lacks the session CSRF echo`).toBe("csrf-census");
      }
    }
  });
});

describe("eval protocol profile client", () => {
  it("reads and durably activates the served first-run profile", async () => {
    document.cookie = "trstctl_csrf=csrf-protocols; path=/";
    mockFetchSequence([
      { status: 200, body: JSON.stringify({ profile: "eval", active: false, protocols: ["acme", "est"] }) },
      { status: 200, body: JSON.stringify({ profile: "eval", active: true, protocols: ["acme", "est"] }) },
    ]);

    expect((await api.protocolProfileStatus()).active).toBe(false);
    expect((await api.activateProtocolProfile()).active).toBe(true);

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls[0][0]).toBe("/api/v1/setup/protocols");
    expect(calls[0][1]?.method).toBeUndefined();
    expect(calls[1][0]).toBe("/api/v1/setup/protocols/activate");
    expect(calls[1][1]?.method).toBe("POST");
    const headers = calls[1][1]?.headers as Record<string, string>;
    expect(headers["Idempotency-Key"]).toBeTruthy();
    expect(headers["X-CSRF-Token"]).toBe("csrf-protocols");
  });
});

describe("protocol responder truth (AUD-75)", () => {
  it("refuses a successful console document for every machine-protocol probe", async () => {
    const consoleHTML = '<!doctype html><html><body><div id="root"></div></body></html>';
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(consoleHTML, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } })),
    );

    const statuses = await api.protocolStatuses();

    expect(statuses.items).toHaveLength(6);
    for (const status of statuses.items) {
      expect(status.enabled, status.protocol).toBe(false);
      expect(status.served, status.protocol).toBe(false);
      expect(status.status_code, status.protocol).toBe(200);
      expect(status.detail, status.protocol).toMatch(/unexpected responder content/i);
    }
  });

  it("accepts only each responder's protocol-specific status, MIME, and body", async () => {
    const responses = new Map<string, () => Response>([
      [
        "/directory",
        () =>
          new Response(
            JSON.stringify({
              newNonce: "https://trstctl.example.test/acme/new-nonce",
              newAccount: "https://trstctl.example.test/acme/new-account",
              newOrder: "https://trstctl.example.test/acme/new-order",
              keyChange: "https://trstctl.example.test/acme/key-change",
              revokeCert: "https://trstctl.example.test/acme/revoke-cert",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
      ],
      [
        "/.well-known/est/cacerts",
        () =>
          new Response("MAA=\n", {
            status: 200,
            headers: { "Content-Type": "application/pkcs7-mime; smime-type=certs-only", "Content-Transfer-Encoding": "base64" },
          }),
      ],
      [
        "/scep?operation=GetCACaps",
        () => new Response("POSTPKIOperation\nSHA-256\nSCEPStandard\n", { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } }),
      ],
      ["/cmp", () => new Response("cmp: POST required (RFC 6712)\n", { status: 405, headers: { "Content-Type": "text/plain; charset=utf-8" } })],
      [
        "/ssh/ca",
        () =>
          new Response("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownPublicOnlyKey trstctl-ssh-ca\n", {
            status: 200,
            headers: { "Content-Type": "text/plain; charset=utf-8" },
          }),
      ],
      ["/tsa", () => new Response("method not allowed\n", { status: 405, headers: { Allow: "POST", "Content-Type": "text/plain; charset=utf-8" } })],
    ]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (target: RequestInfo | URL) => {
        const response = responses.get(String(target));
        if (!response) throw new Error(`unexpected protocol probe ${String(target)}`);
        return response();
      }),
    );

    const statuses = await api.protocolStatuses();

    expect(statuses.items.map((status) => [status.protocol, status.served, status.status_code])).toEqual([
      ["acme", true, 200],
      ["est", true, 200],
      ["scep", true, 200],
      ["cmp", true, 405],
      ["ssh", true, 200],
      ["tsa", true, 405],
    ]);
  });
});

describe("licensed PQC migration client", () => {
  const input = {
    asset_ids: ["asset-1"],
    target_algorithm: "ML-DSA-65" as const,
    protocol: "acme" as const,
    rollback_on_failure: true,
  };

  it("keeps plan preview read-only and puts Idempotency-Key on start and rollback", async () => {
    mockFetchSequence([
      { status: 200, body: JSON.stringify({ reissues: [], tls_rollouts: [], residuals: [], reissue_count: 0, tls_rollout_count: 0 }) },
      {
        status: 202,
        body: JSON.stringify({
          run_id: "run-1",
          queued: 1,
          certificate_reissues_queued: 1,
          tls_findings_queued: 0,
          target_algorithm: "ML-DSA-65",
          effective_algorithm: "hybrid",
          protocol: "acme",
          rollback_configured: true,
          migration_progress: {},
          queued_at: "2026-07-27T12:00:00Z",
        }),
      },
      { status: 200, body: JSON.stringify({ run_id: "run-1", total: 1, queued: 1, applied: 0, failed: 0, rolled_back: 0, findings: [] }) },
      {
        status: 202,
        body: JSON.stringify({ run_id: "run-1", queued: 1, reason: "operator rollback", migration_progress: {}, queued_at: "2026-07-27T12:01:00Z" }),
      },
    ]);

    await api.planPQCMigration(input);
    await api.startPQCMigration(input);
    await api.getPQCMigrationProgress("run-1");
    await api.rollbackPQCMigration("run-1", ["asset-1"], "operator rollback");

    const calls = vi.mocked(fetch).mock.calls;
    expect(calls.map((call) => call[0])).toEqual([
      "/api/v1/pqc/migrations/plan",
      "/api/v1/pqc/migrations",
      "/api/v1/pqc/migrations/run-1",
      "/api/v1/pqc/migrations/run-1/rollback",
    ]);
    expect((calls[0][1]?.headers as Record<string, string>)["Idempotency-Key"]).toBeUndefined();
    expect((calls[1][1]?.headers as Record<string, string>)["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
    expect(calls[2][1]?.method).toBeUndefined();
    expect((calls[3][1]?.headers as Record<string, string>)["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
  });
});

describe("api compliance evidence packs", () => {
  it("reads framework evidence packs from the served compliance route", async () => {
    mockFetch(
      200,
      JSON.stringify({
        format: "trstctl.compliance.evidence-pack.v4",
        framework: "soc2",
        signed_export: { manifest: { framework: "soc2", controls: [] }, signature: "sig" },
        public_key_der: "BASE64PUBLICKEY",
        custody: {
          total: 0,
          recorded: 0,
          unrecorded: 0,
          origins: { requester: 0, host_agent: 0, device: 0, control_plane: 0, signer: 0 },
          storage: { locked_memory: 0, file: 0, os_store: 0, pkcs11: 0, device_bound: 0, service: 0 },
          exportability: { exportable: 0, non_exportable: 0 },
          unrecorded_certificates: [],
        },
        adcs: { observations: [], drift: [] },
      }),
    );

    const pack = await api.complianceEvidencePack("soc2");

    expect(pack.framework).toBe("soc2");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/compliance/evidence-packs/soc2");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });

  it("fetches signed CRL and OCSP endpoint health from the served route", async () => {
    mockFetch(200, JSON.stringify({ observed: true, summary: { endpoints: 1, fresh: 1 }, items: [], guidance: "Verify clients." }));

    const result = await api.revocationHealth();

    expect(result.observed).toBe(true);
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/revocation/health");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });

  it("fetches signed per-segment CRL and OCSP cache posture without mutation headers", async () => {
    mockFetch(
      200,
      JSON.stringify({
        observed: true,
        summary: { caches: 1, fresh: 1, stale: 0, empty: 0, error: 0 },
        items: [{ cache_id: "issuer-a", segment: "plant-7", protocol: "ocsp", metadata_only: true }],
        guidance: "Signed relay metadata only.",
      }),
    );

    const result = await api.revocationCaches();

    expect(result.items[0]?.metadata_only).toBe(true);
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/revocation/caches");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
    expect((vi.mocked(fetch).mock.calls[0][1]?.headers as Record<string, string> | undefined)?.["Idempotency-Key"]).toBeUndefined();
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
      expect((call[1]?.headers as Record<string, string>)["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
  });

  it("uses a distinct Idempotency-Key for each identity transition mutation", async () => {
    document.cookie = "trstctl_csrf=csrf-token-bulk; path=/";
    mockFetch(202, JSON.stringify({ id: "id-1", name: "svc", status: "revoked" }));

    await api.transitionIdentity("id-1", "revoked", "bulk revoke via UI");
    await api.transitionIdentity("id-2", "revoked", "bulk revoke via UI");

    const calls = vi.mocked(fetch).mock.calls;
    const firstHeaders = calls[0][1]?.headers as Record<string, string>;
    const secondHeaders = calls[1][1]?.headers as Record<string, string>;
    expect(firstHeaders["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
    expect(secondHeaders["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
    expect(vi.mocked(fetch).mock.calls[0][1]?.body).toBeUndefined();
  });

  it("previews the trimmed agent grant without creating an idempotent mutation", async () => {
    document.cookie = "trstctl_csrf=csrf-token-agent-preview; path=/";
    mockFetch(
      200,
      JSON.stringify({
        ready: true,
        side_effects: false,
        allowed_identity: "edge-01",
        roles: ["host", "network"],
        required_permissions: ["agents:write", "agents:relay.grant"],
        enroll_path: "/enroll/bootstrap",
        agent_server: "agents.example.test:9443",
        agent_server_name: "agents.example.test",
        data_handling: "A one-time token is not minted or returned.",
        blocked_reasons: [],
      }),
    );

    const plan = await api.previewEnrollmentPlan({ allowed_identity: " edge-01 ", roles: ["host", "network"] });

    expect(plan.side_effects).toBe(false);
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/agents/enrollment-tokens/preview");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-agent-preview");
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toEqual({
      allowed_identity: "edge-01",
      roles: ["host", "network"],
    });
  });

  it("pins an enrollment token to the requested agent identity", async () => {
    document.cookie = "trstctl_csrf=csrf-token-agent-pin; path=/";
    mockFetch(201, JSON.stringify({ token: "BOOT-TOKEN-PINNED", enroll_path: "/enroll/bootstrap" }));

    await api.createEnrollmentToken({ allowed_identity: " node-a " });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/agents/enrollment-tokens");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("POST");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-token-agent-pin");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toEqual({ allowed_identity: "node-a" });
  });

  it("carries the agent role grant to the wire, not just to the client", async () => {
    // A2/A3 regression pin. The request builder once rebuilt the body from
    // allowed_identity alone, so the console's role selector minted host-only
    // tokens no matter what the operator chose — and the Agents page test could
    // not see it, because it asserts against a mocked api client. This test
    // asserts on the actual fetch body: the grant either reaches the wire here
    // or the relay role does not exist.
    document.cookie = "trstctl_csrf=csrf-token-agent-roles; path=/";
    mockFetch(201, JSON.stringify({ token: "BOOT-TOKEN-RELAY", enroll_path: "/enroll/bootstrap", roles: ["host", "network"] }));

    await api.createEnrollmentToken({ allowed_identity: "edge-f5-relay", roles: ["host", "network"] });

    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toEqual({
      allowed_identity: "edge-f5-relay",
      roles: ["host", "network"],
    });
  });

  it("sends a roles-only grant even with no pinned identity", async () => {
    document.cookie = "trstctl_csrf=csrf-token-agent-roles2; path=/";
    mockFetch(201, JSON.stringify({ token: "BOOT-TOKEN-NET", enroll_path: "/enroll/bootstrap", roles: ["network"] }));

    await api.createEnrollmentToken({ roles: ["network"] });

    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toEqual({ roles: ["network"] });
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
      expect(headers["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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

  it("adds wildcard DNS-01 acknowledgement attributes only after operator acknowledgement", () => {
    expect(firstCertificateIdentityRequest({ name: "*.payments.example" }, "owner-1")).toEqual({
      kind: "x509_certificate",
      name: "*.payments.example",
      owner_id: "owner-1",
    });
    expect(firstCertificateIdentityRequest({ name: "*.payments.example", wildcardBlastRadiusAcknowledged: true }, "owner-1")).toEqual({
      kind: "x509_certificate",
      name: "*.payments.example",
      owner_id: "owner-1",
      attributes: {
        validation_method: "dns-01",
        wildcard_blast_radius_acknowledged: true,
      },
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
    expect((calls[1][1]?.headers as Record<string, string>)["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
  });
});

describe("agent contract", () => {
  it("reads an exact agent page so topology callers can follow every cursor", async () => {
    mockFetch(200, JSON.stringify({ agents: [], next_cursor: "cursor-3" }));

    const page = await api.agentPage({ limit: 100, cursor: "cursor-2" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/agents?limit=100&cursor=cursor-2");
    expect(page.next_cursor).toBe("cursor-3");
  });

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
      {
        status: 200,
        body: JSON.stringify({
          newNonce: "/acme/new-nonce",
          newAccount: "/acme/new-account",
          newOrder: "/acme/new-order",
          keyChange: "/acme/key-change",
          revokeCert: "/acme/revoke-cert",
        }),
        headers: { "Content-Type": "application/json" },
      },
      { status: 404, body: "not mounted" },
      {
        status: 200,
        body: "POSTPKIOperation\nSHA-256\nSCEPStandard\n",
        headers: { "Content-Type": "text/plain" },
      },
      { status: 405, body: "cmp: POST required (RFC 6712)\n", headers: { "Content-Type": "text/plain" } },
      { status: 200, body: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnownPublicOnlyKey\n", headers: { "Content-Type": "text/plain" } },
      { status: 405, body: "method not allowed\n", headers: { "Content-Type": "text/plain", Allow: "POST" } },
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

  it("reports each bounded responder failure mode without treating it as served", async () => {
    const results: Array<Response | Error> = [
      new Response("", { status: 503 }),
      new Response("", { status: 401 }),
      new Response("", { status: 418, statusText: "Teapot" }),
      new Response("", { status: 418 }),
      new Error("offline"),
      new Response("", { status: 403 }),
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        const next = results.shift();
        if (next instanceof Error) throw next;
        if (!next) throw new Error("unexpected fetch call");
        return next;
      }),
    );

    const page = await api.protocolStatuses();

    expect(page.items.map((item) => item.detail)).toEqual([
      "Responder is mounted but currently unavailable.",
      "Responder rejected the browser session.",
      "Teapot",
      "Responder returned HTTP 418.",
      "Responder probe failed before an HTTP status was returned.",
      "Responder rejected the browser session.",
    ]);
    expect(page.items.every((item) => !item.served)).toBe(true);
  });

  it("keeps idempotency available when randomUUID is absent", async () => {
    document.cookie = "trstctl_csrf=csrf-fallback; path=/";
    vi.stubGlobal("crypto", {});
    mockFetch(201, JSON.stringify({ id: "owner-1" }));

    await api.createOwner({ kind: "team", name: "Platform" });

    expect(lastSentHeaders()["Idempotency-Key"]).toMatch(/^idem-\d+-[0-9a-f]+$/);
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

    await api.rotateSecret("app/db/password", { value: "new-value" });

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store/app%2Fdb%2Fpassword");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBe("PUT");
    expect(sentHeaders()["X-CSRF-Token"]).toBe("csrf-secret-rotate");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
  });

  it("verifies a secret read with only the workload bearer credential", async () => {
    mockFetch(200, JSON.stringify({ name: "app/db/password", value: "read-once", version: 3 }));

    await api.getSecretWithToken("app/db/password", "trst_workload_reveal_once");

    const call = vi.mocked(fetch).mock.calls[0];
    expect(call[0]).toBe("/api/v1/secrets/store/app%2Fdb%2Fpassword");
    expect(call[1]?.credentials).toBe("omit");
    expect((call[1]?.headers as Record<string, string>).Authorization).toBe("Bearer trst_workload_reveal_once");
  });

  it("reads cloud secret-manager integration posture without mutation headers", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-SEC-04",
        served: true,
        generated_at: "2026-06-29T00:00:00Z",
        summary: {
          total_providers: 4,
          discovery_supported: 4,
          discovery_configured: 4,
          sync_supported: 3,
          sync_configured: 3,
          fully_configured: 4,
          configured_connections: 7,
        },
        providers: [
          {
            id: "azure-key-vault",
            name: "Azure Key Vault",
            platform: "azure",
            discovery_supported: true,
            discovery_configured: true,
            discovery_source_kind: "cloud_secret",
            discovery_source_count: 1,
            discovery_read_ops: ["GET /secrets"],
            sync_supported: true,
            sync_configured: true,
            sync_target_id: "azure-key-vault",
            sync_write_operation: "PUT /secrets/{name}",
            secret_handling: "metadata only",
            capabilities: ["cloud-secret-manager"],
            evidence_refs: ["internal/discovery/cloudsecret/azurekv/azurekv.go"],
          },
        ],
        configured_providers: ["azure-key-vault"],
        configured_sync_targets: ["azure-key-vault"],
        discovery_mode: "read-only",
        outbox_mode: "sealed outbox",
        secret_handling: "metadata only",
        architecture_controls: ["AN-8"],
        evidence_refs: ["internal/api/secrets.go"],
        residuals: [],
        recommended_next_actions: [],
      }),
    );

    const posture = await api.cloudSecretManagers();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/cloud-secret-managers");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
    expect(posture.capability).toBe("CAP-SEC-04");
    expect(posture.providers[0].id).toBe("azure-key-vault");
    expect(JSON.stringify(posture)).not.toContain("secret-value");
  });

  it("reads workload secret-injection posture without mutation headers", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-SECR-05",
        served: true,
        generated_at: "2026-06-30T00:00:00Z",
        crd: {
          kind: "TrstctlSecretInjection",
          api_group: "trstctl.com",
          api_version: "trstctl.com/v1alpha1",
          plural: "trstctlsecretinjections",
          status: "served",
          owns: ["app-container file mounts"],
          evidence_ref: "deploy/operator/crd.yaml",
        },
        modes: [
          {
            id: "file",
            name: "Shared-volume file injection",
            delivered_by: "trstctl-agent",
            workload_change: "pod template patch",
            secret_handling: "byte-backed",
            capabilities: ["no-code-workload-injection"],
          },
        ],
        workload_kinds: ["Deployment"],
        sidecar_command: ["/usr/local/bin/trstctl-agent", "--secret-inject"],
        annotations: ["trstctl.com/secret-injection-hash"],
        sync_dependency: "TrstctlSecretSync",
        secret_handling: "metadata only",
        architecture_controls: ["AN-8"],
        evidence_refs: ["internal/operator/secretinjection.go"],
        residuals: [],
        recommended_next_actions: [],
      }),
    );

    const posture = await api.secretWorkloadInjection();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/workload-injection");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
    expect(posture.capability).toBe("CAP-SECR-05");
    expect(posture.crd.kind).toBe("TrstctlSecretInjection");
  });

  it("reads unvaulted secret posture without mutation headers", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-SECR-07",
        served: true,
        generated_at: "2026-06-30T00:00:00Z",
        summary: {
          repository_sources: 1,
          third_party_sources: 0,
          cloud_secret_sources: 1,
          vault_providers_supported: 4,
          vault_providers_visible: 4,
          sync_targets_configured: 3,
          leaked_secret_findings: 1,
        },
        detection_sources: [
          {
            id: "repositories",
            name: "Git repository secret scanning",
            source_kind: "secret_repo",
            configured_count: 1,
            detection_mode: "served scan",
            secret_handling: "redacted metadata",
            findings_kind: "leaked_secret",
            capabilities: ["unvaulted-secret-detection"],
            evidence_refs: ["internal/secretscan/repository.go"],
          },
        ],
        vault_providers: [
          {
            id: "azure-key-vault",
            name: "Azure Key Vault",
            discovery_configured: true,
            discovery_source_count: 1,
            sync_supported: true,
            sync_configured: true,
            augmentation_mode: "sealed-outbox sync",
            capabilities: ["vault-augmentation"],
            evidence_refs: ["internal/discovery/cloudsecret/azurekv/azurekv.go"],
          },
        ],
        configured_vaults: ["azure-key-vault"],
        configured_sync_targets: ["azure-key-vault"],
        workflow: ["detect", "augment"],
        secret_handling: "metadata only",
        architecture_controls: ["AN-8"],
        evidence_refs: ["internal/api/secrets.go"],
        residuals: [],
        recommended_next_actions: [],
      }),
    );

    const posture = await api.unvaultedSecrets();

    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/unvaulted");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
    expect(sentHeaders()["Idempotency-Key"]).toBeUndefined();
    expect(posture.capability).toBe("CAP-SECR-07");
    expect(posture.summary.vault_providers_visible).toBe(4);
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
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
  });

  it("sends served secret creation, PKI issue, login, and sharing as idempotent mutations", async () => {
    document.cookie = "trstctl_csrf=csrf-secrets; path=/";
    mockFetch(201, JSON.stringify({ name: "app/api", version: 1 }));
    await api.createSecret({ name: "app/api", value: "stored" });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/store");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);

    mockFetch(201, JSON.stringify({ serial: "01", common_name: "svc.internal", certificate: "CERT" }));
    await api.issuePKISecret({ csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----", ttl_seconds: 600 });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/pki");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body))).toEqual({
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
      ttl_seconds: 600,
    });

    mockFetch(200, JSON.stringify({ session_id: "sess-1", principal: "svc", method: "token", scopes: ["secrets:read"], expires_at: "2026-06-19T13:00:00Z" }));
    await api.machineLogin({ method: "token", credential: "machine-token" });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/login");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);

    mockFetch(201, JSON.stringify({ token: "share-token", expires_at: "2026-06-19T13:00:00Z" }));
    await api.createShare({ value: "secret", ttl_seconds: 300 });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/shares");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);

    mockFetch(200, JSON.stringify({ value: "redeemed-once" }));
    await api.redeemShare({ token: "share-token" });
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/secrets/shares/redeem");
    expect(sentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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
        action: {
          id: "right-size-a",
          owner_id: "owner-1",
          owner_name: "payments",
          inventory_id: "identity/id-1",
          display_name: "payments",
          kind: "service_account",
          source: "managed",
          playbook_id: "nhi-right-size",
          action: "right_size",
          status: "accepted",
          severity: "high",
          risk_score: 80,
          connector: "aws-iam",
          target: "role/payments",
          reason: "owner accepted",
          recommendation: "remove admin",
          remove_scopes: ["admin:*"],
          recommended_scopes: ["secrets:read"],
          evidence_refs: [],
          rollback_ref: "restore",
        },
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
  it("fetches CAP-REV-05 rogue and non-compliant certificate posture", async () => {
    mockFetch(
      200,
      JSON.stringify({
        capability: "CAP-REV-05",
        generated_at: "2026-06-30T00:00:00Z",
        coverage: ["ct_unexpected_issuance"],
        summary: { findings: 1, rogue: 1 },
        findings: [
          {
            id: "discovery:f1",
            kind: "rogue_certificate",
            policy_status: "rogue",
            subject: "CN=shadow",
            source: "ct_log",
            finding_types: ["ct_unexpected_issuance"],
            severity: "critical",
            risk_score: 90,
            recommendation: "Investigate",
            evidence_refs: ["projection:discovery_findings:f1"],
          },
        ],
        recommended_actions: ["Investigate"],
        evidence_refs: ["projection:discovery_findings"],
      }),
    );

    const result = await api.rogueCertificates();

    expect(result.capability).toBe("CAP-REV-05");
    expect(result.findings[0]?.kind).toBe("rogue_certificate");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/v1/revocation/rogue-certificates");
    expect(vi.mocked(fetch).mock.calls[0][1]?.method).toBeUndefined();
  });

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
    expect(lastSentHeaders()["Idempotency-Key"]).toMatch(/^(?:idem-.+|[0-9a-f-]{36})$/);
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

describe("CLI-parity client methods (S3.3)", () => {
  interface ParityCase {
    name: string;
    call: () => Promise<unknown>;
    method: string;
    path: string;
    status?: number;
    body?: string;
  }

  const cases: ParityCase[] = [
    { name: "pamSessions", call: () => api.pamSessions({ limit: 5 }), method: "GET", path: "/api/v1/access/sessions?limit=5" },
    { name: "pamSession", call: () => api.pamSession("s/1"), method: "GET", path: "/api/v1/access/sessions/s%2F1" },
    {
      name: "openPAMSession",
      call: () => api.openPAMSession({ method: "tpm", payload_base64: "cGF5", role: "dba", target_id: "db1", target_type: "postgres" }),
      method: "POST",
      path: "/api/v1/access/sessions",
      status: 201,
    },
    { name: "acmeDNS01ProviderConfig", call: () => api.acmeDNS01ProviderConfig("c1"), method: "GET", path: "/api/v1/acme/dns-01/provider-configs/c1" },
    {
      name: "updateACMEDNS01ProviderConfig",
      call: () => api.updateACMEDNS01ProviderConfig("c1", { name: "route53", provider: "route53" }),
      method: "PUT",
      path: "/api/v1/acme/dns-01/provider-configs/c1",
    },
    {
      name: "deleteACMEDNS01ProviderConfig",
      call: () => api.deleteACMEDNS01ProviderConfig("c1"),
      method: "DELETE",
      path: "/api/v1/acme/dns-01/provider-configs/c1",
      status: 204,
    },
    {
      name: "acmeDNS01Preflight",
      call: () => api.acmeDNS01Preflight({ config_id: "c1", domain: "a.example.com" }),
      method: "POST",
      path: "/api/v1/acme/dns-01/preflight",
    },
    {
      name: "revokeAgentCert",
      call: () => api.revokeAgentCert("ag1", { reason: "keyCompromise" }),
      method: "POST",
      path: "/api/v1/agents/ag1/cert-revocations",
      status: 201,
    },
    { name: "caCeremony", call: () => api.caCeremony("cer1"), method: "GET", path: "/api/v1/ca/ceremonies/cer1" },
    { name: "caAuthorities", call: () => api.caAuthorities(), method: "GET", path: "/api/v1/ca/authorities" },
    {
      name: "createRootCA",
      call: () => api.createRootCA({ ceremony_id: "cer1", spec: { common_name: "Root CA" } }),
      method: "POST",
      path: "/api/v1/ca/authorities/roots",
      status: 201,
    },
    {
      name: "createIntermediateCA",
      call: () => api.createIntermediateCA({ ceremony_id: "cer1", parent_id: "root1", spec: { common_name: "Intermediate CA" } }),
      method: "POST",
      path: "/api/v1/ca/authorities/intermediates",
      status: 201,
    },
    {
      name: "signIntermediateCSR",
      call: () =>
        api.signIntermediateCSR("root1", { ceremony_id: "cer1", csr_pem: "-----BEGIN CERTIFICATE REQUEST-----", spec: { common_name: "Issued Intermediate" } }),
      method: "POST",
      path: "/api/v1/ca/authorities/root1/intermediates/csr",
      status: 201,
    },
    {
      name: "issueLeafFromCA",
      call: () => api.issueLeafFromCA("int1", { csr_pem: "-----BEGIN CERTIFICATE REQUEST-----" }),
      method: "POST",
      path: "/api/v1/ca/authorities/int1/issue",
      status: 201,
    },
    {
      name: "bulkRevokeCertificates",
      call: () => api.bulkRevokeCertificates({ certificate_ids: ["c1"], reason: "keyCompromise" }),
      method: "POST",
      path: "/api/v1/certificates/bulk-revoke",
    },
    {
      name: "bulkRevokeIdentities",
      call: () => api.bulkRevokeIdentities({ identity_ids: ["i1"], reason: "superseded" }),
      method: "POST",
      path: "/api/v1/identities/bulk-revoke",
    },
    { name: "connectorTarget", call: () => api.connectorTarget("t1"), method: "GET", path: "/api/v1/connectors/targets/t1" },
    {
      name: "updateConnectorTarget",
      call: () => api.updateConnectorTarget("t1", { connector: "nginx", name: "edge" }),
      method: "PUT",
      path: "/api/v1/connectors/targets/t1",
    },
    { name: "deleteConnectorTarget", call: () => api.deleteConnectorTarget("t1"), method: "DELETE", path: "/api/v1/connectors/targets/t1", status: 204 },
    { name: "outboxCircuits", call: () => api.outboxCircuits(), method: "GET", path: "/api/v1/connectors/outbox-circuits" },
    {
      name: "outboxReconciliationConflicts",
      call: () => api.outboxReconciliationConflicts(),
      method: "GET",
      path: "/api/v1/incidents/outbox-reconciliation-conflicts",
    },
    {
      name: "connectorDeliveries",
      call: () => api.connectorDeliveries({ limit: 20, identityId: "i1" }),
      method: "GET",
      path: "/api/v1/connectors/deliveries?limit=20&identity_id=i1",
    },
    { name: "connectorDelivery", call: () => api.connectorDelivery("d1"), method: "GET", path: "/api/v1/connectors/deliveries/d1" },
    {
      name: "requestEphemeralCredential",
      call: () =>
        api.requestEphemeralCredential({ method: "tpm-quote", payload_base64: "cGF5", public_key_pem: "-----BEGIN PUBLIC KEY-----", request_id: "req1" }),
      method: "POST",
      path: "/api/v1/ephemeral",
      status: 202,
      body: JSON.stringify({ state: "awaiting_approval" }),
    },
    {
      name: "approveEphemeralCredential",
      call: () =>
        api.approveEphemeralCredential("019fec49-6641-7131-ae7f-17f7ea4b5e0e", {
          action: "issue",
          request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e0e",
          intent_digest: "sha256:ephemeral",
        }),
      method: "POST",
      path: "/api/v1/ephemeral/019fec49-6641-7131-ae7f-17f7ea4b5e0e/approvals",
    },
    { name: "issuer", call: () => api.issuer("iss1"), method: "GET", path: "/api/v1/issuers/iss1" },
    { name: "rotationRuns", call: () => api.rotationRuns({ limit: 10 }), method: "GET", path: "/api/v1/lifecycle/rotation-runs?limit=10" },
    { name: "rotationRun", call: () => api.rotationRun("run1"), method: "GET", path: "/api/v1/lifecycle/rotation-runs/run1" },
    { name: "mdmSCEPPolicy", call: () => api.mdmSCEPPolicy("p1"), method: "GET", path: "/api/v1/mdm/scep/policies/p1" },
    {
      name: "updateMDMSCEPPolicy",
      call: () => api.updateMDMSCEPPolicy("p1", { name: "intune", provider: "intune", scep_endpoint: "/scep", scep_profile: "device" }),
      method: "PUT",
      path: "/api/v1/mdm/scep/policies/p1",
    },
    { name: "deleteMDMSCEPPolicy", call: () => api.deleteMDMSCEPPolicy("p1"), method: "DELETE", path: "/api/v1/mdm/scep/policies/p1", status: 204 },
    { name: "rotateMDMSCEPChallenge", call: () => api.rotateMDMSCEPChallenge("p1"), method: "POST", path: "/api/v1/mdm/scep/policies/p1/rotate-challenge" },
    { name: "notification", call: () => api.notification("n1"), method: "GET", path: "/api/v1/notifications/n1" },
    { name: "owner", call: () => api.owner("o1"), method: "GET", path: "/api/v1/owners/o1" },
    { name: "updateOwner", call: () => api.updateOwner("o1", { kind: "team", name: "SRE" }), method: "PUT", path: "/api/v1/owners/o1" },
    { name: "deleteOwner", call: () => api.deleteOwner("o1"), method: "DELETE", path: "/api/v1/owners/o1", status: 204 },
    { name: "platformDistribution", call: () => api.platformDistribution(), method: "GET", path: "/api/v1/platform/distribution" },
    {
      name: "privacyArchiveAttestations",
      call: () => api.privacyArchiveAttestations({ limit: 5, subjectRef: "owner-1" }),
      method: "GET",
      path: "/api/v1/privacy/archive-erasure-attestations?limit=5&subject_ref=owner-1",
    },
    {
      name: "recordPrivacyArchiveAttestation",
      call: () => api.recordPrivacyArchiveAttestation({ action: "deleted", artifact_type: "backup", subject: "owner-1" }),
      method: "POST",
      path: "/api/v1/privacy/archive-erasure-attestations",
      status: 201,
    },
    {
      name: "remediationPlaybookRuns",
      call: () => api.remediationPlaybookRuns({ playbookId: "pb1" }),
      method: "GET",
      path: "/api/v1/remediation/playbook-runs?playbook_id=pb1",
    },
    { name: "remediationOwnerActions", call: () => api.remediationOwnerActions("o1"), method: "GET", path: "/api/v1/remediation/owner-actions?owner_id=o1" },
    { name: "remediationOwnerActionsUnscoped", call: () => api.remediationOwnerActions(), method: "GET", path: "/api/v1/remediation/owner-actions" },
    {
      name: "runSecretRotation",
      call: () => api.runSecretRotation({ key: "db/pass", old_ref: "version:1", provider: "connector:ci", remote_key: "DB_PASS" }),
      method: "POST",
      path: "/api/v1/secrets/rotations",
    },
    {
      name: "createSecretRotationSchedule",
      call: () => api.createSecretRotationSchedule({ interval_seconds: 3600, key: "db/pass", name: "hourly", old_ref: "version:1", provider: "connector:ci" }),
      method: "POST",
      path: "/api/v1/secrets/rotation-schedules",
      status: 201,
    },
    {
      name: "secretRotationSchedules",
      call: () => api.secretRotationSchedules({ limit: 20 }),
      method: "GET",
      path: "/api/v1/secrets/rotation-schedules?limit=20",
    },
    { name: "runDueSecretRotations", call: () => api.runDueSecretRotations(), method: "POST", path: "/api/v1/secrets/rotation-schedules/run-due" },
  ];

  it.each(cases.map((entry) => [entry.name, entry] as const))("%s calls its served route", async (_name, entry) => {
    mockFetch(entry.status ?? 200, entry.body ?? "{}");
    await entry.call();
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe(entry.path);
    expect(vi.mocked(fetch).mock.calls[0][1]?.method ?? "GET").toBe(entry.method);
    if (entry.method !== "GET") {
      expect(lastSentHeaders()["Idempotency-Key"]).toBeTruthy();
    }
  });
});
