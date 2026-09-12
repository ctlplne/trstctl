// HTTP doubles exercise client request/state semantics only. AQID is synthetic
// envelope data, not a signed CSR/certificate or served TLS evidence.
import { webcrypto } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, setPreviewTransportIsolation } from "@/lib/api";
import { bindFirstCertificatePrincipal, retainFirstCertificateAttempt, retainedFirstCertificateAttempt } from "@/lib/firstCertificateMemory";
import {
  checkWizardPublicResult,
  correctWizardCertificateCSR,
  downloadWizardPublicCertificate,
  newWizardCertificateAttempt,
  publicCertificateBlocks,
  readWizardCertificateResult,
  submitWizardCertificateAttempt,
  wizardCertificateForm,
  wizardFailureKind,
  WizardIssuanceStopped,
  type WizardCertificateAttempt,
  type WizardPublicResult,
} from "@/lib/wizardFirstCertificate";

const principal = { tenantId: "tenant-a", subject: "operator-a" };
const csr = "-----BEGIN CERTIFICATE REQUEST-----\nAQID\n-----END CERTIFICATE REQUEST-----";
const pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
const input = {
  name: "payments",
  applicationID: "APP",
  environment: "test",
  alertContact: "ops@example.test",
  ownershipConfirmed: true,
  wildcardAck: false,
  subjectCSRPEM: csr,
};
let saved: WizardCertificateAttempt;
let calls: Array<{ path: string; method: string; key: string | null; body: string | undefined }>;
let failPath: string | null;
let me: { tenant_id: string; subject: string };
let responseHook: ((path: string) => void) | null;
function keep(next: WizardCertificateAttempt) {
  retainFirstCertificateAttempt(next);
  saved = next;
}
function result(state: "pending" | "issued" = "issued"): WizardPublicResult {
  return {
    identity_id: saved.issuance!.identityId!,
    request_key: saved.issuance!.issueKey,
    state,
    ...(state === "issued"
      ? {
          certificate: {
            id: "cert-a",
            tenant_id: principal.tenantId,
            subject: "CN=payments",
            fingerprint: "observed-fingerprint",
            status: "active",
            key_origin: "requester",
            issuer: "Observed authority",
          },
          certificate_pem: pem,
        }
      : {}),
  };
}
function installRead(value: WizardPublicResult | number) {
  const original = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
      if (String(path).includes("issuance-result?")) {
        return new Response(typeof value === "number" ? "{}" : JSON.stringify(value), { status: typeof value === "number" ? value : 200 });
      }
      return original(path, init);
    }),
  );
}
beforeEach(() => {
  bindFirstCertificatePrincipal(null);
  bindFirstCertificatePrincipal(principal);
  setPreviewTransportIsolation(false);
  let sequence = 0;
  vi.stubGlobal("crypto", { subtle: webcrypto.subtle, randomUUID: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}` });
  calls = [];
  failPath = null;
  me = { tenant_id: principal.tenantId, subject: principal.subject };
  responseHook = null;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
      const url = String(path);
      const method = init?.method ?? "GET";
      const headers = new Headers(init?.headers);
      calls.push({ path: url, method, key: headers.get("Idempotency-Key"), body: init?.body as string | undefined });
      expect(init?.credentials).toBe("include");
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      if (url === failPath) {
        failPath = null;
        throw new TypeError("lost response");
      }
      let value: unknown;
      if (url === "/auth/me") value = me;
      else if (url === "/api/v1/owners") value = { id: "owner-a", tenant_id: principal.tenantId, ownership_complete: true, ownership_current: false };
      else if (url === "/api/v1/owners/owner-a/attest")
        value = { id: "owner-a", tenant_id: principal.tenantId, ownership_complete: true, ownership_current: true };
      else if (url === "/api/v1/identities" || url === "/api/v1/identities/identity-a/transitions" || url === "/api/v1/identities/identity-a")
        value = {
          id: "identity-a",
          tenant_id: principal.tenantId,
          owner_id: "owner-a",
          name: input.name,
          kind: "x509_certificate",
          status: url === "/api/v1/identities" ? "requested" : "issued",
        };
      else throw new Error(`unexpected fixture path ${url}`);
      responseHook?.(url);
      return new Response(JSON.stringify(value), { status: 200 });
    }),
  );
  saved = newWizardCertificateAttempt(input, principal);
  keep(saved);
});
afterEach(() => {
  bindFirstCertificatePrincipal(null);
  setPreviewTransportIsolation(false);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("first-certificate client custody and exact attempt", () => {
  it.each(["failed", "unavailable"] as const)("stops an exact %s result without fetching an identity or mutating", async (state) => {
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    const value: WizardPublicResult = { ...result("pending"), state, ...(state === "failed" ? { delivery: { status: "failed", attempts: 10 } } : {}) };
    installRead(value);
    calls.length = 0;
    await expect(readWizardCertificateResult(saved, new AbortController().signal)).rejects.toEqual(new WizardIssuanceStopped(state));
    expect(calls.every((call) => call.path === "/auth/me" && call.method === "GET")).toBe(true);
    expect(() => checkWizardPublicResult({ ...value, request_key: "another-request" }, saved)).toThrow("result_mismatch");
    expect(() => checkWizardPublicResult({ ...value, certificate_pem: pem }, saved)).toThrow("public_result_invalid");
  });
  it("rejects contradictory terminal metadata while retaining a recorded public result after delivery failure", async () => {
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    const failedDelivery = { status: "failed" as const, attempts: 10 };
    expect(() => checkWizardPublicResult({ ...result("pending"), delivery: failedDelivery }, saved)).toThrow("public_result_invalid");
    expect(() => checkWizardPublicResult({ ...result("pending"), state: "failed" }, saved)).toThrow("public_result_invalid");
    expect(() => checkWizardPublicResult({ ...result("pending"), state: "unavailable", delivery: failedDelivery }, saved)).toThrow("public_result_invalid");
    expect(() => checkWizardPublicResult({ ...result(), delivery: { ...failedDelivery, attempts: -1 } }, saved)).toThrow("public_result_invalid");
    const recorded = { ...result(), delivery: failedDelivery };
    expect(checkWizardPublicResult(recorded, saved)).toEqual(recorded);
  });
  it.each(["/api/v1/owners", "/api/v1/owners/owner-a/attest", "/api/v1/identities", "/api/v1/identities/identity-a/transitions"])(
    "retries a lost %s response with exactly its original body and key",
    async (path) => {
      failPath = path;
      await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toThrow("lost response");
      const first = calls.find((call) => call.path === path)!;
      expect(first.key).toBeTruthy();
      await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
      const repeated = calls.filter((call) => call.path === path);
      expect(repeated).toHaveLength(2);
      expect(repeated[1]).toEqual(first);
      const posts = calls.filter((call) => call.method === "POST");
      expect(new Set(posts.map((call) => call.key)).size).toBe(4);
      expect(posts.filter((call) => call.path !== path)).toHaveLength(3);
      expect(saved.issuance?.phase).toBe("accepted");
      expect(retainedFirstCertificateAttempt(principal)).toBe(saved);
      expect(calls.find((call) => call.path.endsWith("/transitions"))?.body).toContain('"subject_csr_pem"');
      expect(JSON.parse(calls.find((call) => call.path.endsWith("/transitions"))!.body!).subject_csr_pem).toBe(csr);
    },
  );
  it("retains canonical inputs before dispatch and refuses writes if retention fails", async () => {
    await expect(
      submitWizardCertificateAttempt(saved, new AbortController().signal, () => {
        throw new Error("retain failed");
      }),
    ).rejects.toThrow("retain failed");
    expect(calls).toEqual([]);
    expect(Object.isFrozen(saved.input)).toBe(true);
  });
  it.each(["", "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----", csr + "\n" + csr, "x".repeat(65537)])(
    "rejects a missing or non-CSR envelope before mutation",
    (bad) => {
      expect(wizardCertificateForm.safeParse({ ...input, subjectCSRPEM: bad }).success).toBe(false);
      expect(calls).toEqual([]);
    },
  );
  it("retains required owner attribution and wildcard acknowledgement in the wire body", async () => {
    expect(wizardCertificateForm.safeParse({ ...input, name: "*.example.test" }).success).toBe(false);
    saved = newWizardCertificateAttempt({ ...input, name: "*.example.test", wildcardAck: true }, principal);
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/owners")!.body!)).toEqual({
      kind: "workload",
      name: "*.example.test",
      service: "*.example.test",
      application_id: "APP",
      environment: "test",
      email: "ops@example.test",
    });
    const created = JSON.parse(calls.find((call) => call.path === "/api/v1/identities")!.body!);
    expect(created.attributes).toEqual({ validation_method: "dns-01", wildcard_blast_radius_acknowledged: true });
    expect(created).not.toHaveProperty("issuer_id");
  });
  it("does not mutate when fresh authentication differs even though the page still holds its old principal", async () => {
    me = { ...me, subject: "other-operator" };
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toThrow("session_changed");
    expect(calls.filter((call) => call.method === "POST")).toEqual([]);
  });
  it("checks principal changes after an awaited owner response before identity creation", async () => {
    responseHook = (path) => {
      if (path === "/api/v1/owners") me = { ...me, tenant_id: "tenant-b" };
    };
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toThrow("session_changed");
    expect(calls.filter((call) => call.method === "POST").map((call) => call.path)).toEqual(["/api/v1/owners"]);
  });
  it("clears the volatile attempt and aborts an in-flight operation on the authenticated scope change", async () => {
    responseHook = (path) => {
      if (path === "/api/v1/owners") bindFirstCertificatePrincipal({ tenantId: "tenant-b", subject: "other" });
    };
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toThrow("operation_interrupted");
    expect(retainedFirstCertificateAttempt(principal)).toBeNull();
    expect(calls.some((call) => call.path === "/api/v1/identities")).toBe(false);
  });
  it("honors cancellation before its first authentication call", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(submitWizardCertificateAttempt(saved, controller.signal, keep)).rejects.toThrow("operation_interrupted");
    expect(calls).toEqual([]);
  });
  it("refuses successful replies observed after the absolute submission budget", async () => {
    let now = 0;
    vi.spyOn(performance, "now").mockImplementation(() => now);
    responseHook = (path) => {
      if (path === "/api/v1/owners") now = 90_001;
    };
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toThrow("operation_interrupted");
    expect(calls.some((call) => call.path === "/api/v1/identities")).toBe(false);
  });
  it("has no insecure random-key fallback or preview transport escape", () => {
    vi.stubGlobal("crypto", {});
    expect(() => newWizardCertificateAttempt(input, principal)).toThrow("secure_ids_unavailable");
    setPreviewTransportIsolation(true);
    expect(() => newWizardCertificateAttempt(input, principal)).toThrow("session_changed");
    expect(calls).toEqual([]);
  });
  it("distinguishes approval-gate refusal from permission refusal and uncertain transport failure", () => {
    expect(wizardFailureKind(new ApiError(403, JSON.stringify({ detail: "dual control: request expired" })))).toBe("approval");
    expect(wizardFailureKind(new ApiError(403, JSON.stringify({ detail: "denied by policy" })))).toBe("refused");
    expect(wizardFailureKind(new TypeError("offline"))).toBe("uncertain");
  });
});
describe("immutable public result boundary", () => {
  beforeEach(async () => {
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    calls.length = 0;
  });
  it("treats pending as unconfirmed and obtains no substitute inventory certificate", async () => {
    installRead(result("pending"));
    expect(await readWizardCertificateResult(saved, new AbortController().signal)).toBeNull();
    expect(calls.some((call) => call.path === "/api/v1/identities/identity-a")).toBe(false);
    expect(calls.some((call) => call.method === "POST")).toBe(false);
  });
  it.each([404, 403, 409, 503])("keeps result HTTP %s as an error", async (status) => {
    installRead(status);
    await expect(readWizardCertificateResult(saved, new AbortController().signal)).rejects.toThrow();
  });
  it("returns only the exact server result and its real identity; read-only replay never issues again", async () => {
    const raw = result();
    installRead(raw);
    const record = await readWizardCertificateResult(saved, new AbortController().signal);
    expect(record?.result).toEqual(raw);
    expect(record?.identity.id).toBe(raw.identity_id);
    expect(calls.filter((call) => call.method === "POST")).toEqual([]);
  });
  it("rejects other request keys, tenant IDs, missing material and inconsistent pending envelopes", () => {
    const raw = result();
    for (const invalid of [
      { ...raw, request_key: "other" },
      { ...raw, identity_id: "other" },
      { ...raw, certificate: { ...raw.certificate!, tenant_id: "tenant-b" } },
      { ...raw, certificate_pem: "" },
      { ...raw, state: "pending" as const },
    ]) {
      expect(() => checkWizardPublicResult(invalid, saved)).toThrow();
    }
  });
  it("never promotes a server-returned private-key block or trailing non-certificate material to a download", () => {
    for (const value of [pem + "untrusted trailer", pem + "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----", pem.repeat(17)])
      expect(() => publicCertificateBlocks(value)).toThrow();
    expect(publicCertificateBlocks(pem + pem)).toEqual([pem.trim(), pem.trim()]);
  });
});

describe("finite result polling budget", () => {
  beforeEach(async () => {
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    calls.length = 0;
  });
  it("does not dispatch a read whose polling window already ended", async () => {
    vi.spyOn(performance, "now").mockReturnValue(240_000);
    await expect(readWizardCertificateResult(saved, new AbortController().signal, 240_000)).rejects.toThrow("operation_interrupted");
    expect(calls).toEqual([]);
  });
  it("rejects a successful response across the polling deadline even within the usual ten-second read budget", async () => {
    let now = 239_999;
    vi.spyOn(performance, "now").mockImplementation(() => now);
    installRead(result());
    const original = fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
        const response = await original(path, init);
        if (String(path).includes("issuance-result?")) now = 240_001;
        return response;
      }),
    );
    await expect(readWizardCertificateResult(saved, new AbortController().signal, 240_000)).rejects.toThrow("operation_interrupted");
  });
  it("keeps missing or contradictory requester-key custody unconfirmed", () => {
    const raw = result();
    for (const key_origin of [undefined, "signer", "control_plane"] as const)
      expect(() => checkWizardPublicResult({ ...raw, certificate: { ...raw.certificate!, key_origin } }, saved)).toThrow("public_result_custody_unconfirmed");
  });
});

describe("public download principal guard", () => {
  it("refuses a queued download after the principal changes", async () => {
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    installRead(result());
    const record = await readWizardCertificateResult(saved, new AbortController().signal);
    expect(record).not.toBeNull();
    bindFirstCertificatePrincipal({ ...principal, subject: "different-operator" });
    expect(() => downloadWizardPublicCertificate(record!, "leaf", principal)).toThrow("session_changed");
  });
});

describe("exact CSR rejection and intentional correction", () => {
  const correctedCSR = csr.replace("AQID", "AQIE");
  function installRejection(change: (body: Record<string, unknown>) => void = () => {}, status = 400, loseFirst = false) {
    const original = globalThis.fetch;
    const posts: Array<{ key: string; body: string }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
        if (String(path).endsWith("/transitions")) {
          const key = new Headers(init?.headers).get("Idempotency-Key")!;
          posts.push({ key, body: String(init?.body) });
          if (posts.length === 1 && loseFirst) throw new TypeError("lost rejection response");
          const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
          if (request.subject_csr_pem === correctedCSR) return original(path, init);
          const digest = Array.from(
            new Uint8Array(await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(String(request.subject_csr_pem)))),
            (byte) => byte.toString(16).padStart(2, "0"),
          ).join("");
          const disposition = {
            tenant_id: principal.tenantId,
            subject: principal.subject,
            identity_id: "identity-a",
            request_key: key,
            to: request.to,
            reason: request.reason,
            subject_csr_sha256: digest,
          };
          const body: Record<string, unknown> = { code: "identity_csr_rejected_before_transition", disposition };
          change(body);
          return new Response(JSON.stringify(body), { status });
        }
        return original(path, init);
      }),
    );
    return posts;
  }
  it("recovers a lost exact refusal before correcting only the CSR and issuance key", async () => {
    const posts = installRejection(undefined, 400, true);
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toThrow("lost rejection response");
    expect(() => correctWizardCertificateCSR(saved, correctedCSR)).toThrow("correction_not_authorized");
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toBeInstanceOf(ApiError);
    expect(posts[1]).toEqual(posts[0]);
    const rejected = saved;
    saved = correctWizardCertificateCSR(saved, correctedCSR);
    keep(saved);
    expect(saved.ownerKey).toBe(rejected.ownerKey);
    expect(saved.attestKey).toBe(rejected.attestKey);
    expect(saved.owner).toBe(rejected.owner);
    expect(saved.issuance!.identityId).toBe(rejected.issuance!.identityId);
    expect(saved.issuance!.createKey).toBe(rejected.issuance!.createKey);
    expect(saved.issuance!.issueKey).not.toBe(rejected.issuance!.issueKey);
    expect(saved.replacesRejectedIssueKey).toBe(rejected.issuance!.issueKey);
    expect(saved.csrRejection).toBeNull();
    expect(saved.transitionDispatched).toBe(false);
    await submitWizardCertificateAttempt(saved, new AbortController().signal, keep);
    expect(saved.issuance!.phase).toBe("accepted");
    expect(JSON.parse(posts[2].body).subject_csr_pem).toBe(correctedCSR);
    for (const path of ["/api/v1/owners", "/api/v1/owners/owner-a/attest", "/api/v1/identities"])
      expect(calls.filter((call) => call.path === path && call.method === "POST")).toHaveLength(1);
  });
  it.each([400, 403, 409, 500])("does not unlock correction for a generic HTTP%d", async (status) => {
    installRejection((body) => {
      delete body.code;
      delete body.disposition;
    }, status);
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toBeInstanceOf(ApiError);
    expect(() => correctWizardCertificateCSR(saved, correctedCSR)).toThrow("correction_not_authorized");
  });
  it.each(["tenant_id", "subject", "identity_id", "request_key", "subject_csr_sha256", "to", "reason"])("requires exact rejection field %s", async (field) => {
    installRejection((body) => {
      (body.disposition as Record<string, unknown>)[field] = "different";
    });
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toBeInstanceOf(ApiError);
    expect(() => correctWizardCertificateCSR(saved, correctedCSR)).toThrow("correction_not_authorized");
  });
  it("requires a deliberate changed CSR, a fresh key and the same authenticated principal", async () => {
    installRejection();
    await expect(submitWizardCertificateAttempt(saved, new AbortController().signal, keep)).rejects.toBeInstanceOf(ApiError);
    expect(() => correctWizardCertificateCSR(saved, csr)).toThrow("correction_not_authorized");
    vi.stubGlobal("crypto", { subtle: webcrypto.subtle, randomUUID: () => saved.issuance!.issueKey });
    expect(() => correctWizardCertificateCSR(saved, correctedCSR)).toThrow("secure_ids_unavailable");
    bindFirstCertificatePrincipal({ tenantId: principal.tenantId, subject: "different" });
    expect(() => correctWizardCertificateCSR(saved, correctedCSR)).toThrow("session_changed");
  });
});
