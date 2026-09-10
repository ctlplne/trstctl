import { describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { newFirstCertificateAttempt, submitFirstCertificateAttempt, type FirstCertificateAttempt } from "@/lib/firstCertificateAttempt";

const principal = { tenantId: "tenant-1", subject: "operator-1" };
const input = {
  name: "service.example.test",
  ownerId: "owner-1",
  subjectCSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\ncHVibGljLXRlc3QtcmVxdWVzdA==\n-----END CERTIFICATE REQUEST-----",
};
// These are client state-machine controls. They do not prove native issuance.
function client() {
  return {
    createIdentity: vi
      .fn<typeof api.createIdentity>()
      .mockResolvedValue({ id: "identity-1", status: "requested" } as Awaited<ReturnType<typeof api.createIdentity>>),
    transitionIdentity: vi
      .fn<typeof api.transitionIdentity>()
      .mockResolvedValue({ id: "identity-1", status: "issued" } as Awaited<ReturnType<typeof api.transitionIdentity>>),
  };
}
describe("first certificate attempt", () => {
  it("requires a public CSR and freezes the exact attempt", () => {
    expect(() => newFirstCertificateAttempt({ ...input, subjectCSRPEM: "" }, principal)).toThrow();
    expect(() => newFirstCertificateAttempt({ ...input, subjectCSRPEM: input.subjectCSRPEM + "\n-----BEGIN PRIVATE KEY-----" }, principal)).toThrow();
    expect(() => newFirstCertificateAttempt({ ...input, issuerId: "cosmetic-issuer-id" }, principal)).toThrow();
    const attempt = newFirstCertificateAttempt(input, principal);
    expect(Object.isFrozen(attempt)).toBe(true);
    expect(Object.isFrozen(attempt.input)).toBe(true);
    expect(attempt.createKey).not.toBe(attempt.issueKey);
  });
  it("persists the created identity before transition and resumes the same key after a lost acknowledgement", async () => {
    let saved = newFirstCertificateAttempt(input, principal);
    const original = saved;
    const c = client();
    c.transitionIdentity.mockRejectedValueOnce(new Error("lost response"));
    const persist = (next: FirstCertificateAttempt) => {
      saved = next;
    };
    await expect(submitFirstCertificateAttempt(saved, principal, persist, c)).rejects.toThrow("lost response");
    expect(saved.identityId).toBe("identity-1");
    const accepted = await submitFirstCertificateAttempt(saved, principal, persist, c);
    expect(c.createIdentity).toHaveBeenCalledTimes(1);
    expect(c.createIdentity.mock.calls[0][1]).toBe(original.createKey);
    expect(c.transitionIdentity.mock.calls.map((call) => call[4])).toEqual([original.issueKey, original.issueKey]);
    expect(c.transitionIdentity.mock.calls.map((call) => call[3])).toEqual([input.subjectCSRPEM, input.subjectCSRPEM]);
    expect(accepted).toEqual({ state: "accepted", identityId: "identity-1", requestKey: original.issueKey });
    expect(accepted).not.toHaveProperty("certificate");
  });
  it("reuses the original creation key when the creation response is lost", async () => {
    const attempt = newFirstCertificateAttempt(input, principal);
    const c = client();
    c.createIdentity.mockRejectedValueOnce(new Error("lost create"));
    await expect(submitFirstCertificateAttempt(attempt, principal, () => {}, c)).rejects.toThrow("lost create");
    await submitFirstCertificateAttempt(attempt, principal, () => {}, c);
    expect(c.createIdentity.mock.calls.map((call) => call[1])).toEqual([attempt.createKey, attempt.createKey]);
  });
  it("does not transition if durable client persistence fails", async () => {
    const c = client();
    const attempt = newFirstCertificateAttempt(input, principal);
    await expect(
      submitFirstCertificateAttempt(
        attempt,
        principal,
        () => {
          throw new Error("storage failed");
        },
        c,
      ),
    ).rejects.toThrow("storage failed");
    expect(c.transitionIdentity).not.toHaveBeenCalled();
  });
  it("rejects another tenant or principal before any mutation", async () => {
    const attempt = newFirstCertificateAttempt(input, principal);
    const c = client();
    for (const changed of [
      { ...principal, tenantId: "tenant-2" },
      { ...principal, subject: "operator-2" },
    ]) {
      await expect(submitFirstCertificateAttempt(attempt, changed, () => {}, c)).rejects.toThrow();
    }
    expect(c.createIdentity).not.toHaveBeenCalled();
    expect(c.transitionIdentity).not.toHaveBeenCalled();
  });
  it("does not accept an approval object as a completed transition", async () => {
    const c = client();
    c.transitionIdentity.mockResolvedValue({ id: "approval-1", status: "pending" } as Awaited<ReturnType<typeof api.transitionIdentity>>);
    let saved = newFirstCertificateAttempt(input, principal);
    await expect(
      submitFirstCertificateAttempt(
        saved,
        principal,
        (next) => {
          saved = next;
        },
        c,
      ),
    ).rejects.toThrow();
    expect(saved.phase).toBe("transition");
  });
});
