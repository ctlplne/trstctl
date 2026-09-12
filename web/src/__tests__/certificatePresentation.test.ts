import { describe, expect, it } from "vitest";
import { certificateDisplayName, certificateDeadline, certificateIdentity, certificateCanRenew } from "@/lib/certificatePresentation";
import type { Certificate, Identity } from "@/lib/api";

describe("certificate presentation preserves identity and exact time meaning", () => {
  const leaf: Certificate = { id: "leaf", tenant_id: "tenant", subject: "CN=same.example", fingerprint: "fp", status: "active", owner_id: "owner" };
  const first: Identity = { id: "first", kind: "x509_certificate", name: "same.example", owner_id: "owner", status: "deployed" };
  const second: Identity = { ...first, id: "second" };
  it("never selects a managing identity by name, owner, or list order", () => {
    expect(certificateIdentity(leaf, [first, second])).toBeUndefined();
    expect(certificateIdentity({ ...leaf, identity_ids: ["first", "second"] }, [first, second])).toBeUndefined();
    expect(certificateIdentity({ ...leaf, identity_ids: ["second"] }, [first, second])).toBe(second);
    expect(certificateIdentity({ ...leaf, identity_ids: ["second"] }, [second, first])).toBe(second);
    expect(certificateIdentity({ ...leaf, identity_ids: ["missing"] }, [first, second])).toBeUndefined();
  });
  it.each(["requested", "issued", "renewing", "revoked", "retired", "unknown"])("does not offer renewal from %s", (status) => {
    expect(certificateCanRenew(leaf, { ...first, status })).toBe(false);
  });
  it("offers only live certificate renewal from deployed or failed renewal states", () => {
    expect(certificateCanRenew(leaf, first)).toBe(true);
    expect(certificateCanRenew(leaf, { ...first, status: "renewal_failed" })).toBe(true);
    expect(certificateCanRenew({ ...leaf, status: "revoked" }, first)).toBe(false);
    expect(certificateCanRenew({ ...leaf, status: "superseded" }, first)).toBe(false);
    expect(certificateCanRenew({ ...leaf, source: "attested:spiffe" }, first)).toBe(false);
  });
  it("uses subject, then a SPIFFE URI, then another SAN, then the stable id", () => {
    expect(certificateDisplayName({ id: "c1", subject: "CN=api.test", sans: ["spiffe://test/worker"] })).toBe("CN=api.test");
    expect(certificateDisplayName({ id: "c1", subject: "", sans: ["api.test", "spiffe://test/worker"] })).toBe("spiffe://test/worker");
    expect(certificateDisplayName({ id: "c1", subject: "  ", sans: [" ", "api.test"] })).toBe("api.test");
    expect(certificateDisplayName({ id: "c1", subject: "", sans: [] })).toBe("c1");
  });
  it.each([
    [0, "certificateCockpit.deadline.expiredNow"],
    [-1, "certificateCockpit.deadline.expiredNow"],
    [-60000, "certificateCockpit.deadline.expiredNow"],
    [1, "certificateCockpit.deadline.underMinute"],
    [60000, "certificateCockpit.deadline.minutes:1"],
    [45 * 60000, "certificateCockpit.deadline.minutes:45"],
    [3600000, "certificateCockpit.deadline.hours:1"],
    [3 * 3600000, "certificateCockpit.deadline.hours:3"],
    [86400000, "certificateCockpit.deadline.one:1"],
    [-86400000, "certificateCockpit.deadline.expiredOne:1"],
  ])("does not round %d milliseconds into a misleading day", (delta, expected) => {
    const now = Date.parse("2026-08-30T12:00:00Z");
    expect(certificateDeadline(new Date(now + delta).toISOString(), now, (key, vars) => key + (vars?.count ? `:${vars.count}` : ""))).toBe(expected);
  });
  it("keeps unknown expiry unknown", () => {
    expect(certificateDeadline(undefined, 0, (key) => key)).toBe("certificateCockpit.deadline.unknown");
    expect(certificateDeadline("not-a-date", 0, (key) => key)).toBe("certificateCockpit.deadline.unknown");
  });
});
