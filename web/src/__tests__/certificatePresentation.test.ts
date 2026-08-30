import { describe, expect, it } from "vitest";
import { certificateDisplayName, certificateDeadline } from "@/lib/certificatePresentation";

describe("certificate presentation preserves identity and exact time meaning", () => {
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
