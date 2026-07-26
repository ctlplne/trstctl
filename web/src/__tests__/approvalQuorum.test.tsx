import { describe, expect, it } from "vitest";
import { parseApprovalProgress } from "@/lib/approvalQueue";

// S-C18: the queue must never invent a quorum. Recognized shapes become
// have/need; everything else keeps the server's own words.
describe("approval quorum parsing", () => {
  it("reads the shapes the server emits", () => {
    expect(parseApprovalProgress("1 of 2")).toEqual({ have: 1, need: 2, remaining: 1 });
    expect(parseApprovalProgress("1/2")).toEqual({ have: 1, need: 2, remaining: 1 });
    expect(parseApprovalProgress("2 / 3")).toEqual({ have: 2, need: 3, remaining: 1 });
    expect(parseApprovalProgress("1 de 2")).toEqual({ have: 1, need: 2, remaining: 1 });
    expect(parseApprovalProgress("1 von 2")).toEqual({ have: 1, need: 2, remaining: 1 });
  });

  it("reports a met quorum with nothing remaining", () => {
    expect(parseApprovalProgress("2 of 2")).toEqual({ have: 2, need: 2, remaining: 0 });
    // Over-collection is still met, never negative.
    expect(parseApprovalProgress("3 of 2")).toEqual({ have: 3, need: 2, remaining: 0 });
  });

  it("passes through anything it does not recognize, rather than guessing", () => {
    expect(parseApprovalProgress("returned after approval")).toBeNull();
    expect(parseApprovalProgress("2")).toBeNull();
    expect(parseApprovalProgress("")).toBeNull();
    expect(parseApprovalProgress("   ")).toBeNull();
    expect(parseApprovalProgress("pending second approver")).toBeNull();
  });

  it("refuses a zero threshold instead of dividing by nothing", () => {
    expect(parseApprovalProgress("0 of 0")).toBeNull();
  });
});
