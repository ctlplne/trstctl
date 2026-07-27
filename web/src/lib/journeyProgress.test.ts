import { afterEach, describe, expect, it, vi } from "vitest";
import { hasJourneyMark, persistJourneyMarks, readJourneyMarks, toggleJourneyMark } from "@/lib/journeyProgress";

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

describe("manual journey progress", () => {
  it("round-trips string marks while rejecting malformed or non-string storage", () => {
    expect(readJourneyMarks()).toEqual(new Set());

    localStorage.setItem("trstctl-journey-progress", JSON.stringify(["journey-1:step-1", 7, null]));
    expect(readJourneyMarks()).toEqual(new Set(["journey-1:step-1"]));

    localStorage.setItem("trstctl-journey-progress", JSON.stringify({ mark: "journey-1:step-1" }));
    expect(readJourneyMarks()).toEqual(new Set());

    localStorage.setItem("trstctl-journey-progress", "{broken");
    expect(readJourneyMarks()).toEqual(new Set());
  });

  it("adds and removes an exact journey-step mark without mutating the caller set", () => {
    const original = new Set<string>();
    const marked = toggleJourneyMark(original, "journey-1", "step-1");

    expect(original).toEqual(new Set());
    expect(hasJourneyMark(marked, "journey-1", "step-1")).toBe(true);
    expect(readJourneyMarks()).toEqual(marked);

    const cleared = toggleJourneyMark(marked, "journey-1", "step-1");
    expect(hasJourneyMark(cleared, "journey-1", "step-1")).toBe(false);
  });

  it("treats unavailable browser storage as a non-fatal convenience failure", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });

    expect(() => persistJourneyMarks(new Set(["journey-1:step-1"]))).not.toThrow();
  });
});
