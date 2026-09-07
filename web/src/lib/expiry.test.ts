import { describe, expect, it } from "vitest";
import { DAY_MS, arrivalBinIndex, daysUntil, expiresWithinDays, remainingMs } from "./expiry";

// One half-open rule for every client-side expiry decision, matching the served
// expiring_Nd counts (not_after >= now AND not_after < now + N days). DP2-012: a
// certificate in its 30th day used to be "≤30d" on the tile and "30–44 days" in the
// arrival histogram at the same time because the histogram binned a rounded-up day
// count.
describe("expiry rule", () => {
  const now = Date.parse("2026-08-24T12:00:00Z");
  const at = (ms: number) => new Date(now + ms).toISOString();

  it("keeps the rounded-up day count for display only", () => {
    expect(daysUntil(at(29 * DAY_MS + 23 * 3_600_000), now)).toBe(30);
    expect(daysUntil(at(30 * DAY_MS), now)).toBe(30);
    expect(daysUntil(at(-1), now)).toBe(-1);
    expect(daysUntil(undefined, now)).toBeNull();
    expect(remainingMs("not a date", now)).toBeNull();
  });

  it("decides 'within N days' half-open by exact remaining time", () => {
    expect(expiresWithinDays(at(29 * DAY_MS + 23 * 3_600_000), now, 30)).toBe(true);
    expect(expiresWithinDays(at(30 * DAY_MS - 1), now, 30)).toBe(true);
    expect(expiresWithinDays(at(30 * DAY_MS), now, 30)).toBe(false);
    expect(expiresWithinDays(at(-1), now, 30)).toBe(false);
    expect(expiresWithinDays(undefined, now, 30)).toBe(false);
  });

  it("puts a certificate in exactly one 15-day arrival bin, consistent with the 30-day rule", () => {
    const day30 = at(29 * DAY_MS + 23 * 3_600_000);
    expect(arrivalBinIndex(day30, now)).toBe(1); // 15–29, and within 30 days: counted once
    expect(expiresWithinDays(day30, now, 30)).toBe(true);
    expect(arrivalBinIndex(at(30 * DAY_MS), now)).toBe(2); // 30–44, and not within 30 days
    expect(expiresWithinDays(at(30 * DAY_MS), now, 30)).toBe(false);
    expect(arrivalBinIndex(at(14 * DAY_MS + 23 * 3_600_000), now)).toBe(0);
    expect(arrivalBinIndex(at(89 * DAY_MS + 23 * 3_600_000), now)).toBe(5);
    expect(arrivalBinIndex(at(90 * DAY_MS), now)).toBeNull();
    expect(arrivalBinIndex(at(-1), now)).toBeNull();
    // Invariant behind DP2-012: the first two bins are exactly the within-30-days population.
    const sample = [0.5, 7, 14.9, 15, 29.9, 30, 44.9, 45, 89.9].map((d) => at(d * DAY_MS));
    const within30 = sample.filter((c) => expiresWithinDays(c, now, 30)).length;
    const firstTwoBins = sample.filter((c) => (arrivalBinIndex(c, now) ?? 9) <= 1).length;
    expect(firstTwoBins).toBe(within30);
  });
});
