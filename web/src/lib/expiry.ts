// One expiry rule for every client-side count, bucket, and urgency flag, matching the
// served certificate health summary: a certificate is "within N days" when it is live now
// and expires strictly before now + N days (half-open, exact time). The day count used for
// display rounds up, so it must never be the thing that decides a bucket (DP2-012).
export const DAY_MS = 86_400_000;

/** Milliseconds until `notAfter` from `now`; null when the value is missing or unparsable. */
export function remainingMs(notAfter: string | undefined, now: number): number | null {
  if (!notAfter) return null;
  const time = new Date(notAfter).getTime();
  return Number.isFinite(time) ? time - now : null;
}

/** Whole days until expiry for display: live values round up, expired values are negative. */
export function daysUntil(notAfter: string | undefined, now: number): number | null {
  const remaining = remainingMs(notAfter, now);
  if (remaining === null) return null;
  return remaining <= 0 ? -Math.max(1, Math.floor(-remaining / DAY_MS)) : Math.ceil(remaining / DAY_MS);
}

/** The served rule: live now and expiring before now + `days`. Mirrors the API's expiring_Nd counts. */
export function expiresWithinDays(notAfter: string | undefined, now: number, days: number): boolean {
  const remaining = remainingMs(notAfter, now);
  return remaining !== null && remaining >= 0 && remaining < days * DAY_MS;
}

/** 15-day arrival bin (0..5) of a live certificate inside the 90-day window, by exact remaining time; null outside it. */
export function arrivalBinIndex(notAfter: string | undefined, now: number): number | null {
  const remaining = remainingMs(notAfter, now);
  if (remaining === null || remaining < 0 || remaining >= 90 * DAY_MS) return null;
  return Math.floor(remaining / DAY_MS / 15);
}
