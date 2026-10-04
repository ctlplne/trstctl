// Both tenant and Provider billing forms interpret the browser's date-time
// control as a UTC minute, not the operator's local timezone.
export function defaultBillingPeriod(): { start: string; end: string } {
  const now = new Date();
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const start = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() - 1, 1));
  return { start: start.toISOString().slice(0, 16), end: end.toISOString().slice(0, 16) };
}

export function asRFC3339UTCMinute(utcMinute: string): string {
  return `${utcMinute}:00Z`;
}

export function validUTCPeriod(start: string, end: string): boolean {
  const validMinute = (value: string) => {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return false;
    const parsed = new Date(asRFC3339UTCMinute(value));
    return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 16) === value;
  };
  return validMinute(start) && validMinute(end) && start < end;
}
