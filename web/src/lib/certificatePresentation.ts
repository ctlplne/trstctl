import type { Certificate } from "@/lib/api";
import type { MessageKey } from "@/i18n/messages";

// Display only: never use this fallback to match an identity or authorize a
// renewal. SPIFFE certificates legitimately have an empty X.509 subject.
export function certificateDisplayName(certificate: Pick<Certificate, "id" | "subject" | "sans">): string {
  const subject = certificate.subject.trim();
  if (subject) return subject;
  const sans = certificate.sans?.map((value) => value.trim()).filter(Boolean) ?? [];
  return sans.find((value) => value.startsWith("spiffe://")) ?? sans[0] ?? certificate.id;
}

export function certificateDeadline(value: string | undefined, now: number, t: (key: MessageKey, values?: Record<string, string>) => string): string {
  const expiry = value ? Date.parse(value) : NaN;
  if (!Number.isFinite(expiry)) return t("certificateCockpit.deadline.unknown");
  const remaining = expiry - now;
  const day = 86_400_000;
  if (remaining <= 0) {
    if (remaining > -day) return t("certificateCockpit.deadline.expiredNow");
    const days = Math.floor(-remaining / day);
    return t(days === 1 ? "certificateCockpit.deadline.expiredOne" : "certificateCockpit.deadline.expiredMany", { count: String(days) });
  }
  if (remaining < 60_000) return t("certificateCockpit.deadline.underMinute");
  if (remaining < 3_600_000) return t("certificateCockpit.deadline.minutes", { count: String(Math.ceil(remaining / 60_000)) });
  if (remaining < day)
    return t("certificateCockpit.deadline.hours", {
      count: String(Math.floor(remaining / 3_600_000)),
      minutes: String(Math.floor((remaining % 3_600_000) / 60_000)),
    });
  const days = Math.ceil(remaining / day);
  return t(days === 1 ? "certificateCockpit.deadline.one" : "certificateCockpit.deadline.many", { count: String(days) });
}

export function certificateReplacementPath(certificate: Pick<Certificate, "source">): string {
  return certificate.source?.startsWith("attested:") ? "/workloads?workflow=attested" : "/request";
}
