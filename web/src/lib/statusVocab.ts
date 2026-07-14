import { translateNow } from "@/i18n/I18nProvider";
export type StatusTone = "operate" | "observe" | "disclose" | "success" | "warning" | "critical" | "high" | "medium" | "low" | "neutral" | "info";

export type StatusVocabulary = "agent" | "certificate" | "delivery" | "expiry" | "honesty" | "lifecycle" | "risk";

export type StatusDescriptor = {
  label: string;
  tone: StatusTone;
  order?: number;
};

export const lifecycleStatus: Record<string, StatusDescriptor> = {
  requested: { get label() {
      return translateNow("source.requested.c6a91ee7f9");
    }, tone: "observe", order: 1 },
  approved: { get label() {
      return translateNow("source.approved.2687f86ed6");
    }, tone: "operate", order: 2 },
  issued: { get label() {
      return translateNow("source.issued.c91a3cc769");
    }, tone: "success", order: 3 },
  deployed: { get label() {
      return translateNow("source.deployed.c1fa83ed9f");
    }, tone: "success", order: 4 },
  renewing: { get label() {
      return translateNow("source.renewing.7c0bdbad43");
    }, tone: "warning", order: 5 },
  revoked: { get label() {
      return translateNow("source.revoked.4bb47f186d");
    }, tone: "critical", order: 6 },
  retired: { get label() {
      return translateNow("source.retired.5b720147b6");
    }, tone: "neutral", order: 7 },
};

export const certificateStatus: Record<string, StatusDescriptor> = {
  active: { get label() {
      return translateNow("source.active.9687961165");
    }, tone: "success", order: 1 },
  superseded: { get label() {
      return translateNow("source.superseded.444bd9c51d");
    }, tone: "neutral", order: 2 },
  revoked: { get label() {
      return translateNow("source.revoked.4bb47f186d");
    }, tone: "critical", order: 3 },
};

export const riskBands: Record<string, StatusDescriptor> = {
  critical: { get label() {
      return translateNow("source.critical.427dd2969b");
    }, tone: "critical", order: 1 },
  high: { get label() {
      return translateNow("source.high.c4ebc6d4a5");
    }, tone: "high", order: 2 },
  medium: { get label() {
      return translateNow("source.medium.8e588cd187");
    }, tone: "medium", order: 3 },
  low: { get label() {
      return translateNow("source.low.f793de205e");
    }, tone: "low", order: 4 },
  none: { get label() {
      return translateNow("source.none.dc937b5989");
    }, tone: "neutral", order: 5 },
};

export const expiryBands: Record<string, StatusDescriptor> = {
  expired: { get label() {
      return translateNow("source.expired.424a2551d3");
    }, tone: "critical", order: 1 },
  critical: { get label() {
      return translateNow("source.7d.critical.b43c284b63");
    }, tone: "critical", order: 2 },
  watch: { get label() {
      return translateNow("source.7.30d.watch.7ecf4fbde2");
    }, tone: "warning", order: 3 },
  planned: { get label() {
      return translateNow("source.30.90d.planned.be92bb89d8");
    }, tone: "info", order: 4 },
  healthy: { get label() {
      return translateNow("source.90d.healthy.af665501c4");
    }, tone: "success", order: 5 },
  unknown: { get label() {
      return translateNow("source.no.expiry.fe06351db8");
    }, tone: "neutral", order: 6 },
};

export const honestyModes: Record<string, StatusDescriptor> = {
  operate: { get label() {
      return translateNow("source.operate.58c3939c4c");
    }, tone: "operate", order: 1 },
  observe: { get label() {
      return translateNow("source.observe.744ea732e2");
    }, tone: "observe", order: 2 },
  disclose: { get label() {
      return translateNow("source.disclose.5e663b5c89");
    }, tone: "disclose", order: 3 },
  real: { get label() {
      return translateNow("source.operate.58c3939c4c");
    }, tone: "operate", order: 1 },
  disclosure: { get label() {
      return translateNow("source.disclose.5e663b5c89");
    }, tone: "disclose", order: 3 },
};

export const featureMaturityLabels: Record<string, string> = {
  served: "Served",
  conditional: "Conditional",
  partial: "Partial",
  library: "Library-only",
  roadmap: "Roadmap",
};

export const agentStatus: Record<string, StatusDescriptor> = {
  online: { get label() {
      return translateNow("source.online.f6fc84c9f2");
    }, tone: "success", order: 1 },
  degraded: { get label() {
      return translateNow("source.degraded.3c8cab8b47");
    }, tone: "warning", order: 2 },
  offline: { get label() {
      return translateNow("source.offline.8e2c7ac508");
    }, tone: "neutral", order: 3 },
  offboarded: { get label() {
      return translateNow("source.offboarded.1e493e6cf3");
    }, tone: "neutral", order: 4 },
};

export const deliveryStatus: Record<string, StatusDescriptor> = {
  pending: { get label() {
      return translateNow("source.pending.62a2fed3d6");
    }, tone: "observe", order: 1 },
  processing: { get label() {
      return translateNow("source.processing.0a63dd9aa0");
    }, tone: "operate", order: 2 },
  delivered: { get label() {
      return translateNow("source.delivered.373e0712c8");
    }, tone: "success", order: 3 },
  failed: { get label() {
      return translateNow("source.failed.5d28a90f44");
    }, tone: "critical", order: 4 },
};

export const statusVocabulary: Record<StatusVocabulary, Record<string, StatusDescriptor>> = {
  agent: agentStatus,
  certificate: certificateStatus,
  delivery: deliveryStatus,
  expiry: expiryBands,
  honesty: honestyModes,
  lifecycle: lifecycleStatus,
  risk: riskBands,
};

export function describeStatus(vocabulary: StatusVocabulary, value: string): StatusDescriptor {
  const normalized = value.toLowerCase();
  return (
    statusVocabulary[vocabulary][normalized] ?? {
      label: humanizeStatus(value),
      tone: "neutral",
    }
  );
}

export function riskBand(score: number): keyof typeof riskBands {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score > 0) return "low";
  return "none";
}

export function expiryBandForDate(value?: string): keyof typeof expiryBands {
  if (!value) return "unknown";
  const days = Math.ceil((new Date(value).getTime() - Date.now()) / (24 * 60 * 60 * 1000));
  if (Number.isNaN(days)) return "unknown";
  if (days < 0) return "expired";
  if (days < 7) return "critical";
  if (days <= 30) return "watch";
  if (days <= 90) return "planned";
  return "healthy";
}

export function humanizeStatus(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}
