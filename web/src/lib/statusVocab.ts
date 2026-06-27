export type StatusTone = "operate" | "observe" | "disclose" | "success" | "warning" | "critical" | "high" | "medium" | "low" | "neutral" | "info";

export type StatusVocabulary = "agent" | "certificate" | "delivery" | "expiry" | "honesty" | "lifecycle" | "risk";

export type StatusDescriptor = {
  label: string;
  tone: StatusTone;
  order?: number;
};

export const lifecycleStatus: Record<string, StatusDescriptor> = {
  requested: { label: "requested", tone: "observe", order: 1 },
  approved: { label: "approved", tone: "operate", order: 2 },
  issued: { label: "issued", tone: "success", order: 3 },
  deployed: { label: "deployed", tone: "success", order: 4 },
  renewing: { label: "renewing", tone: "warning", order: 5 },
  revoked: { label: "revoked", tone: "critical", order: 6 },
  retired: { label: "retired", tone: "neutral", order: 7 },
};

export const certificateStatus: Record<string, StatusDescriptor> = {
  active: { label: "active", tone: "success", order: 1 },
  superseded: { label: "superseded", tone: "neutral", order: 2 },
  revoked: { label: "revoked", tone: "critical", order: 3 },
};

export const riskBands: Record<string, StatusDescriptor> = {
  critical: { label: "Critical", tone: "critical", order: 1 },
  high: { label: "High", tone: "high", order: 2 },
  medium: { label: "Medium", tone: "medium", order: 3 },
  low: { label: "Low", tone: "low", order: 4 },
  none: { label: "None", tone: "neutral", order: 5 },
};

export const expiryBands: Record<string, StatusDescriptor> = {
  expired: { label: "Expired", tone: "critical", order: 1 },
  critical: { label: "<7d critical", tone: "critical", order: 2 },
  watch: { label: "7-30d watch", tone: "warning", order: 3 },
  planned: { label: "30-90d planned", tone: "info", order: 4 },
  healthy: { label: ">90d healthy", tone: "success", order: 5 },
  unknown: { label: "No expiry", tone: "neutral", order: 6 },
};

export const honestyModes: Record<string, StatusDescriptor> = {
  operate: { label: "Operate", tone: "operate", order: 1 },
  observe: { label: "Observe", tone: "observe", order: 2 },
  disclose: { label: "Disclose", tone: "disclose", order: 3 },
  real: { label: "Operate", tone: "operate", order: 1 },
  disclosure: { label: "Disclose", tone: "disclose", order: 3 },
};

export const featureMaturityLabels: Record<string, string> = {
  served: "Served",
  conditional: "Conditional",
  partial: "Partial",
  library: "Library-only",
  roadmap: "Roadmap",
};

export const agentStatus: Record<string, StatusDescriptor> = {
  online: { label: "online", tone: "success", order: 1 },
  degraded: { label: "degraded", tone: "warning", order: 2 },
  offline: { label: "offline", tone: "neutral", order: 3 },
};

export const deliveryStatus: Record<string, StatusDescriptor> = {
  pending: { label: "pending", tone: "observe", order: 1 },
  processing: { label: "processing", tone: "operate", order: 2 },
  delivered: { label: "delivered", tone: "success", order: 3 },
  failed: { label: "failed", tone: "critical", order: 4 },
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
