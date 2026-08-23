import { translateNow } from "@/i18n/I18nProvider";
export type StatusTone = "operate" | "observe" | "disclose" | "success" | "warning" | "critical" | "high" | "medium" | "low" | "neutral" | "info";

export type StatusVocabulary = "agent" | "certificate" | "delivery" | "discovery" | "expiry" | "honesty" | "lifecycle" | "risk";

export type StatusDescriptor = {
  label: string;
  tone: StatusTone;
  order?: number;
};

export const lifecycleStatus: Record<string, StatusDescriptor> = {
  requested: {
    get label() {
      return translateNow("source.requested.c6a91ee7f9");
    },
    tone: "observe",
    order: 1,
  },
  approved: {
    get label() {
      return translateNow("source.approved.2687f86ed6");
    },
    tone: "operate",
    order: 2,
  },
  issued: {
    get label() {
      return translateNow("source.issued.c91a3cc769");
    },
    tone: "success",
    order: 3,
  },
  deployed: {
    get label() {
      return translateNow("source.deployed.c1fa83ed9f");
    },
    tone: "success",
    order: 4,
  },
  renewing: {
    get label() {
      return translateNow("source.renewing.7c0bdbad43");
    },
    tone: "warning",
    order: 5,
  },
  revoked: {
    get label() {
      return translateNow("source.revoked.4bb47f186d");
    },
    tone: "critical",
    order: 6,
  },
  retired: {
    get label() {
      return translateNow("source.retired.5b720147b6");
    },
    tone: "neutral",
    order: 7,
  },
};

export const certificateStatus: Record<string, StatusDescriptor> = {
  active: {
    get label() {
      return translateNow("source.active.9687961165");
    },
    tone: "success",
    order: 1,
  },
  superseded: {
    get label() {
      return translateNow("source.superseded.444bd9c51d");
    },
    tone: "neutral",
    order: 2,
  },
  revoked: {
    get label() {
      return translateNow("source.revoked.4bb47f186d");
    },
    tone: "critical",
    order: 3,
  },
};

export const riskBands: Record<string, StatusDescriptor> = {
  critical: {
    get label() {
      return translateNow("source.critical.427dd2969b");
    },
    tone: "critical",
    order: 1,
  },
  high: {
    get label() {
      return translateNow("source.high.c4ebc6d4a5");
    },
    tone: "high",
    order: 2,
  },
  medium: {
    get label() {
      return translateNow("source.medium.8e588cd187");
    },
    tone: "medium",
    order: 3,
  },
  low: {
    get label() {
      return translateNow("source.low.f793de205e");
    },
    tone: "low",
    order: 4,
  },
  none: {
    get label() {
      return translateNow("source.none.dc937b5989");
    },
    tone: "neutral",
    order: 5,
  },
};

export const expiryBands: Record<string, StatusDescriptor> = {
  expired: {
    get label() {
      return translateNow("source.expired.424a2551d3");
    },
    tone: "critical",
    order: 1,
  },
  critical: {
    get label() {
      return translateNow("source.7d.critical.b43c284b63");
    },
    tone: "critical",
    order: 2,
  },
  watch: {
    get label() {
      return translateNow("source.7.30d.watch.7ecf4fbde2");
    },
    tone: "warning",
    order: 3,
  },
  planned: {
    get label() {
      return translateNow("source.30.90d.planned.be92bb89d8");
    },
    tone: "info",
    order: 4,
  },
  healthy: {
    get label() {
      return translateNow("source.90d.healthy.af665501c4");
    },
    tone: "success",
    order: 5,
  },
  unknown: {
    get label() {
      return translateNow("source.no.expiry.fe06351db8");
    },
    tone: "neutral",
    order: 6,
  },
};

export const honestyModes: Record<string, StatusDescriptor> = {
  operate: {
    get label() {
      return translateNow("source.operate.58c3939c4c");
    },
    tone: "operate",
    order: 1,
  },
  observe: {
    get label() {
      return translateNow("source.observe.744ea732e2");
    },
    tone: "observe",
    order: 2,
  },
  disclose: {
    get label() {
      return translateNow("source.disclose.5e663b5c89");
    },
    tone: "disclose",
    order: 3,
  },
  real: {
    get label() {
      return translateNow("source.operate.58c3939c4c");
    },
    tone: "operate",
    order: 1,
  },
  disclosure: {
    get label() {
      return translateNow("source.disclose.5e663b5c89");
    },
    tone: "disclose",
    order: 3,
  },
};

export const featureMaturityLabels: Record<string, string> = {
  served: "Served",
  conditional: "Conditional",
  partial: "Partial",
  library: "Library-only",
  roadmap: "Roadmap",
};

export const agentStatus: Record<string, StatusDescriptor> = {
  online: {
    get label() {
      return translateNow("source.online.f6fc84c9f2");
    },
    tone: "success",
    order: 1,
  },
  degraded: {
    get label() {
      return translateNow("source.degraded.3c8cab8b47");
    },
    tone: "warning",
    order: 2,
  },
  offline: {
    get label() {
      return translateNow("source.offline.8e2c7ac508");
    },
    tone: "neutral",
    order: 3,
  },
  offboarded: {
    get label() {
      return translateNow("source.offboarded.1e493e6cf3");
    },
    tone: "neutral",
    order: 4,
  },
};

export const discoveryStatus: Record<string, StatusDescriptor> = {
  unmanaged: {
    get label() {
      return translateNow("discovery.findings.statusUnmanaged");
    },
    tone: "critical",
    order: 1,
  },
  investigating: {
    get label() {
      return translateNow("discovery.findings.statusInvestigating");
    },
    tone: "warning",
    order: 2,
  },
  managed: {
    get label() {
      return translateNow("discovery.findings.statusManaged");
    },
    tone: "success",
    order: 3,
  },
  dismissed: {
    get label() {
      return translateNow("discovery.findings.statusDismissed");
    },
    tone: "neutral",
    order: 4,
  },
};

export const deliveryStatus: Record<string, StatusDescriptor> = {
  pending: {
    get label() {
      return translateNow("source.pending.62a2fed3d6");
    },
    tone: "observe",
    order: 1,
  },
  processing: {
    get label() {
      return translateNow("source.processing.0a63dd9aa0");
    },
    tone: "operate",
    order: 2,
  },
  delivered: {
    get label() {
      return translateNow("source.delivered.373e0712c8");
    },
    tone: "success",
    order: 3,
  },
  failed: {
    get label() {
      return translateNow("source.failed.5d28a90f44");
    },
    tone: "critical",
    order: 4,
  },
  // Connector delivery receipt statuses. These labels are the operator-facing
  // half of the served status vocabulary in internal/servedstatus: a status is a
  // claim, so the badge says exactly what the code did. config_validated and
  // rollback_recorded deliberately are not success tones — nothing reached the
  // target on either path (truth-integrity 3 and 4). They turn green when epics
  // D5 and D4 make them a real dry-run and a real executed restore.
  queued: {
    get label() {
      return translateNow("source.queued.661ff40a07");
    },
    tone: "observe",
    order: 1,
  },
  config_validated: {
    get label() {
      return translateNow("source.config.validated.target.not.contacted.983573f318");
    },
    tone: "info",
    order: 5,
  },
  // D5 dry-run statuses. dry_run_planned is the first of these that may read as
  // success, and it earns it honestly: a relay reached the target, resolved
  // every credential a deploy needs, and returned the mutation plan. It still
  // says "would" rather than "did", because nothing was changed.
  dry_run_queued: {
    get label() {
      return translateNow("source.dry.run.queued.d5dry00001");
    },
    tone: "observe",
    order: 2,
  },
  dry_run_planned: {
    get label() {
      return translateNow("source.dry.run.planned.d5dry00002");
    },
    tone: "success",
    order: 6,
  },
  dry_run_blocked: {
    get label() {
      return translateNow("source.dry.run.blocked.d5dry00003");
    },
    tone: "critical",
    order: 7,
  },
  // Retired spelling, still stored on receipts written before the rename, so the
  // console must keep rendering it rather than falling back to a raw string.
  test_succeeded: {
    get label() {
      return translateNow("source.config.validated.legacy.label.2387440f43");
    },
    tone: "info",
    order: 5,
  },
  rollback_recorded: {
    get label() {
      return translateNow("source.rollback.attested.not.executed.7bf8b3ca82");
    },
    tone: "warning",
    order: 6,
  },
  // D4: a rollback that will actually execute. Queued is deliberately NOT a
  // success tone — no agent has reported, so the listener is unchanged so far
  // as this control plane knows.
  rollback_queued: {
    get label() {
      return translateNow("source.rollback.queued.d4rb000001");
    },
    tone: "info",
    order: 7,
  },
  // Success, and the only rollback state that earns it: an agent performed the
  // family-specific predecessor restore. The receipt detail says separately
  // whether the configured listener was reverified.
  rolled_back: {
    get label() {
      return translateNow("source.rolled.back.d4rb000002");
    },
    tone: "success",
    order: 8,
  },
};

export const statusVocabulary: Record<StatusVocabulary, Record<string, StatusDescriptor>> = {
  agent: agentStatus,
  certificate: certificateStatus,
  delivery: deliveryStatus,
  discovery: discoveryStatus,
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
