import { useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { StatTile, Meter, BucketBar, type BucketDatum } from "@/components/charts";
import { DashboardGrid, SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatusBadge } from "@/components/StatusBadge";
import { validityBandForDates, type StatusTone } from "@/lib/statusVocab";
import type { Certificate, ConnectorDelivery, RotationRun } from "@/lib/api";
import type { RiskItem } from "@/components/risk";
import { translateNow } from "@/i18n/I18nProvider";

const DAY = 86_400_000;

export function daysUntil(notAfter?: string): number {
  if (!notAfter) return Infinity;
  const time = new Date(notAfter).getTime();
  if (Number.isNaN(time)) return Infinity;
  return Math.ceil((time - Date.now()) / DAY);
}

function expiryBuckets(certificates: Certificate[]): BucketDatum[] {
  let expired = 0;
  let within7 = 0;
  let within30 = 0;
  let within90 = 0;
  let beyond = 0;
  for (const certificate of certificates) {
    if (certificate.status === "revoked") continue;
    const days = daysUntil(certificate.not_after);
    if (days < 0) expired += 1;
    else if (days <= 7) within7 += 1;
    else if (days <= 30) within30 += 1;
    else if (days <= 90) within90 += 1;
    else beyond += 1;
  }
  return [
    { label: translateNow("source.expired.424a2551d3"), value: expired, tone: "critical" },
    { label: "<=7d", value: within7, tone: "critical" },
    { label: translateNow("source.8.30d.3a1c0beb22"), value: within30, tone: "warning" },
    { label: translateNow("source.31.90d.149111f115"), value: within90, tone: "info" },
    { label: translateNow("source.90d.460c87f2aa"), value: beyond, tone: "low" },
  ];
}

function rotationFingerprints(runs: RotationRun[]): Set<string> {
  const fingerprints = new Set<string>();
  for (const run of runs) {
    if (run.successor_fingerprint) fingerprints.add(run.successor_fingerprint);
    if (run.predecessor_fingerprint) fingerprints.add(run.predecessor_fingerprint);
  }
  return fingerprints;
}

export function autoRenewingCount(certificates: Certificate[], runs: RotationRun[]): number {
  const fingerprints = rotationFingerprints(runs);
  return certificates.filter((certificate) => certificate.status !== "revoked" && fingerprints.has(certificate.fingerprint)).length;
}

export function CertKpis({ certificates, risks }: { certificates: Certificate[]; risks: RiskItem[] }) {
  const active = certificates.filter((certificate) => certificate.status !== "revoked");
  const expiring7 = active.filter((certificate) => {
    const days = daysUntil(certificate.not_after);
    return days >= 0 && days <= 7;
  }).length;
  const expiring30 = active.filter((certificate) => {
    const days = daysUntil(certificate.not_after);
    return days >= 0 && days <= 30;
  }).length;
  const revoked = certificates.filter((certificate) => certificate.status === "revoked").length;
  const highRisk = risks.filter((risk) => (risk.score ?? 0) >= 70).length;
  // Total + expiring counts intentionally live on the server-backed estate
  // health panel (one KPI strip per page — the two used to double-count the
  // same estate as "Total inventory" vs "Total certificates").
  void expiring7;
  void expiring30;
  return (
    <DashboardGrid>
      <StatTile label="Revoked" value={revoked} />
      <StatTile label="High risk" value={highRisk} tone={highRisk ? "high" : undefined} />
    </DashboardGrid>
  );
}

export function CertificatesDashboard({ certificates, risks }: { certificates: Certificate[]; risks: RiskItem[] }) {
  const buckets = expiryBuckets(certificates);
  const attention = certificates
    .filter((certificate) => certificate.status !== "revoked")
    .map((certificate) => ({ certificate, days: daysUntil(certificate.not_after) }))
    .filter((entry) => entry.days <= 30)
    .sort((a, b) => a.days - b.days)
    .slice(0, 6);
  return (
    <div className="grid gap-4">
      <CertKpis certificates={certificates} risks={risks} />
      <SectionCard title={translateNow("source.expiring.certificates.73810831a4")} description="by time to expiry">
        <BucketBar ariaLabel="Certificates by time to expiry" data={buckets} />
      </SectionCard>
      <SectionCard title={translateNow("source.needs.attention.c1ebc78178")} description="expiring within 30 days, soonest first">
        {attention.length === 0 ? (
          <p className="text-caption text-muted-foreground">{translateNow("source.nothing.expiring.in.the.next.30.days.b4f1023cf6")}</p>
        ) : (
          <AttentionList ariaLabel="Certificates needing attention">
            {attention.map(({ certificate, days }) => (
              <AttentionRow key={certificate.id}>
                <span className="flex-1 truncate font-mono text-caption">{certificate.subject}</span>
                <span className="w-40 truncate text-muted-foreground">{certificate.issuer ?? "—"}</span>
                <StatusBadge vocabulary="expiry" value={validityBandForDates(certificate.not_before, certificate.not_after)} />
                <span className="w-16 text-right tabular-nums">
                  {Number.isFinite(days) ? translateNow("source.value1.d.eb20d8f12a", { value1: days }) : "—"}
                </span>
              </AttentionRow>
            ))}
          </AttentionList>
        )}
      </SectionCard>
    </div>
  );
}

export function ReadinessPanel({
  certificates,
  rotationRuns,
  actions,
}: {
  certificates: Certificate[];
  rotationRuns: RotationRun[];
  /** Optional header action — the global home passes a link into the
   * Certificates renewal-readiness tab (C-D1: numbers are doors). */
  actions?: ReactNode;
}) {
  const fingerprints = rotationFingerprints(rotationRuns);
  const active = certificates.filter((certificate) => certificate.status !== "revoked");
  const auto = active.filter((certificate) => fingerprints.has(certificate.fingerprint)).length;
  const manual = Math.max(active.length - auto, 0);
  const pct = active.length ? Math.round((auto / active.length) * 100) : 0;
  const manualAtRisk = active.filter((certificate) => !fingerprints.has(certificate.fingerprint) && daysUntil(certificate.not_after) <= 47).length;
  return (
    <SectionCard title={translateNow("source.47.day.renewal.readiness.971543ca36")} description="short-lived certificates require automation" actions={actions}>
      <div className="flex items-baseline gap-2">
        <span className="text-[2.25rem] font-semibold leading-none tabular-nums">{pct}%</span>
        <span className="text-body text-muted-foreground">{translateNow("source.of.certificates.auto.renew.02d35aa265")}</span>
      </div>
      <p className="mt-1 text-caption text-status-warning">
        {manualAtRisk} {translateNow("source.manual.certs.expiring.within.47.days.e57062b5bf")}
      </p>
      <Meter
        className="mt-3"
        ariaLabel="Auto-renew vs manual"
        segments={[
          { value: auto, tone: "success", label: translateNow("source.auto.929260ad9b") },
          { value: manual, tone: "warning", label: translateNow("source.manual.36bde66f28") },
        ]}
      />
      <div className="mt-2 flex justify-between text-caption text-muted-foreground">
        <span>{translateNow("certificates.readiness.current")}</span>
        <span>{translateNow("certificates.readiness.200DayModel")}</span>
        <span>{translateNow("certificates.readiness.100DayModel")}</span>
        <span>{translateNow("certificates.readiness.47DayTarget")}</span>
      </div>
    </SectionCard>
  );
}

export function ReadinessSimulator({ certificates, autoRenewing }: { certificates: Certificate[]; autoRenewing: number }) {
  const [cap, setCap] = useState(47);
  const active = certificates.filter((certificate) => certificate.status !== "revoked").length;
  const manual = Math.max(active - autoRenewing, 0);
  const renewalsPerYear = Math.ceil(365 / cap);
  const manualLoad = manual * renewalsPerYear;
  return (
    <SectionCard title={translateNow("source.47.day.readiness.simulator.6c79ae6d09")} description="model your fleet against shorter validity caps">
      <div role="group" aria-label={translateNow("source.validity.cap.1e61e889d2")} className="flex gap-2">
        {[200, 100, 47].map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={cap === value}
            onClick={() => setCap(value)}
            className={cn(
              "min-h-9 rounded-control border px-3 text-body",
              cap === value ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background",
            )}
          >
            {value}
            {translateNow("source.day.b396878953")}
          </button>
        ))}
      </div>
      <DashboardGrid className="mt-3">
        <StatTile label="Renewals per cert / year" value={renewalsPerYear} />
        <StatTile label="Manual renewal load / year" value={manualLoad} tone={manualLoad ? "warning" : undefined} />
        <StatTile label="Certs that would lapse" value={manual} tone={manual ? "critical" : undefined} hint="without automation" />
      </DashboardGrid>
    </SectionCard>
  );
}

function deliveryTone(status: ConnectorDelivery["status"]): StatusTone {
  if (status === "delivered") return "success";
  if (status === "failed") return "critical";
  return "neutral";
}

function runTone(status: RotationRun["status"]): StatusTone {
  if (status === "succeeded") return "success";
  if (status === "failed") return "critical";
  return "info";
}

export function DeploymentReceipts({ deliveries }: { deliveries: ConnectorDelivery[] }) {
  const recent = deliveries.slice(0, 8);
  return (
    <SectionCard title={translateNow("source.recent.deployments.df97a4e11f")} description="last-mile connector delivery receipts">
      {recent.length === 0 ? (
        <p className="text-caption text-muted-foreground">{translateNow("source.no.deployment.receipts.yet.439880ad78")}</p>
      ) : (
        <AttentionList ariaLabel="Connector delivery receipts">
          {recent.map((receipt) => (
            <AttentionRow key={receipt.id}>
              <span className="flex-1 truncate">
                {receipt.connector} <span className="text-muted-foreground">→ {receipt.target || receipt.destination}</span>
              </span>
              <StatusBadge value={receipt.status} label={receipt.status} tone={deliveryTone(receipt.status)} />
              {receipt.rollback_ref ? (
                <span className="w-44 truncate text-caption text-muted-foreground">
                  {translateNow("source.rollback.c48b9dea6f")} {receipt.rollback_ref}
                </span>
              ) : null}
            </AttentionRow>
          ))}
        </AttentionList>
      )}
    </SectionCard>
  );
}

export function RenewalHistory({ runs }: { runs: RotationRun[] }) {
  if (runs.length === 0) {
    return <p className="text-caption text-muted-foreground">{translateNow("source.no.renewal.history.for.this.certificate.ye.d731b9489d")}</p>;
  }
  return (
    <AttentionList ariaLabel="Renewal history">
      {runs.map((renewal) => (
        <AttentionRow key={renewal.id}>
          <StatusBadge value={renewal.status} label={renewal.status} tone={runTone(renewal.status)} />
          <span className="flex-1 truncate text-caption text-muted-foreground">
            {renewal.trigger}
            {renewal.reason ? translateNow("source.value1.d610afc356", { value1: renewal.reason }) : ""}
          </span>
          <span className="w-44 truncate text-caption text-muted-foreground">{renewal.completed_at ?? renewal.created_at}</span>
        </AttentionRow>
      ))}
    </AttentionList>
  );
}
