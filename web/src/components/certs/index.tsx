import { useState } from "react";
import { cn } from "@/lib/utils";
import { StatTile, Meter, BucketBar, type BucketDatum } from "@/components/charts";
import { DashboardGrid, SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatusBadge } from "@/components/StatusBadge";
import { expiryBandForDate, type StatusTone } from "@/lib/statusVocab";
import type { Certificate, ConnectorDelivery, RotationRun } from "@/lib/api";
import type { RiskItem } from "@/components/risk";

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
    { label: "Expired", value: expired, tone: "critical" },
    { label: "<=7d", value: within7, tone: "critical" },
    { label: "8-30d", value: within30, tone: "warning" },
    { label: "31-90d", value: within90, tone: "info" },
    { label: "90d+", value: beyond, tone: "low" },
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
      <SectionCard title="Expiring certificates" description="by time to expiry">
        <BucketBar ariaLabel="Certificates by time to expiry" data={buckets} />
      </SectionCard>
      <SectionCard title="Needs attention" description="expiring within 30 days, soonest first">
        {attention.length === 0 ? (
          <p className="text-caption text-muted-foreground">Nothing expiring in the next 30 days.</p>
        ) : (
          <AttentionList ariaLabel="Certificates needing attention">
            {attention.map(({ certificate, days }) => (
              <AttentionRow key={certificate.id}>
                <span className="flex-1 truncate font-mono text-caption">{certificate.subject}</span>
                <span className="w-40 truncate text-muted-foreground">{certificate.issuer ?? "—"}</span>
                <StatusBadge vocabulary="expiry" value={expiryBandForDate(certificate.not_after)} />
                <span className="w-16 text-right tabular-nums">{Number.isFinite(days) ? `${days}d` : "—"}</span>
              </AttentionRow>
            ))}
          </AttentionList>
        )}
      </SectionCard>
    </div>
  );
}

export function ReadinessPanel({ certificates, rotationRuns }: { certificates: Certificate[]; rotationRuns: RotationRun[] }) {
  const fingerprints = rotationFingerprints(rotationRuns);
  const active = certificates.filter((certificate) => certificate.status !== "revoked");
  const auto = active.filter((certificate) => fingerprints.has(certificate.fingerprint)).length;
  const manual = Math.max(active.length - auto, 0);
  const pct = active.length ? Math.round((auto / active.length) * 100) : 0;
  const manualAtRisk = active.filter((certificate) => !fingerprints.has(certificate.fingerprint) && daysUntil(certificate.not_after) <= 47).length;
  return (
    <SectionCard title="47-day renewal readiness" description="short-lived certificates require automation">
      <div className="flex items-baseline gap-2">
        <span className="text-[2.25rem] font-semibold leading-none tabular-nums">{pct}%</span>
        <span className="text-body text-muted-foreground">of certificates auto-renew</span>
      </div>
      <p className="mt-1 text-caption text-risk-high">{manualAtRisk} manual certs expiring within 47 days</p>
      <Meter
        className="mt-3"
        ariaLabel="Auto-renew vs manual"
        segments={[
          { value: auto, tone: "success", label: "auto" },
          { value: manual, tone: "warning", label: "manual" },
        ]}
      />
      <div className="mt-2 flex justify-between text-caption text-muted-foreground">
        <span>398d today</span>
        <span>200d · 2026</span>
        <span>100d · 2027</span>
        <span>47d · 2029</span>
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
    <SectionCard title="47-day readiness simulator" description="model your fleet against shorter validity caps">
      <div role="group" aria-label="Validity cap" className="flex gap-2">
        {[200, 100, 47].map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={cap === value}
            onClick={() => setCap(value)}
            className={cn("min-h-9 rounded-control border px-3 text-body", cap === value ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background")}
          >
            {value}-day
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
    <SectionCard title="Recent deployments" description="last-mile connector delivery receipts">
      {recent.length === 0 ? (
        <p className="text-caption text-muted-foreground">No deployment receipts yet.</p>
      ) : (
        <AttentionList ariaLabel="Connector delivery receipts">
          {recent.map((receipt) => (
            <AttentionRow key={receipt.id}>
              <span className="flex-1 truncate">
                {receipt.connector} <span className="text-muted-foreground">→ {receipt.target || receipt.destination}</span>
              </span>
              <StatusBadge value={receipt.status} label={receipt.status} tone={deliveryTone(receipt.status)} />
              {receipt.rollback_ref ? <span className="w-44 truncate text-caption text-muted-foreground">rollback: {receipt.rollback_ref}</span> : null}
            </AttentionRow>
          ))}
        </AttentionList>
      )}
    </SectionCard>
  );
}

export function RenewalHistory({ runs }: { runs: RotationRun[] }) {
  if (runs.length === 0) {
    return <p className="text-caption text-muted-foreground">No renewal history for this certificate yet.</p>;
  }
  return (
    <AttentionList ariaLabel="Renewal history">
      {runs.map((renewal) => (
        <AttentionRow key={renewal.id}>
          <StatusBadge value={renewal.status} label={renewal.status} tone={runTone(renewal.status)} />
          <span className="flex-1 truncate text-caption text-muted-foreground">
            {renewal.trigger}
            {renewal.reason ? ` · ${renewal.reason}` : ""}
          </span>
          <span className="w-44 truncate text-caption text-muted-foreground">{renewal.completed_at ?? renewal.created_at}</span>
        </AttentionRow>
      ))}
    </AttentionList>
  );
}
