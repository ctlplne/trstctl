import { SectionCard, DashboardGrid } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import type { DiscoveryFinding, DiscoverySource } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

function kindCounts(findings: DiscoveryFinding[]): Array<[string, number]> {
  const map = new Map<string, number>();
  for (const finding of findings) map.set(finding.kind, (map.get(finding.kind) ?? 0) + 1);
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

export function DiscoveryHero({ findings }: { findings: DiscoveryFinding[] }) {
  const kinds = kindCounts(findings);
  const highRisk = findings.filter((finding) => (finding.risk_score ?? 0) >= 70).length;
  return (
    <SectionCard title={translateNow("source.shadow.inventory.fd12d94cc1")} description="unmanaged credentials discovered across your environments">
      <DashboardGrid>
        <StatTile label="Shadow findings" value={findings.length} />
        <StatTile label="High risk" value={highRisk} tone={highRisk ? "high" : undefined} />
        <StatTile label="Finding types" value={kinds.length} />
      </DashboardGrid>
    </SectionCard>
  );
}

// C5: certificate transparency used to share this tile with drift detection —
// one number labelled "CT-log & drift findings", which is not a capability, it
// is a footnote. CT monitoring now has its own surface (CTMonitoringPanel) and
// this counts drift alone, so neither number is diluted by the other.
export function DriftPanel({ findings, sources }: { findings: DiscoveryFinding[]; sources: DiscoverySource[] }) {
  const driftSourceIds = new Set(sources.filter((source) => source.kind === "drift").map((source) => source.id));
  const drift = findings.filter((finding) => driftSourceIds.has(finding.source_id)).length;
  return (
    <SectionCard title={translateNow("source.configuration.drift.9e0db44c38")} description="credentials that no longer match the state trstctl declared">
      <DashboardGrid>
        <StatTile label="Drift findings" value={drift} tone={drift ? "warning" : undefined} />
      </DashboardGrid>
    </SectionCard>
  );
}

export { CTMonitoringPanel } from "./CTMonitoringPanel";
