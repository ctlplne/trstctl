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

export function CTDriftPanel({ findings, sources }: { findings: DiscoveryFinding[]; sources: DiscoverySource[] }) {
  const monitoredSourceIds = new Set(sources.filter((source) => source.kind === "ct_log" || source.kind === "drift").map((source) => source.id));
  const monitored = findings.filter((finding) => monitoredSourceIds.has(finding.source_id)).length;
  return (
    <SectionCard title={translateNow("source.ct.log.drift.monitoring.82c2bb4d3f")} description="certificate-transparency and configuration-drift findings">
      <DashboardGrid>
        <StatTile label="CT-log & drift findings" value={monitored} tone={monitored ? "warning" : undefined} />
      </DashboardGrid>
    </SectionCard>
  );
}
