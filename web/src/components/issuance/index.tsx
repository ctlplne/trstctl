import { DashboardGrid, SectionCard } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import type { Identity } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

const STAGE_ORDER = ["requested", "pending", "pending_approval", "approved", "issued", "deployed", "active", "renewing", "expiring", "revoked", "retired"];

function orderIndex(stage: string): number {
  const index = STAGE_ORDER.indexOf(stage);
  return index === -1 ? STAGE_ORDER.length : index;
}

function stageLabel(stage: string): string {
  const text = stage.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function pipelineStages(identities: Identity[]): Array<{ stage: string; count: number }> {
  const counts = new Map<string, number>();
  for (const identity of identities) {
    const stage = identity.status;
    counts.set(stage, (counts.get(stage) ?? 0) + 1);
  }
  return [...counts.entries()].map(([stage, count]) => ({ stage, count })).sort((a, b) => orderIndex(a.stage) - orderIndex(b.stage));
}

export function IssuancePipeline({ identities }: { identities: Identity[] }) {
  const stages = pipelineStages(identities);
  if (stages.length === 0) return null;
  return (
    <SectionCard title={translateNow("identities.health.title")} description={translateNow("identities.health.description")} className="mb-4">
      <DashboardGrid>
        {stages.map(({ stage, count }) => (
          <StatTile key={stage} label={stageLabel(stage)} value={count} />
        ))}
      </DashboardGrid>
    </SectionCard>
  );
}
