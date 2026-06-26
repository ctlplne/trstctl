import { DashboardGrid } from "@/components/dashboard";
import { StatTile, Meter } from "@/components/charts";
import type { CBOMMigrationProgress } from "@/lib/api";

/** PQCReadinessSummary turns the CBOM migration_progress projection into the
 * crypto-agility "are we quantum-safe yet?" gauge: one readiness bar plus the
 * four counts that frame a NIST/NCSC migration program. It is a pure summary —
 * it renders no per-asset rows, so it sits above the readiness table without
 * duplicating it. */
export function PQCReadinessSummary({ progress }: { progress: CBOMMigrationProgress }) {
  const pct = Math.max(0, Math.min(100, Math.round(progress.percent_migrated ?? 0)));
  return (
    <div className="grid gap-4">
      <div className="grid gap-1">
        <div className="flex items-baseline justify-between gap-3">
          <p className="text-caption text-muted-foreground">PQC migration readiness (NIST FIPS 203/204 framing)</p>
          <p className="text-body font-semibold tabular-nums">{pct}%</p>
        </div>
        <Meter
          ariaLabel="PQC migration readiness"
          segments={[
            { label: "PQC-ready", value: pct, tone: "success" },
            { label: "Remaining", value: 100 - pct, tone: "neutral" },
          ]}
        />
      </div>
      <DashboardGrid>
        <StatTile label="Crypto assets" value={progress.total_assets} />
        <StatTile
          label="Quantum-vulnerable assets"
          value={progress.quantum_vulnerable_assets}
          tone={progress.quantum_vulnerable_assets ? "critical" : undefined}
        />
        <StatTile label="PQC-ready assets" value={progress.post_quantum_ready_assets} tone="success" />
        <StatTile label="Out-of-policy assets" value={progress.out_of_policy_assets} tone={progress.out_of_policy_assets ? "warning" : undefined} />
      </DashboardGrid>
    </div>
  );
}
