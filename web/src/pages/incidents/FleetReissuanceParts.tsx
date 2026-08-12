import { Download, Pause, Play, RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";
import type { FleetReissuanceRun } from "@/lib/api";

export function FleetReissuanceTable({
  runs,
  action,
  onAction,
}: {
  runs: FleetReissuanceRun[];
  action: string | null;
  onAction: (kind: "pause" | "resume" | "rollback" | "evidence", run: FleetReissuanceRun) => void;
}) {
  if (runs.length === 0) {
    return <p className="text-sm text-muted-foreground">{translateNow("source.no.fleet.reissuance.runs.have.been.recorde.0f1169b466")}</p>;
  }
  return (
    <div className="overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[76rem]">
        <caption className="sr-only">{translateNow("source.fleet.reissuance.runs.c1afb05039")}</caption>
        <thead>
          <tr>
            <th scope="col">{translateNow("source.run.00d60e31a4")}</th>
            <th scope="col">{translateNow("source.issuer.39e02c46a0")}</th>
            <th scope="col">{translateNow("source.status.920e413c7d")}</th>
            <th scope="col">{translateNow("source.scope.b073f6c68e")}</th>
            <th scope="col">{translateNow("source.batches.56a8df948f")}</th>
            <th scope="col">{translateNow("source.failed.targets.4ffa850540")}</th>
            <th scope="col">{translateNow("source.evidence.03867aea70")}</th>
            <th scope="col">{translateNow("source.actions.ff8059dc67")}</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id} className="align-top">
              <td className="font-mono text-xs">{run.id}</td>
              <td className="font-mono text-xs">{run.issuer_id}</td>
              <td>
                <p className="font-medium">{run.status}</p>
                <p className="text-xs text-muted-foreground">{run.phase}</p>
                {run.halted_reason && (
                  <p className="mt-1 max-w-[22rem] text-xs text-danger" role="alert">
                    {run.halted_reason}
                  </p>
                )}
              </td>
              <td>
                <p>
                  {run.affected_identity_ids.length} {translateNow("source.affected.19b6357dad")}
                </p>
                <p className="text-xs text-muted-foreground">
                  {run.revoked_identity_ids.length} {translateNow("source.revoked.4bb47f186d")}
                </p>
                <p className="text-xs text-muted-foreground">
                  {run.mode} · {translateNow("source.trusted.by.count.h1trust0002", {
                    value1: run.exact_trust_store_ids?.length ?? 0,
                    value2: run.exact_trust_hosts?.length ?? 0,
                  })}
                </p>
                {(run.candidate_trust_store_ids?.length ?? 0) > 0 && (
                  <p className="text-xs text-warning">
                    {run.candidate_trust_store_ids.length} {translateNow("source.candidate.ca.fingerprint.78e53d126d")} ·{" "}
                    {translateNow("source.not.verified.j2dr000008")}
                  </p>
                )}
                {run.plan_digest && (
                  <p className="max-w-[16rem] truncate font-mono text-xs text-muted-foreground">
                    {translateNow("source.plan.fa8ed0bdab")} {run.plan_digest}
                  </p>
                )}
              </td>
              <td>
                <p>
                  {run.batch_count} {translateNow("source.batches.467629e63d")}
                </p>
                <p className="text-xs text-muted-foreground">
                  {translateNow("source.batches.56a8df948f")}{" "}
                  {translateNow("source.value1.value2.7d8908f134", { value1: run.next_batch_index, value2: run.batch_count })}
                </p>
                <p className="text-xs text-muted-foreground">{run.health_gates.map((gate) => `${gate.name}:${gate.status}`).join(", ")}</p>
              </td>
              <td>{run.failed_targets?.length ? run.failed_targets.join(", ") : translateNow("source.none.140bedbf9c")}</td>
              <td>
                <p className="font-medium">{run.evidence_bundle_format || translateNow("source.unavailable.ba691ba042")}</p>
                <p className="max-w-[14rem] truncate font-mono text-xs text-muted-foreground">{run.evidence_bundle || "-"}</p>
              </td>
              <td>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("pause", run)}
                    disabled={action === `pause:${run.id}` || Boolean(run.migration_run_id && run.status !== "running")}
                    aria-label={translateNow("source.pause.fleet.run.value1.225d7f781f", { value1: shortId(run.id) })}
                  >
                    <Pause className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("resume", run)}
                    disabled={action === `resume:${run.id}` || Boolean(run.migration_run_id && run.status !== "paused")}
                    aria-label={translateNow("source.resume.fleet.run.value1.82d98d67fc", { value1: shortId(run.id) })}
                  >
                    <Play className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("rollback", run)}
                    disabled={action === `rollback:${run.id}` || Boolean(run.migration_run_id && !["running", "paused", "halted"].includes(run.status))}
                    aria-label={translateNow("source.rollback.fleet.run.value1.21446f0a1d", { value1: shortId(run.id) })}
                  >
                    <RotateCcw className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("evidence", run)}
                    disabled={action === `evidence:${run.id}` || Boolean(run.migration_run_id && run.evidence_bundle_format !== "jws")}
                    aria-label={translateNow("source.export.fleet.run.value1.evidence.6065920a10", { value1: shortId(run.id) })}
                  >
                    <Download className="h-4 w-4" aria-hidden="true" />
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}
