import { useState } from "react";
import { api, type MigrationAssessment, type MigrationRun, type MigrationRunStartRequest } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";
import { translateNow } from "@/i18n/I18nProvider";

const defaultManifest =
  '{"plan_id":"ca-rollover-2026","new_authority_id":"00000000-0000-4000-8000-000000000000","waves":[{"id":"canary","ordinal":1,"members":[{"identity_id":"","agent_id":"","trust_anchor_path":"/etc/trstctl/next-root.pem"}]}]}';

// Assessment and execution are separate operator decisions. The server still
// owns every exact-agent trust and live-listener gate; this page cannot skip one.
export function Migration() {
  const runs = useApiQuery(["migration-runs"], api.migrationRuns);
  const [manifest, setManifest] = useState(defaultManifest);
  const [assessment, setAssessment] = useState<MigrationAssessment | null>(null);
  const [reviewed, setReviewed] = useState<MigrationRunStartRequest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function perform(operation: "assess" | "start" | "pause" | "resume" | "rollback", run?: MigrationRun) {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      if (operation === "assess") {
        const request = parseManifest(manifest);
        if (!request) throw new Error();
        setAssessment(
          await api.assessMigration({
            plan_id: request.plan_id,
            require_full_trust: true,
            waves: request.waves.map((wave) => ({ ...wave, members: wave.members.map((member) => member.identity_id) })),
          }),
        );
        setReviewed(request);
      } else if (operation === "start" && reviewed) {
        await api.startMigrationRun(reviewed);
        setAssessment(null);
        setReviewed(null);
        runs.refetch();
      } else if (run) {
        if (operation === "pause") await api.pauseMigrationRun(run.id);
        else if (operation === "resume") await api.resumeMigrationRun(run.id);
        else await api.rollbackMigrationRun(run.id);
        runs.refetch();
      }
    } catch {
      setError(translateNow("source.migration.h2mig00001"));
    } finally {
      setBusy(false);
    }
  }

  const ready = Boolean(assessment && assessment.unknowns.length === 0 && assessment.migratable === assessment.members);
  const problem = error ?? runs.error;

  return (
    <section aria-labelledby="migration-heading" className="space-y-6">
      <PageHeader
        titleId="migration-heading"
        title={translateNow("source.migration.h2mig00001")}
        description={translateNow("source.migration.description.h2mig00002")}
      />
      {problem && <ErrorState title={translateNow("source.migration.h2mig00001")}>{problem}</ErrorState>}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_28rem]">
        <form
          className="ui-panel space-y-3 p-comfortable"
          onSubmit={(event) => {
            event.preventDefault();
            void perform("assess");
          }}
        >
          <label htmlFor="migration-plan" className="grid gap-1 text-sm font-medium">
            {translateNow("source.migration.plan.h2mig00003")}
            <Textarea id="migration-plan" className="min-h-64 font-mono text-xs" value={manifest} onChange={(event) => setManifest(event.target.value)} />
          </label>
          <Button type="submit" disabled={busy}>
            {translateNow("source.migration.assess.h2mig00004")}
          </Button>
          <p className="text-caption text-muted-foreground">{translateNow("source.migration.readonly.h2mig00005")}</p>
        </form>

        <div className="space-y-5">
          {assessment && (
            <section aria-labelledby="assessment-heading" className="ui-panel space-y-2 p-comfortable text-sm">
              <h2 id="assessment-heading" className="font-semibold">
                {translateNow("source.migration.assess.h2mig00004")}
              </h2>
              <p>
                {translateNow("source.migration.counts.h2mig00008", {
                  value1: String(assessment.migratable),
                  value2: String(assessment.members),
                })}
              </p>
              <p className="text-caption text-muted-foreground">{assessment.guidance}</p>
              {assessment.unknowns.map((unknown, index) => (
                <p key={`${unknown.member}:${unknown.kind}:${index}`}>
                  <code>{unknown.member}</code> · {unknown.detail}
                </p>
              ))}
            </section>
          )}
          {reviewed && ready && (
            <section aria-labelledby="migration-review" className="ui-panel space-y-3 p-comfortable">
              <h2 id="migration-review" className="text-title font-semibold">
                {translateNow("source.migration.plan.h2mig00003")}
              </h2>
              <p className="text-sm">{reviewed.plan_id}</p>
              <p className="text-sm">
                {translateNow("source.authority.c4xr000007")}: <code>{reviewed.new_authority_id}</code>
              </p>
              <p className="text-sm">
                {translateNow("source.migration.waves.h2mig00009")}: {reviewed.waves.length}
              </p>
              <p className="text-caption text-muted-foreground">
                <code>{JSON.stringify(reviewed.waves)}</code>
              </p>
              <Button type="button" disabled={busy} onClick={() => void perform("start")}>
                {translateNow("posture.pqcMigration.start")}
              </Button>
            </section>
          )}
        </div>
      </div>

      <section aria-labelledby="migration-runs" className="space-y-3">
        <h2 id="migration-runs" className="text-title font-semibold">
          {translateNow("source.runs.848f54e896")}
        </h2>
        <div className="grid gap-4">
          {runs.data?.items.map((run) => (
            <article key={run.id} className="ui-panel space-y-3 p-comfortable">
              <h3 className="font-semibold">{run.plan_id || run.id}</h3>
              <p className="text-caption text-muted-foreground">
                <code>{run.id}</code> · {run.status}
              </p>
              <ul className="space-y-2 text-sm">
                {run.waves.map((wave) => {
                  const verification = waveVerification(wave);
                  return (
                    <li key={wave.id}>
                      <strong>{wave.id}</strong> · {wave.phase} · {wave.members.length} · {verification.percent}% ({verification.verified}/{verification.total})
                      <div className="text-caption text-muted-foreground">{wave.members.map((member) => member.identity_id).join(", ")}</div>
                    </li>
                  );
                })}
              </ul>
              <div className="flex flex-wrap gap-2">
                {run.status === "running" && (
                  <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void perform("pause", run)}>
                    {translateNow("source.pause.fleet.run.value1.225d7f781f", { value1: run.plan_id || run.id })}
                  </Button>
                )}
                {run.status === "paused" && (
                  <Button type="button" size="sm" disabled={busy} onClick={() => void perform("resume", run)}>
                    {translateNow("source.resume.fleet.run.value1.82d98d67fc", { value1: run.plan_id || run.id })}
                  </Button>
                )}
                {["running", "paused", "halted", "complete"].includes(run.status) && (
                  <Button type="button" size="sm" variant="destructive-outline" disabled={busy} onClick={() => void perform("rollback", run)}>
                    {translateNow("source.rollback.c591f55749")}
                  </Button>
                )}
              </div>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}

function parseManifest(value: string): MigrationRunStartRequest | null {
  try {
    const request = JSON.parse(value) as MigrationRunStartRequest;
    const validMembers = request.waves?.every((wave) => wave.members?.every((member) => member.identity_id && member.agent_id && member.trust_anchor_path));
    return request.plan_id && request.new_authority_id && request.waves?.length && validMembers ? request : null;
  } catch {
    return null;
  }
}

function waveVerification(wave: MigrationRun["waves"][number]): { percent: number; verified: number; total: number } {
  const total = wave.members.length * 2;
  const verified = wave.members.reduce(
    (count, member) => count + Number(member.trust_verdict === "verified") + Number(member.successor_verdict === "verified"),
    0,
  );
  return { verified, total, percent: total === 0 ? 0 : Math.floor((verified * 100) / total) };
}

export default Migration;
