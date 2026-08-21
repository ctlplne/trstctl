import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, type MigrationAssessment, type MigrationRun, type MigrationRunStartRequest } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Dialog } from "@/components/Dialog";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";

const defaultManifest =
  '{"plan_id":"ca-rollover-2026","new_authority_id":"00000000-0000-4000-8000-000000000000","waves":[{"id":"canary","ordinal":1,"members":[{"identity_id":"","agent_id":"","trust_anchor_path":"/etc/trstctl/next-root.pem"}]}]}';

type Disclosure = "plan" | "gates" | "history";

// Assessment and execution are separate operator decisions. The server still
// owns every exact-agent trust and live-listener gate; this page cannot skip one.
export function Migration() {
  const { t } = useTranslation();
  const runs = useApiQuery(["migration-runs"], api.migrationRuns);
  const [manifest, setManifest] = useState(defaultManifest);
  const [assessment, setAssessment] = useState<MigrationAssessment | null>(null);
  const [reviewed, setReviewed] = useState<MigrationRunStartRequest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<Record<Disclosure, boolean>>({ plan: false, gates: false, history: false });
  const [rollbackRun, setRollbackRun] = useState<MigrationRun | null>(null);
  const planRef = useRef<HTMLTextAreaElement>(null);
  const confirmRollbackRef = useRef<HTMLButtonElement>(null);

  const runItems = runs.data?.items ?? [];
  const activeRuns = runItems.filter((run) => ["running", "paused", "halted", "rolling_back"].includes(run.status)).length;
  const attentionRuns = runItems.filter((run) => ["paused", "halted", "rolling_back"].includes(run.status)).length;
  const assessmentMatches = Boolean(assessment && reviewed && assessmentMatchesRequest(assessment, reviewed));
  const ready = Boolean(assessment && assessmentMatches && assessment.unknowns.length === 0 && assessment.migratable === assessment.members);
  const problem = error ?? runs.error;

  useEffect(() => {
    if (open.plan) planRef.current?.focus();
  }, [open.plan]);

  async function perform(operation: "assess" | "start" | "pause" | "resume" | "rollback", run?: MigrationRun) {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      if (operation === "assess") {
        const request = parseManifest(manifest);
        if (!request) {
          setError(t("migration.design.invalidPlan"));
          return;
        }
        setAssessment(
          await api.assessMigration({
            plan_id: request.plan_id,
            require_full_trust: true,
            waves: request.waves.map((wave) => ({ ...wave, members: wave.members.map((member) => member.identity_id) })),
          }),
        );
        setReviewed(request);
        setOpen((current) => ({ ...current, gates: true }));
      } else if (operation === "start" && reviewed) {
        await api.startMigrationRun(reviewed);
        setAssessment(null);
        setReviewed(null);
        setOpen((current) => ({ ...current, gates: false, history: true }));
        runs.refetch();
      } else if (run) {
        if (operation === "pause") await api.pauseMigrationRun(run.id);
        else if (operation === "resume") await api.resumeMigrationRun(run.id);
        else {
          await api.rollbackMigrationRun(run.id);
          setRollbackRun(null);
        }
        runs.refetch();
      }
    } catch {
      setError(t("migration.design.operationError"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="migration-heading" className="grid min-w-0 w-full max-w-full gap-4">
      <PageHeader
        titleId="migration-heading"
        title={translateNow("source.migration.h2mig00001")}
        description={t("migration.design.answer")}
        technicalDetails={t("migration.design.technicalDetails")}
        actions={
          <Button type="button" onClick={() => setOpen((current) => ({ ...current, plan: true }))}>
            {t("migration.design.startPlan")}
          </Button>
        }
      />

      {problem && <ErrorState title={translateNow("source.migration.h2mig00001")}>{problem}</ErrorState>}

      <div className="ui-panel grid gap-2 p-comfortable" aria-live="polite">
        {runs.loading ? (
          <LoadingState>{t("migration.design.checkingRuns")}</LoadingState>
        ) : runItems.length === 0 ? (
          <>
            <h2 className="text-title font-semibold">{t("migration.design.noRuns")}</h2>
            <p className="max-w-3xl text-caption text-muted-foreground">{t("migration.design.noRunsBody")}</p>
          </>
        ) : (
          <>
            <h2 className="text-title font-semibold">
              {runItems.length === 1 ? t("migration.design.runCountOne") : t("migration.design.runCountMany", { count: String(runItems.length) })}
            </h2>
            <p className="max-w-3xl text-caption text-muted-foreground">
              {t("migration.design.runSummary", { active: String(activeRuns), attention: String(attentionRuns) })}
            </p>
          </>
        )}
      </div>

      <MigrationDisclosure
        title={t("migration.design.disclosure.plan")}
        open={open.plan}
        onToggle={(value) => setOpen((current) => ({ ...current, plan: value }))}
      >
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void perform("assess");
          }}
        >
          <div className="grid gap-1">
            <label htmlFor="migration-plan" className="text-sm font-medium">
              {t("migration.design.planJson")}
            </label>
            <p id="migration-plan-help" className="text-caption text-muted-foreground">
              {t("migration.design.planHelp")}
            </p>
            <Textarea
              ref={planRef}
              id="migration-plan"
              aria-describedby="migration-plan-help"
              className="min-h-64 font-mono text-xs"
              value={manifest}
              onChange={(event) => {
                setManifest(event.target.value);
                setAssessment(null);
                setReviewed(null);
              }}
            />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" loading={busy}>
              {t("migration.design.assess")}
            </Button>
            <p className="text-caption text-muted-foreground">{t("migration.design.readOnly")}</p>
          </div>
        </form>
      </MigrationDisclosure>

      <MigrationDisclosure
        title={t("migration.design.disclosure.gates")}
        open={open.gates}
        onToggle={(value) => setOpen((current) => ({ ...current, gates: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("migration.design.dualRunBoundary")}</p>
          {!assessment ? (
            <EmptyState title={t("migration.design.noAssessment")}>{t("migration.design.noAssessmentBody")}</EmptyState>
          ) : (
            <section aria-labelledby="assessment-heading" className="grid gap-3">
              <div>
                <h2 id="assessment-heading" className="text-title font-semibold">
                  {t("migration.design.assessmentTitle")}
                </h2>
                <p className="mt-1 text-sm">
                  {t("migration.design.readyCount", { migratable: String(assessment.migratable), members: String(assessment.members) })}
                </p>
                <p className="mt-1 text-caption text-muted-foreground">{assessment.guidance}</p>
              </div>
              {assessment.unknowns.length > 0 ? (
                <div className="rounded-panel border border-status-warning/40 bg-status-warning/10 p-4">
                  <h3 className="font-semibold">{t("migration.design.blockers")}</h3>
                  <ul className="mt-2 grid gap-2 text-sm">
                    {assessment.unknowns.map((unknown, index) => (
                      <li key={`${unknown.member}:${unknown.kind}:${index}`}>
                        <code className="break-all">{unknown.member}</code> · {unknown.detail}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {reviewed && !assessmentMatches ? (
                <div className="rounded-panel border border-status-warning/40 bg-status-warning/10 p-4 text-sm">{t("migration.design.assessmentMismatch")}</div>
              ) : null}
              {reviewed && ready ? (
                <div className="rounded-panel border border-status-success/40 bg-status-success/10 p-4">
                  <h3 className="font-semibold">{t("migration.design.readyToStart")}</h3>
                  <dl className="mt-3 grid gap-2 text-sm md:grid-cols-[12rem_minmax(0,1fr)]">
                    <dt className="text-muted-foreground">{t("migration.design.planId")}</dt>
                    <dd className="break-all font-mono text-xs">{reviewed.plan_id}</dd>
                    <dt className="text-muted-foreground">{t("migration.design.newAuthority")}</dt>
                    <dd className="break-all font-mono text-xs">{reviewed.new_authority_id}</dd>
                    <dt className="text-muted-foreground">{t("migration.design.waves")}</dt>
                    <dd>{reviewed.waves.length}</dd>
                  </dl>
                  <Button className="mt-4" type="button" loading={busy} onClick={() => void perform("start")}>
                    {t("migration.design.startRun")}
                  </Button>
                </div>
              ) : null}
            </section>
          )}
        </div>
      </MigrationDisclosure>

      <MigrationDisclosure
        title={t("migration.design.disclosure.history")}
        open={open.history}
        onToggle={(value) => setOpen((current) => ({ ...current, history: value }))}
      >
        {runs.loading ? (
          <LoadingState>{t("migration.design.checkingRuns")}</LoadingState>
        ) : runItems.length === 0 ? (
          <EmptyState title={t("migration.design.noRuns")}>{t("migration.design.noRunsHistory")}</EmptyState>
        ) : (
          <div className="grid gap-4">
            {runItems.map((run) => (
              <article key={run.id} className="rounded-panel border border-border bg-muted/20 p-4">
                <h2 className="text-title font-semibold">{run.plan_id || run.id}</h2>
                <p className="mt-1 text-caption text-muted-foreground">
                  <code className="break-all">{run.id}</code> · {run.status}
                </p>
                {run.halt_reason ? <p className="mt-2 text-sm text-status-warning">{run.halt_reason}</p> : null}
                <ol className="mt-4 grid gap-3">
                  {run.waves.map((wave) => {
                    const verification = waveVerification(wave);
                    return (
                      <li key={wave.id} className="rounded-control border border-border bg-card p-3">
                        <h3 className="font-semibold">
                          {wave.id} · {wave.phase}
                        </h3>
                        <p className="mt-1 text-caption text-muted-foreground">
                          {t("migration.design.waveProgress", {
                            members: String(wave.members.length),
                            percent: String(verification.percent),
                            verified: String(verification.verified),
                            total: String(verification.total),
                          })}
                        </p>
                        <ul className="mt-3 grid gap-3">
                          {wave.members.map((member) => (
                            <MigrationMemberEvidence key={member.identity_id} member={member} />
                          ))}
                        </ul>
                      </li>
                    );
                  })}
                </ol>
                <div className="mt-4 flex flex-wrap gap-2">
                  {run.status === "running" ? (
                    <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void perform("pause", run)}>
                      {t("migration.design.pauseRun")}
                    </Button>
                  ) : null}
                  {run.status === "paused" ? (
                    <Button type="button" size="sm" disabled={busy} onClick={() => void perform("resume", run)}>
                      {t("migration.design.resumeRun")}
                    </Button>
                  ) : null}
                  {canRollback(run.status) ? (
                    <Button type="button" size="sm" variant="destructive-outline" disabled={busy} onClick={() => setRollbackRun(run)}>
                      {t("migration.design.reviewRollback")}
                    </Button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        )}
      </MigrationDisclosure>

      <Dialog
        open={Boolean(rollbackRun)}
        onClose={() => !busy && setRollbackRun(null)}
        titleId="migration-rollback-title"
        descriptionId="migration-rollback-description"
        role="alertdialog"
        initialFocusRef={confirmRollbackRef}
        closeOnBackdropClick={!busy}
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        overlayClassName="absolute inset-0 bg-black/55"
        panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card shadow-elevation2"
      >
        <div className="p-5">
          <h2 id="migration-rollback-title" className="text-title font-semibold">
            {t("migration.design.confirmRollbackTitle", { plan: rollbackRun?.plan_id || rollbackRun?.id || "" })}
          </h2>
          <p id="migration-rollback-description" className="mt-2 text-sm text-muted-foreground">
            {t("migration.design.confirmRollbackBody")}
          </p>
          <div className="mt-5 flex justify-end gap-2">
            <Button type="button" variant="outline" disabled={busy} onClick={() => setRollbackRun(null)}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button
              ref={confirmRollbackRef}
              type="button"
              variant="destructive-outline"
              loading={busy}
              onClick={() => rollbackRun && void perform("rollback", rollbackRun)}
            >
              {t("migration.design.confirmRollback")}
            </Button>
          </div>
        </div>
      </Dialog>
    </section>
  );
}

function MigrationDisclosure({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      <div className="border-t border-border p-4">{open ? children : null}</div>
    </details>
  );
}

function MigrationMemberEvidence({ member }: { member: MigrationRun["waves"][number]["members"][number] }) {
  const { t } = useTranslation();
  const binding = member.binding as Partial<MigrationRun["waves"][number]["members"][number]["binding"]>;
  const mapping = [binding.connector, binding.target].filter(Boolean).join(" → ") || t("migration.design.notReturned");
  const trust = `${member.trust_verdict || t("migration.design.notObserved")} / ${member.successor_verdict || t("migration.design.notObserved")}`;
  const rollback = `${member.rollback_trust_verdict || t("migration.design.notObserved")} / ${member.rollback_successor_verdict || t("migration.design.notObserved")}`;
  return (
    <li className="grid gap-2 rounded-control border border-border p-3 text-sm">
      <strong className="break-all">{member.identity_id}</strong>
      <dl className="grid gap-1 text-caption md:grid-cols-[11rem_minmax(0,1fr)]">
        <dt className="text-muted-foreground">{t("migration.design.sourceMapping")}</dt>
        <dd className="break-all">{mapping}</dd>
        <dt className="text-muted-foreground">{t("migration.design.currentFingerprint")}</dt>
        <dd className="break-all font-mono text-xs">{binding.predecessor_fingerprint || t("migration.design.notReturned")}</dd>
        <dt className="text-muted-foreground">{t("migration.design.nextFingerprint")}</dt>
        <dd className="break-all font-mono text-xs">{binding.successor_fingerprint || t("migration.design.notObserved")}</dd>
        <dt className="text-muted-foreground">{t("migration.design.trustEvidence")}</dt>
        <dd>{trust}</dd>
        <dt className="text-muted-foreground">{t("migration.design.rollbackEvidence")}</dt>
        <dd>{rollback}</dd>
      </dl>
    </li>
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

function canRollback(status: MigrationRun["status"]): boolean {
  return status === "running" || status === "paused" || status === "halted" || status === "complete";
}

function assessmentMatchesRequest(assessment: MigrationAssessment, request: MigrationRunStartRequest): boolean {
  if (assessment.plan_id !== request.plan_id || assessment.waves.length !== request.waves.length) return false;
  return assessment.waves.every((assessedWave) => {
    const requestedWave = request.waves.find((wave) => wave.id === assessedWave.id && wave.ordinal === assessedWave.ordinal);
    if (!requestedWave) return false;
    const assessedMembers = [...assessedWave.members].sort();
    const requestedMembers = requestedWave.members.map((member) => member.identity_id).sort();
    return assessedMembers.length === requestedMembers.length && assessedMembers.every((member, index) => member === requestedMembers[index]);
  });
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
