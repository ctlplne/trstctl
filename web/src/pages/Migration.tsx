import { useState } from "react";
import { api, type MigrationAssessment } from "@/lib/api";
import { apiProblemContext as apiProblemMessage } from "@/lib/apiProblem";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";
import { translateNow } from "@/i18n/I18nProvider";

// The migration console (epic H2).
//
// Assess-only for now, and the page says so rather than showing disabled
// execute controls. A greyed-out "Run migration" button reads as a feature that
// exists and is temporarily unavailable; the honest surface is the one that
// tells an operator what it can actually do today.
//
// The unknowns table is the centre of the page, not an appendix. A migration
// plan that looks ready is the dangerous one — the members with no observed
// trust store are exactly the hosts that go dark in wave three, and they are
// invisible on any surface that only counts what it found.

export function Migration() {
  const [planText, setPlanText] = useState(
    JSON.stringify(
      {
        plan_id: "ca-rollover-2026",
        require_full_trust: true,
        waves: [{ id: "w1", ordinal: 1, members: [] }],
      },
      null,
      2,
    ),
  );
  const [assessment, setAssessment] = useState<MigrationAssessment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function assess() {
    setBusy(true);
    setError(null);
    try {
      setAssessment(await api.assessMigration(JSON.parse(planText)));
    } catch (err) {
      setAssessment(null);
      setError(apiProblemMessage(err, "Could not assess this migration plan"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="migration-heading" className="space-y-6">
      <PageHeader
        titleId="migration-heading"
        title={translateNow("source.migration.h2mig00001")}
        description={translateNow("source.migration.description.h2mig00002")}
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_28rem]">
        <form
          className="ui-panel space-y-3 p-comfortable"
          onSubmit={(event) => {
            event.preventDefault();
            void assess();
          }}
        >
          <label htmlFor="migration-plan" className="grid gap-1 text-sm font-medium">
            {translateNow("source.migration.plan.h2mig00003")}
            <Textarea id="migration-plan" className="min-h-64 font-mono text-xs" value={planText} onChange={(event) => setPlanText(event.target.value)} />
          </label>
          <Button type="submit" disabled={busy}>
            {translateNow("source.migration.assess.h2mig00004")}
          </Button>
          <p className="text-caption text-muted-foreground">{translateNow("source.migration.readonly.h2mig00005")}</p>
        </form>

        <div className="space-y-5">
          {error && <ErrorState title={translateNow("source.migration.unavailable.h2mig00006")}>{error}</ErrorState>}
          {assessment && <AssessmentPanel assessment={assessment} />}
        </div>
      </div>
    </section>
  );
}

function AssessmentPanel({ assessment }: { assessment: MigrationAssessment }) {
  return (
    <>
      <section aria-labelledby="assessment-heading" className="ui-panel space-y-3 p-comfortable">
        <h2 id="assessment-heading" className="text-title font-semibold">
          {translateNow("source.migration.assessment.h2mig00007")}
        </h2>
        {/* Deliberately NOT a readiness percentage. A migration that is "94%
            ready" still takes down the other 6%, and a percentage invites
            somebody to round it up. */}
        <p className="text-sm">
          {translateNow("source.migration.counts.h2mig00008", {
            value1: String(assessment.migratable),
            value2: String(assessment.members),
          })}
        </p>
        <p className="text-caption text-muted-foreground">{assessment.guidance}</p>
      </section>

      {assessment.waves.length > 0 && (
        <section aria-labelledby="waves-heading" className="ui-panel space-y-3 p-comfortable">
          <h2 id="waves-heading" className="text-title font-semibold">
            {translateNow("source.migration.waves.h2mig00009")}
          </h2>
          <ul className="space-y-2 text-sm">
            {assessment.waves.map((wave) => (
              <li key={wave.id} className="border-b border-border pb-2 last:border-0">
                <span className="font-medium">
                  {wave.ordinal}. {wave.id}
                </span>
                <span className="ml-2 text-muted-foreground">
                  {translateNow("source.migration.wave.members.h2mig00010", {
                    value1: String(wave.members.length),
                  })}
                </span>
                {wave.guidance && <span className="mt-1 block text-caption text-status-warning">{wave.guidance}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="unknowns-heading" className="ui-panel space-y-3 p-comfortable">
        <h2 id="unknowns-heading" className="text-title font-semibold">
          {translateNow("source.migration.unknowns.h2mig00011")}
        </h2>
        {assessment.unknowns.length === 0 ? (
          <p className="text-sm text-status-success">{translateNow("source.migration.no.unknowns.h2mig00012")}</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {assessment.unknowns.map((unknown, index) => (
              <li key={`${unknown.member}:${unknown.kind}:${index}`}>
                <span className="font-mono text-xs">{unknown.member}</span>
                <span className="mt-1 block text-caption text-muted-foreground">{unknown.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}

export default Migration;
