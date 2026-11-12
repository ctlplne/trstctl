import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type MigrationCohortPlan, type MigrationPlannedCohort } from "@/lib/api";

type Authority = { id: string; common_name: string };

// P3-L1: build canary-first cohorts from a selector instead of listing every
// member. The plan is read-only; using it only fills the waves the operator
// then reviews, assesses and starts.
export function MigrationCohortPlanner({ authorities, onUse }: { authorities: Authority[]; onUse: (waves: MigrationPlannedCohort[]) => void }) {
  const { t } = useTranslation();
  const [profile, setProfile] = useState("");
  const [issuer, setIssuer] = useState("");
  const [canary, setCanary] = useState("1");
  const [cohort, setCohort] = useState("25");
  const [plan, setPlan] = useState<MigrationCohortPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const ready = profile.trim() !== "" || issuer !== "";

  async function build() {
    if (busy || !ready) return;
    setBusy(true);
    setError(null);
    setPlan(null);
    try {
      setPlan(
        await api.migrationCohortPlan({
          profile: profile.trim() || undefined,
          issuer_ca_id: issuer || undefined,
          canary_size: Number(canary),
          cohort_size: Number(cohort),
        }),
      );
    } catch {
      setError(t("migration.cohorts.error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="migration-cohort-planner" className="rounded-panel border border-border p-4">
      <h3 id="migration-cohort-planner" className="font-semibold">
        {t("migration.cohorts.title")}
      </h3>
      <p className="mt-1 text-caption text-muted-foreground">{t("migration.cohorts.help")}</p>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <Field label={t("migration.cohorts.profile")}>
          {(field) => <Input {...field} value={profile} onChange={(event) => setProfile(event.target.value)} />}
        </Field>
        <Field label={t("migration.cohorts.issuer")}>
          {(field) => (
            <Select {...field} value={issuer} onChange={(event) => setIssuer(event.target.value)}>
              <option value="">{t("migration.cohorts.anyIssuer")}</option>
              {authorities.map((authority) => (
                <option key={authority.id} value={authority.id}>
                  {authority.common_name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("migration.cohorts.canarySize")}>
          {(field) => <Input {...field} type="number" min={1} max={10} value={canary} onChange={(event) => setCanary(event.target.value)} />}
        </Field>
        <Field label={t("migration.cohorts.cohortSize")}>
          {(field) => <Input {...field} type="number" min={1} max={500} value={cohort} onChange={(event) => setCohort(event.target.value)} />}
        </Field>
      </div>
      <Button className="mt-3" type="button" variant="outline" loading={busy} disabled={!ready} onClick={() => void build()}>
        {t("migration.cohorts.plan")}
      </Button>
      {error ? (
        <p role="alert" className="mt-2 text-sm text-status-danger">
          {error}
        </p>
      ) : null}
      {plan ? (
        <div className="mt-3 grid gap-2 text-sm" aria-live="polite">
          <p>{t("migration.cohorts.summary", { members: String(plan.members), cohorts: String(plan.waves.length), skipped: String(plan.skipped_count) })}</p>
          {plan.truncated ? <p className="text-status-warning">{t("migration.cohorts.truncated")}</p> : null}
          <ol className="grid gap-1">
            {plan.waves.map((wave) => (
              <li key={wave.id}>
                <span className="font-medium">{wave.id}</span>: {wave.members.map((member) => member.name).join(", ")}
              </li>
            ))}
          </ol>
          {plan.skipped.length > 0 ? (
            <ul className="grid gap-1 text-caption text-muted-foreground">
              {plan.skipped.map((skipped) => (
                <li key={skipped.identity_id}>
                  {skipped.name} · {skipped.reason}
                </li>
              ))}
            </ul>
          ) : null}
          {plan.members > 0 ? (
            <Button type="button" onClick={() => onUse(plan.waves)}>
              {t("migration.cohorts.use")}
            </Button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
