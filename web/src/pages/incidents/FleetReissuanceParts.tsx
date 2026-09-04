import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { Download, Pause, Play, Plus, RotateCcw, Trash2 } from "lucide-react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";
import { z } from "zod";

import { CapabilityActionNotice, capabilityExecutionReason } from "@/components/CapabilityTruth";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { api, type FleetReissuanceRequest, type FleetReissuanceRun } from "@/lib/api";
import { useCapabilityExecution } from "@/lib/capabilities";
import { AppQueryProvider, useApiQuery, useHasAppQueryProvider } from "@/lib/query";

const initialFleetRequest: FleetReissuanceRequest = {
  issuer_id: "",
  replacement_authority_id: "",
  mode: "live",
  reason: "intermediate CA private key exposure",
  rollback_ref: "restore the exact predecessor for this cohort",
  cohorts: [
    {
      id: "canary",
      ordinal: 1,
      members: [{ identity_id: "", agent_id: "", trust_anchor_path: "/etc/trstctl/next-root.pem" }],
    },
  ],
};

type FleetReissuanceForm = Omit<FleetReissuanceRequest, "reason" | "rollback_ref"> & {
  reason: string;
  rollback_ref: string;
};

type FleetReissuanceConfigurationProps = {
  initialReason?: string;
  running: boolean;
  onStart: (request: FleetReissuanceRequest) => void | Promise<void>;
};

export function FleetReissuanceConfiguration(props: FleetReissuanceConfigurationProps) {
  const hasQueryProvider = useHasAppQueryProvider();
  if (hasQueryProvider) return <FleetReissuanceConfigurationBody {...props} />;
  return (
    <AppQueryProvider>
      <FleetReissuanceConfigurationBody {...props} />
    </AppQueryProvider>
  );
}

function FleetReissuanceConfigurationBody({ initialReason, running, onStart }: FleetReissuanceConfigurationProps) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const issuersQuery = useApiQuery(["fleet-reissuance", "issuers"], () => api.issuers(), { retry: false });
  const authoritiesQuery = useApiQuery(["fleet-reissuance", "authorities"], () => api.caAuthorities(), { retry: false });
  const identitiesQuery = useApiQuery(["fleet-reissuance", "identities"], () => api.identities(), { retry: false });
  const agentsQuery = useApiQuery(["fleet-reissuance", "agents"], () => api.agents(), { retry: false });
  const schema = useMemo(
    () =>
      z
        .object({
          issuer_id: z.string().trim().min(1, t("broker.form.required")),
          replacement_authority_id: z.string().trim().min(1, t("broker.form.required")),
          mode: z.enum(["live", "game_day"]),
          reason: z.string().trim().min(1, t("broker.form.required")),
          rollback_ref: z.string().trim().min(1, t("broker.form.required")),
          cohorts: z
            .array(
              z.object({
                id: z.string().trim().min(1, t("broker.form.required")),
                ordinal: z.number().int().positive(t("incidents.fleet.invalidWave")),
                members: z
                  .array(
                    z.object({
                      identity_id: z.string().trim().min(1, t("broker.form.required")),
                      agent_id: z.string().trim().min(1, t("broker.form.required")),
                      trust_anchor_path: z.string().trim().min(1, t("broker.form.required")),
                    }),
                  )
                  .min(1, t("incidents.fleet.invalidWave")),
              }),
            )
            .min(1, t("incidents.fleet.invalidWave")),
        })
        .superRefine((values, context) => {
          const ids = new Set<string>();
          const ordinals = new Set<number>();
          values.cohorts.forEach((cohort, index) => {
            if (ids.has(cohort.id)) context.addIssue({ code: "custom", path: ["cohorts", index, "id"], message: t("incidents.fleet.invalidWave") });
            if (ordinals.has(cohort.ordinal))
              context.addIssue({ code: "custom", path: ["cohorts", index, "ordinal"], message: t("incidents.fleet.invalidWave") });
            ids.add(cohort.id);
            ordinals.add(cohort.ordinal);
          });
        }),
    [t],
  );
  const {
    control,
    register,
    handleSubmit,
    trigger,
    getValues,
    setValue,
    formState: { errors },
  } = useForm<FleetReissuanceForm>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: initialFleetRequest,
  });
  const { fields: cohortFields, append: appendCohort, remove: removeCohort } = useFieldArray({ control, name: "cohorts" });
  const issuerID = useWatch({ control, name: "issuer_id" });
  const cohorts = useWatch({ control, name: "cohorts" }) ?? [];
  const mode = useWatch({ control, name: "mode" });

  useEffect(() => {
    const reason = initialReason?.trim();
    if (reason) setValue("reason", reason, { shouldValidate: true });
  }, [initialReason, setValue]);

  const issuers = (issuersQuery.data ?? []).filter((issuer) => issuer.kind === "x509_ca");
  const authorities = (authoritiesQuery.data?.items ?? []).filter((authority) => authority.status === "active");
  const identities = (identitiesQuery.data ?? []).filter(
    (identity) => identity.kind === "x509_certificate" && identity.issuer_id === issuerID && ["issued", "deployed", "renewing"].includes(identity.status),
  );
  const agents = (agentsQuery.data ?? []).filter((agent) => agent.status !== "offboarded");
  const loading = issuersQuery.loading || authoritiesQuery.loading || identitiesQuery.loading || agentsQuery.loading;
  const rosterError = issuersQuery.error || authoritiesQuery.error || identitiesQuery.error || agentsQuery.error;
  const setupBlocked = issuers.length === 0 || authorities.length === 0 || agents.length === 0;
  const setupReady = !loading && !rosterError && !setupBlocked;
  const selectedIssuer = issuers.find((issuer) => issuer.id === issuerID);
  const selectedAuthority = authorities.find((authority) => authority.id === getValues("replacement_authority_id"));
  const steps: CarouselStep[] = [
    { id: "scope", label: t("incidents.fleet.scopeStep"), description: t("incidents.fleet.planSummary") },
    { id: "cohorts", label: t("incidents.fleet.cohortStep"), description: t("incidents.fleet.planSummary") },
    { id: "review", label: t("incidents.fleet.reviewStep"), description: t("incidents.fleet.planSummary") },
  ];

  async function advance() {
    const fields = step === 0 ? (["issuer_id", "replacement_authority_id", "mode", "reason", "rollback_ref"] as const) : (["cohorts"] as const);
    if (await trigger(fields)) setStep((current) => Math.min(2, current + 1));
  }

  function addMember(cohortIndex: number) {
    const members = getValues(`cohorts.${cohortIndex}.members`) ?? [];
    setValue(`cohorts.${cohortIndex}.members`, [...members, { identity_id: "", agent_id: "", trust_anchor_path: "/etc/trstctl/next-root.pem" }], {
      shouldDirty: true,
      shouldValidate: true,
    });
  }

  function removeMember(cohortIndex: number, memberIndex: number) {
    const members = getValues(`cohorts.${cohortIndex}.members`) ?? [];
    if (members.length <= 1) return;
    setValue(
      `cohorts.${cohortIndex}.members`,
      members.filter((_, index) => index !== memberIndex),
      { shouldDirty: true, shouldValidate: true },
    );
  }

  return (
    <div className="grid gap-4">
      {loading ? <LoadingState>{t("incidents.fleet.loadingSetup")}</LoadingState> : null}
      {rosterError ? <ErrorState title={t("incidents.fleet.setupUnavailable")}>{rosterError}</ErrorState> : null}
      {!loading && !rosterError && setupBlocked ? (
        <UnavailableState title={t("incidents.fleet.setupIncomplete")}>{t("incidents.fleet.setupNeeds")}</UnavailableState>
      ) : null}

      <StepShell
        steps={steps}
        currentIndex={step}
        progressLabel={t("incidents.fleet.configurationProgress")}
        onPrevious={step > 0 ? () => setStep((current) => Math.max(0, current - 1)) : undefined}
        onNext={step < 2 ? () => void advance() : undefined}
        nextDisabled={!setupReady || running || (step === 1 && identities.length === 0)}
        nextLabel={step === 0 ? t("incidents.fleet.buildWaves") : t("incidents.fleet.reviewRun")}
      >
        {step === 0 ? (
          <div className="grid gap-4">
            <div className="grid gap-4 md:grid-cols-2">
              <Field label={t("incidents.fleet.compromisedIssuer")} error={errors.issuer_id?.message} required>
                {(field) => (
                  <Select {...field} {...register("issuer_id")}>
                    <option value="">{t("incidents.fleet.chooseIssuer")}</option>
                    {issuers.map((issuer) => (
                      <option key={issuer.id} value={issuer.id}>
                        {issuer.name} — {shortId(issuer.id)}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("incidents.fleet.replacementAuthority")} error={errors.replacement_authority_id?.message} required>
                {(field) => (
                  <Select {...field} {...register("replacement_authority_id")}>
                    <option value="">{t("incidents.fleet.chooseAuthority")}</option>
                    {authorities.map((authority) => (
                      <option key={authority.id} value={authority.id}>
                        {authority.common_name} — {authority.kind} · {authority.status}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("secrets.scan.mode")} error={errors.mode?.message} required>
                {(field) => (
                  <Select {...field} {...register("mode")}>
                    <option value="live">{t("integrate.gitops.live")}</option>
                    <option value="game_day">{t("incidents.fleet.modeGameDay")}</option>
                  </Select>
                )}
              </Field>
              <Field label={t("source.what.happened.483bd49023")} error={errors.reason?.message} required>
                {(field) => <Input {...field} {...register("reason")} />}
              </Field>
              <Field className="md:col-span-2" label={t("incidents.fleet.rollback")} error={errors.rollback_ref?.message} required>
                {(field) => <Input {...field} {...register("rollback_ref")} />}
              </Field>
            </div>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="grid gap-4">
            {identities.length === 0 ? (
              <UnavailableState title={t("incidents.fleet.noAffectedIdentitiesTitle")}>{t("incidents.fleet.noAffectedIdentities")}</UnavailableState>
            ) : null}
            {cohortFields.map((cohort, cohortIndex) => {
              const members = cohorts[cohortIndex]?.members ?? [];
              return (
                <Card key={cohort.id}>
                  <CardHeader className="flex-row items-start justify-between gap-3">
                    <div>
                      <CardTitle>{t("incidents.fleet.wave", { number: cohortIndex + 1 })}</CardTitle>
                      {cohortIndex === 0 ? <p className="text-sm text-muted-foreground">{t("incidents.fleet.canaryHelp")}</p> : null}
                    </div>
                    {cohortFields.length > 1 ? (
                      <Button type="button" variant="destructive-outline" size="sm" onClick={() => removeCohort(cohortIndex)}>
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
                        {t("incidents.fleet.removeWave")}
                      </Button>
                    ) : null}
                  </CardHeader>
                  <CardContent className="grid gap-4">
                    <div className="grid gap-4 md:grid-cols-2">
                      <Field label={t("incidents.fleet.waveName")} error={errors.cohorts?.[cohortIndex]?.id?.message} required>
                        {(field) => <Input {...field} {...register(`cohorts.${cohortIndex}.id`)} />}
                      </Field>
                      <Field label={t("incidents.fleet.waveOrder")} error={errors.cohorts?.[cohortIndex]?.ordinal?.message} required>
                        {(field) => (
                          <Input {...field} type="number" min="1" step="1" {...register(`cohorts.${cohortIndex}.ordinal`, { valueAsNumber: true })} />
                        )}
                      </Field>
                    </div>
                    {members.map((_, memberIndex) => (
                      <div key={`${cohort.id}-member-${memberIndex}`} className="grid gap-3 border-t border-border pt-4 lg:grid-cols-[1fr_1fr_1fr_auto]">
                        <Field
                          label={t("source.identity.i4diag0013")}
                          error={errors.cohorts?.[cohortIndex]?.members?.[memberIndex]?.identity_id?.message}
                          required
                        >
                          {(field) => (
                            <Select {...field} {...register(`cohorts.${cohortIndex}.members.${memberIndex}.identity_id`)}>
                              <option value="">{t("incidents.fleet.chooseIdentity")}</option>
                              {identities.map((identity) => (
                                <option key={identity.id} value={identity.id}>
                                  {identity.name} — {shortId(identity.id)}
                                </option>
                              ))}
                            </Select>
                          )}
                        </Field>
                        <Field label={t("source.agent.11b39c9377")} error={errors.cohorts?.[cohortIndex]?.members?.[memberIndex]?.agent_id?.message} required>
                          {(field) => (
                            <Select {...field} {...register(`cohorts.${cohortIndex}.members.${memberIndex}.agent_id`)}>
                              <option value="">{t("incidents.fleet.chooseAgent")}</option>
                              {agents.map((agent) => (
                                <option key={agent.id} value={agent.id}>
                                  {agent.name} — {agent.presence.state}
                                </option>
                              ))}
                            </Select>
                          )}
                        </Field>
                        <Field
                          label={t("incidents.fleet.trustAnchorPath")}
                          error={errors.cohorts?.[cohortIndex]?.members?.[memberIndex]?.trust_anchor_path?.message}
                          required
                        >
                          {(field) => (
                            <Input {...field} className="font-mono" {...register(`cohorts.${cohortIndex}.members.${memberIndex}.trust_anchor_path`)} />
                          )}
                        </Field>
                        <div className="flex items-end">
                          <Button
                            type="button"
                            variant="destructive-outline"
                            size="sm"
                            disabled={members.length <= 1}
                            aria-label={t("incidents.fleet.removeMember", { number: memberIndex + 1 })}
                            onClick={() => removeMember(cohortIndex, memberIndex)}
                          >
                            <Trash2 className="h-4 w-4" aria-hidden="true" />
                          </Button>
                        </div>
                      </div>
                    ))}
                    <div>
                      <Button type="button" variant="outline" size="sm" onClick={() => addMember(cohortIndex)}>
                        <Plus className="h-4 w-4" aria-hidden="true" />
                        {t("incidents.fleet.addMember")}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
            <div>
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  appendCohort({
                    id: `wave-${cohortFields.length + 1}`,
                    ordinal: cohortFields.length + 1,
                    members: [{ identity_id: "", agent_id: "", trust_anchor_path: "/etc/trstctl/next-root.pem" }],
                  })
                }
              >
                <Plus className="h-4 w-4" aria-hidden="true" />
                {t("incidents.fleet.addWave")}
              </Button>
            </div>
          </div>
        ) : null}

        {step === 2 ? (
          <div className="grid gap-4">
            <Card>
              <CardHeader>
                <CardTitle>{t("incidents.fleet.reviewTitle")}</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4">
                <dl className="grid gap-3 md:grid-cols-3">
                  <div>
                    <dt className="text-sm text-muted-foreground">{t("incidents.fleet.compromisedIssuer")}</dt>
                    <dd className="font-medium">{selectedIssuer?.name ?? issuerID}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-muted-foreground">{t("incidents.fleet.replacementAuthority")}</dt>
                    <dd className="font-medium">{selectedAuthority?.common_name ?? getValues("replacement_authority_id")}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-muted-foreground">{t("secrets.scan.mode")}</dt>
                    <dd className="font-medium">{mode === "game_day" ? t("incidents.fleet.modeGameDay") : t("integrate.gitops.live")}</dd>
                  </div>
                </dl>
                <div className="grid gap-2">
                  {cohorts.map((cohort) => (
                    <div key={cohort.id} className="rounded-control border border-border p-3">
                      <p className="font-medium">
                        {cohort.ordinal}. {cohort.id}
                      </p>
                      <ul className="mt-1 list-disc ps-5 text-sm text-muted-foreground">
                        {cohort.members.map((member, index) => {
                          const identity = identitiesQuery.data?.find((item) => item.id === member.identity_id);
                          const agent = agentsQuery.data?.find((item) => item.id === member.agent_id);
                          return (
                            <li key={`${cohort.id}-${member.identity_id}-${index}`}>
                              {identity?.name ?? shortId(member.identity_id)} → {agent?.name ?? shortId(member.agent_id)}
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  ))}
                </div>
                <p className="text-sm text-muted-foreground">{t("incidents.fleet.reviewWarning")}</p>
                <details>
                  <summary className="cursor-pointer text-sm font-medium">{t("incidents.fleet.exactRequest")}</summary>
                  <pre className="mt-2 max-w-full overflow-x-auto whitespace-pre-wrap rounded-control bg-muted p-3 font-mono text-caption">
                    {JSON.stringify(getValues(), null, 2)}
                  </pre>
                </details>
                <FleetStartAction running={running} onStart={handleSubmit((request) => onStart(request))} />
              </CardContent>
            </Card>
          </div>
        ) : null}
      </StepShell>
    </div>
  );
}

export function FleetStartAction({ running, onStart }: { running: boolean; onStart: () => void }) {
  const { t } = useTranslation();
  const action = useCapabilityExecution("F32", "startFleetReissuance");
  const explanation = capabilityExecutionReason(action, t);
  return (
    <div className="grid gap-2">
      <Button type="button" onClick={onStart} disabled={running || !action.runnable} title={!action.runnable ? explanation : undefined}>
        <Play className="h-4 w-4" aria-hidden="true" />
        {running ? translateNow("source.starting.82b93630a9") : translateNow("source.start.fleet.run.140963492c")}
      </Button>
      <CapabilityActionNotice action={action} />
    </div>
  );
}

function FleetRunActions({
  run,
  action,
  onAction,
}: {
  run: FleetReissuanceRun;
  action: string | null;
  onAction: (kind: "pause" | "resume" | "rollback" | "evidence", run: FleetReissuanceRun) => void;
}) {
  const pause = useCapabilityExecution("F32", "pauseFleetReissuance");
  const resume = useCapabilityExecution("F32", "resumeFleetReissuance");
  const rollback = useCapabilityExecution("F32", "rollbackFleetReissuance");
  const evidence = useCapabilityExecution("F32", "exportFleetReissuanceEvidence");
  return (
    <div className="flex flex-wrap gap-2">
      <Button
        type="button"
        variant="outline"
        onClick={() => onAction("pause", run)}
        disabled={!pause.runnable || action === `pause:${run.id}` || Boolean(run.migration_run_id && run.status !== "running")}
        title={!pause.runnable ? pause.unavailable?.detail : undefined}
        aria-label={translateNow("source.pause.fleet.run.value1.225d7f781f", { value1: shortId(run.id) })}
      >
        <Pause className="h-4 w-4" aria-hidden="true" />
      </Button>
      <Button
        type="button"
        variant="outline"
        onClick={() => onAction("resume", run)}
        disabled={!resume.runnable || action === `resume:${run.id}` || Boolean(run.migration_run_id && run.status !== "paused")}
        title={!resume.runnable ? resume.unavailable?.detail : undefined}
        aria-label={translateNow("source.resume.fleet.run.value1.82d98d67fc", { value1: shortId(run.id) })}
      >
        <Play className="h-4 w-4" aria-hidden="true" />
      </Button>
      <Button
        type="button"
        variant="outline"
        onClick={() => onAction("rollback", run)}
        disabled={
          !rollback.runnable || action === `rollback:${run.id}` || Boolean(run.migration_run_id && !["running", "paused", "halted"].includes(run.status))
        }
        title={!rollback.runnable ? rollback.unavailable?.detail : undefined}
        aria-label={translateNow("source.rollback.fleet.run.value1.21446f0a1d", { value1: shortId(run.id) })}
      >
        <RotateCcw className="h-4 w-4" aria-hidden="true" />
      </Button>
      <Button
        type="button"
        variant="outline"
        onClick={() => onAction("evidence", run)}
        disabled={!evidence.runnable || action === `evidence:${run.id}` || Boolean(run.migration_run_id && run.evidence_bundle_format !== "jws")}
        title={!evidence.runnable ? evidence.unavailable?.detail : undefined}
        aria-label={translateNow("source.export.fleet.run.value1.evidence.6065920a10", { value1: shortId(run.id) })}
      >
        <Download className="h-4 w-4" aria-hidden="true" />
      </Button>
    </div>
  );
}

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
                  {run.mode} ·{" "}
                  {translateNow("source.trusted.by.count.h1trust0002", {
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
                <FleetRunActions run={run} action={action} onAction={onAction} />
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
