import { useEffect, useMemo, useRef, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type MigrationPlannedCohort, type MigrationRunStartRequest } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { MigrationCohortPlanner } from "@/pages/MigrationCohortPlanner";

// trust_anchor_path is always a string in the form; an empty value means an
// appliance member (A33), which the request omits the path for.
type Member = { identity_id: string; agent_id: string; trust_anchor_path: string };

// A cloud certificate store the control plane carries joins a run with no
// agent (A166): the form records the choice explicitly, and the request names
// neither an agent nor a trust path for it.
const CONTROL_PLANE_EXECUTOR = "control-plane";
// P3-L2: a vendor CA from the external CA registry can be the new issuer; the
// selector carries it as "external:<id>" and the request names it apart.
const EXTERNAL_ISSUER = "external:";
type PlanForm = {
  plan_id: string;
  new_authority_id: string;
  // The vendor root the hosts trust first, when the new issuer is a vendor.
  new_trust_anchor_pem: string;
  // P3-L3: a planned CA switch revokes each predecessor once its successor is
  // verified live.
  revoke_predecessors: boolean;
  waves: { id: string; members: Member[] }[];
};

const newMember = (): Member => ({ identity_id: "", agent_id: "", trust_anchor_path: "/etc/trstctl/next-root.pem" });
const initialPlan: PlanForm = {
  plan_id: "",
  new_authority_id: "",
  new_trust_anchor_pem: "",
  revoke_predecessors: false,
  waves: [{ id: "canary", members: [newMember()] }],
};

const advancedMemberSchema = z.strictObject({
  identity_id: z.string().trim().min(1),
  agent_id: z.string().trim().min(1).optional(),
  trust_anchor_path: z.string().trim().optional(),
});
const advancedSchema = z.strictObject({
  plan_id: z.string().trim().min(1),
  new_authority_id: z.string().trim().min(1).optional(),
  new_external_ca_id: z.string().trim().min(1).optional(),
  new_trust_anchor_pem: z.string().trim().min(1).optional(),
  revoke_predecessors: z.boolean().optional(),
  waves: z.array(z.strictObject({ id: z.string().trim().min(1), ordinal: z.number().int().positive(), members: z.array(advancedMemberSchema).min(1) })).min(1),
});

function parseAdvanced(value: string): MigrationRunStartRequest | null {
  try {
    const parsed = advancedSchema.safeParse(JSON.parse(value));
    if (!parsed.success) return null;
    const plan = parsed.data;
    if (Boolean(plan.new_authority_id) === Boolean(plan.new_external_ca_id)) return null;
    if (plan.new_external_ca_id && !plan.new_trust_anchor_pem) return null;
    const waveIDs = plan.waves.map((wave) => wave.id);
    const ordinals = plan.waves.map((wave) => wave.ordinal);
    const identities = plan.waves.flatMap((wave) => wave.members.map((member) => member.identity_id));
    if (new Set(waveIDs).size !== waveIDs.length || new Set(ordinals).size !== ordinals.length || new Set(identities).size !== identities.length) return null;
    return plan;
  } catch {
    return null;
  }
}

function requestFromForm(form: PlanForm): MigrationRunStartRequest {
  const { revoke_predecessors, new_authority_id, new_trust_anchor_pem, ...plan } = form;
  const issuer = new_authority_id.startsWith(EXTERNAL_ISSUER)
    ? { new_external_ca_id: new_authority_id.slice(EXTERNAL_ISSUER.length), new_trust_anchor_pem: new_trust_anchor_pem.trim() }
    : { new_authority_id };
  return {
    ...plan,
    ...issuer,
    ...(revoke_predecessors ? { revoke_predecessors: true } : {}),
    waves: form.waves.map((wave, index) => ({
      ...wave,
      ordinal: index + 1,
      members: wave.members.map(({ identity_id, agent_id, trust_anchor_path }) => {
        if (agent_id === CONTROL_PLANE_EXECUTOR) return { identity_id };
        return trust_anchor_path.trim() ? { identity_id, agent_id, trust_anchor_path: trust_anchor_path.trim() } : { identity_id, agent_id };
      }),
    })),
  };
}

export function MigrationPlanEditor({
  busy,
  onAssess,
  onPlanChanged,
}: {
  busy: boolean;
  onAssess: (request: MigrationRunStartRequest) => void | Promise<void>;
  onPlanChanged: () => void;
}) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [advanced, setAdvanced] = useState(false);
  const [jsonText, setJSONText] = useState("");
  const [editorError, setEditorError] = useState<string | null>(null);
  const authoritiesQuery = useApiQuery(["migration-plan", "authorities"], api.caAuthorities, { retry: false });
  // Vendor issuers are optional: a registry that cannot be read offers none.
  const vendorsQuery = useApiQuery(["migration-plan", "external-cas"], api.externalCAs, { retry: false });
  const identitiesQuery = useApiQuery(["migration-plan", "identities"], api.identities, { retry: false });
  const agentsQuery = useApiQuery(["migration-plan", "agents"], api.agents, { retry: false });
  const schema = useMemo(() => {
    const required = t("broker.form.required");
    const member = z.object({
      identity_id: z.string().trim().min(1, required),
      agent_id: z.string().trim().min(1, required),
      trust_anchor_path: z.string().trim(),
    });
    return z
      .object({
        plan_id: z.string().trim().min(1, required),
        new_authority_id: z.string().trim().min(1, required),
        new_trust_anchor_pem: z.string(),
        revoke_predecessors: z.boolean(),
        waves: z.array(z.object({ id: z.string().trim().min(1, required), members: z.array(member).min(1, required) })).min(1, required),
      })
      .superRefine((plan, context) => {
        if (plan.new_authority_id.startsWith(EXTERNAL_ISSUER) && !plan.new_trust_anchor_pem.includes("BEGIN CERTIFICATE"))
          context.addIssue({ code: "custom", path: ["new_trust_anchor_pem"], message: t("migration.form.vendorRootRequired") });
        const waveIDs = new Set<string>();
        const identities = new Set<string>();
        plan.waves.forEach((wave, waveIndex) => {
          if (waveIDs.has(wave.id)) context.addIssue({ code: "custom", path: ["waves", waveIndex, "id"], message: t("migration.form.duplicateWave") });
          waveIDs.add(wave.id);
          wave.members.forEach((memberValue, memberIndex) => {
            if (identities.has(memberValue.identity_id))
              context.addIssue({
                code: "custom",
                path: ["waves", waveIndex, "members", memberIndex, "identity_id"],
                message: t("migration.form.duplicateIdentity"),
              });
            identities.add(memberValue.identity_id);
          });
        });
      });
  }, [t]);
  const {
    control,
    register,
    trigger,
    getValues,
    setValue,
    reset,
    setFocus,
    handleSubmit,
    formState: { errors },
  } = useForm<PlanForm>({ resolver: zodResolver(schema), mode: "onTouched", defaultValues: initialPlan });
  const { fields: waveFields, append: appendWave, remove: removeWave, move: moveWave, replace: replaceWaves } = useFieldArray({ control, name: "waves" });
  const watched = useWatch({ control });
  const initialized = useRef(false);
  const focused = useRef(false);

  useEffect(() => {
    if (!initialized.current) {
      initialized.current = true;
      return;
    }
    onPlanChanged();
  }, [watched, onPlanChanged]);

  const authorities = (authoritiesQuery.data?.items ?? []).filter((authority) => authority.status === "active");
  const vendors = (vendorsQuery.data ?? []).filter((vendor) => vendor.status === "available");
  const identities = (identitiesQuery.data ?? []).filter(
    (identity) => identity.kind === "x509_certificate" && ["issued", "deployed", "renewing"].includes(identity.status),
  );
  const agents = (agentsQuery.data ?? []).filter((agent) => agent.status !== "offboarded");
  const loading = authoritiesQuery.loading || identitiesQuery.loading || agentsQuery.loading;
  const rosterError = authoritiesQuery.error || identitiesQuery.error || agentsQuery.error;
  const setupBlocked = authorities.length === 0 || identities.length === 0 || agents.length === 0;
  const setupReady = !loading && !rosterError && !setupBlocked;

  useEffect(() => {
    if (setupReady && !advanced && !focused.current) {
      setFocus("plan_id");
      focused.current = true;
    }
  }, [setupReady, advanced, setFocus]);
  const normalizedReview = step === 2 ? schema.safeParse(getValues()) : null;
  const planForReview = normalizedReview?.success ? normalizedReview.data : watched;
  const selectedVendor = vendors.find((vendor) => EXTERNAL_ISSUER + vendor.id === planForReview.new_authority_id);
  const selectedAuthority = authorities.find((authority) => authority.id === planForReview.new_authority_id);
  const vendorSelected = (watched.new_authority_id ?? "").startsWith(EXTERNAL_ISSUER);
  const steps: CarouselStep[] = [
    { id: "authority", label: t("migration.form.scopeStep"), description: t("migration.form.scopeHelp") },
    { id: "waves", label: t("migration.form.mapStep"), description: t("migration.form.mapHelp") },
    { id: "review", label: t("migration.form.reviewStep"), description: t("migration.form.reviewHelp") },
  ];

  async function advance() {
    const valid = await trigger(step === 0 ? (["plan_id", "new_authority_id", "new_trust_anchor_pem"] as const) : (["waves"] as const));
    if (valid) setStep((current) => Math.min(2, current + 1));
  }

  function changeMode() {
    setEditorError(null);
    if (!advanced) {
      setJSONText(JSON.stringify(requestFromForm(getValues()), null, 2));
      setAdvanced(true);
      return;
    }
    const parsed = parseAdvanced(jsonText);
    if (!parsed) {
      setEditorError(t("migration.design.invalidPlan"));
      return;
    }
    reset({
      plan_id: parsed.plan_id,
      new_authority_id: parsed.new_external_ca_id ? EXTERNAL_ISSUER + parsed.new_external_ca_id : (parsed.new_authority_id ?? ""),
      new_trust_anchor_pem: parsed.new_trust_anchor_pem ?? "",
      waves: [...parsed.waves].sort((a, b) => a.ordinal - b.ordinal).map(({ id, members }) => ({ id, members })),
    });
    onPlanChanged();
    setStep(0);
    setAdvanced(false);
  }

  // P3-L1: a planned set of cohorts replaces the waves, each member on its
  // target's host agent with the default trust anchor path.
  function applyCohorts(cohorts: MigrationPlannedCohort[]) {
    replaceWaves(
      cohorts.map((cohort) => ({
        id: cohort.id,
        members: cohort.members.map((member) => ({ ...newMember(), identity_id: member.identity_id, agent_id: member.agent_id ?? "" })),
      })),
    );
  }

  function addMember(waveIndex: number) {
    setValue(`waves.${waveIndex}.members`, [...getValues(`waves.${waveIndex}.members`), newMember()], { shouldDirty: true, shouldValidate: true });
    onPlanChanged();
  }

  function removeMember(waveIndex: number, memberIndex: number) {
    const members = getValues(`waves.${waveIndex}.members`);
    if (members.length <= 1) return;
    setValue(
      `waves.${waveIndex}.members`,
      members.filter((_, index) => index !== memberIndex),
      { shouldDirty: true, shouldValidate: true },
    );
    onPlanChanged();
  }

  return (
    <div className="grid gap-4">
      <div>
        <Button type="button" variant="outline" onClick={changeMode}>
          {advanced ? t("migration.form.guided") : t("migration.form.advanced")}
        </Button>
      </div>
      {advanced ? (
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            const parsed = parseAdvanced(jsonText);
            if (!parsed) {
              setEditorError(t("migration.design.invalidPlan"));
              return;
            }
            setEditorError(null);
            void onAssess(parsed);
          }}
        >
          <Field label={t("migration.design.planJson")} description={t("migration.design.planHelp")} error={editorError ?? undefined} required>
            {(field) => (
              <Textarea
                {...field}
                className="min-h-64 font-mono text-xs"
                value={jsonText}
                onChange={(event) => {
                  setJSONText(event.target.value);
                  setEditorError(null);
                  onPlanChanged();
                }}
              />
            )}
          </Field>
          <Button type="submit" loading={busy}>
            {t("migration.design.assess")}
          </Button>
          <p className="text-caption text-muted-foreground">{t("migration.design.readOnly")}</p>
        </form>
      ) : (
        <>
          {loading ? <LoadingState>{t("migration.form.loadingRosters")}</LoadingState> : null}
          {rosterError ? <ErrorState title={t("migration.form.rosterUnavailable")}>{rosterError}</ErrorState> : null}
          {!loading && !rosterError && setupBlocked ? (
            <UnavailableState title={t("migration.form.setupIncomplete")}>
              <ul className="list-disc ps-5">
                {authorities.length === 0 ? <li>{t("migration.form.needAuthority")}</li> : null}
                {identities.length === 0 ? <li>{t("migration.form.needIdentity")}</li> : null}
                {agents.length === 0 ? <li>{t("migration.form.needAgent")}</li> : null}
              </ul>
            </UnavailableState>
          ) : null}
          {!loading && !rosterError && !setupBlocked ? (
            <StepShell
              steps={steps}
              currentIndex={step}
              progressLabel={t("migration.form.progress")}
              onPrevious={step > 0 ? () => setStep((current) => current - 1) : undefined}
              onNext={step < 2 ? () => void advance() : undefined}
              nextDisabled={!setupReady || busy}
              nextLabel={step === 0 ? t("migration.form.mapStep") : t("migration.form.reviewStep")}
            >
              {step === 0 ? (
                <div className="grid gap-4">
                  <Field label={t("migration.form.planId")} error={errors.plan_id?.message} required>
                    {(field) => <Input {...field} {...register("plan_id")} />}
                  </Field>
                  <Field label={t("migration.form.authority")} description={t("migration.form.scopeHelp")} error={errors.new_authority_id?.message} required>
                    {(field) => (
                      <Select {...field} {...register("new_authority_id")}>
                        <option value="">{t("migration.form.chooseAuthority")}</option>
                        {authorities.map((authority) => (
                          <option key={authority.id} value={authority.id}>
                            {authority.common_name} — {authority.id}
                          </option>
                        ))}
                        {vendors.length > 0 ? (
                          <optgroup label={t("migration.form.vendorIssuers")}>
                            {vendors.map((vendor) => (
                              <option key={vendor.id} value={EXTERNAL_ISSUER + vendor.id}>
                                {vendor.name || vendor.id} — {vendor.id}
                              </option>
                            ))}
                          </optgroup>
                        ) : null}
                      </Select>
                    )}
                  </Field>
                  {vendorSelected ? (
                    <Field
                      label={t("migration.form.vendorRoot")}
                      description={t("migration.form.vendorRootHelp")}
                      error={errors.new_trust_anchor_pem?.message}
                      required
                    >
                      {(field) => <Textarea {...field} rows={6} className="font-mono text-xs" {...register("new_trust_anchor_pem")} />}
                    </Field>
                  ) : null}
                  <label className="flex items-start gap-2 text-body font-medium">
                    <Checkbox className="mt-1" {...register("revoke_predecessors")} />
                    <span>
                      {t("migration.form.revokePredecessors")}
                      <span className="mt-1 block text-caption font-normal text-muted-foreground">{t("migration.form.revokePredecessorsHelp")}</span>
                    </span>
                  </label>
                </div>
              ) : null}
              {step === 1 ? (
                <div className="grid gap-4">
                  <MigrationCohortPlanner authorities={authorities} onUse={applyCohorts} />
                  {waveFields.map((wave, waveIndex) => {
                    const members = watched.waves?.[waveIndex]?.members ?? [];
                    return (
                      <Card key={wave.id}>
                        <CardHeader className="flex flex-row items-center justify-between gap-3">
                          <CardTitle>{t("migration.form.wave", { number: String(waveIndex + 1) })}</CardTitle>
                          <div className="flex flex-wrap gap-1">
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              disabled={waveIndex === 0}
                              aria-label={t("migration.form.moveUp", { number: String(waveIndex + 1) })}
                              onClick={() => {
                                moveWave(waveIndex, waveIndex - 1);
                                onPlanChanged();
                              }}
                            >
                              <ArrowUp className="h-4 w-4" aria-hidden="true" />
                            </Button>
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              disabled={waveIndex === waveFields.length - 1}
                              aria-label={t("migration.form.moveDown", { number: String(waveIndex + 1) })}
                              onClick={() => {
                                moveWave(waveIndex, waveIndex + 1);
                                onPlanChanged();
                              }}
                            >
                              <ArrowDown className="h-4 w-4" aria-hidden="true" />
                            </Button>
                            <Button
                              type="button"
                              variant="destructive-outline"
                              size="sm"
                              disabled={waveFields.length <= 1}
                              aria-label={t("migration.form.removeWave", { number: String(waveIndex + 1) })}
                              onClick={() => {
                                removeWave(waveIndex);
                                onPlanChanged();
                              }}
                            >
                              <Trash2 className="h-4 w-4" aria-hidden="true" />
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent className="grid gap-4">
                          <Field label={t("migration.form.waveName")} error={errors.waves?.[waveIndex]?.id?.message} required>
                            {(field) => <Input {...field} {...register(`waves.${waveIndex}.id`)} />}
                          </Field>
                          {members.map((_, memberIndex) => (
                            <div key={`${wave.id}-member-${memberIndex}`} className="grid gap-3 border-t border-border pt-4 lg:grid-cols-[1fr_1fr_1fr_auto]">
                              <Field
                                label={t("migration.form.identity")}
                                error={errors.waves?.[waveIndex]?.members?.[memberIndex]?.identity_id?.message}
                                required
                              >
                                {(field) => (
                                  <Select {...field} {...register(`waves.${waveIndex}.members.${memberIndex}.identity_id`)}>
                                    <option value="">{t("migration.form.chooseIdentity")}</option>
                                    {identities.map((identity) => (
                                      <option key={identity.id} value={identity.id}>
                                        {identity.name} — {identity.status}
                                      </option>
                                    ))}
                                  </Select>
                                )}
                              </Field>
                              <Field label={t("migration.form.agent")} error={errors.waves?.[waveIndex]?.members?.[memberIndex]?.agent_id?.message} required>
                                {(field) => (
                                  <Select {...field} {...register(`waves.${waveIndex}.members.${memberIndex}.agent_id`)}>
                                    <option value="">{t("migration.form.chooseAgent")}</option>
                                    <option value={CONTROL_PLANE_EXECUTOR}>{t("migration.form.controlPlaneExecutor")}</option>
                                    {agents.map((agent) => (
                                      <option key={agent.id} value={agent.id}>
                                        {agent.name} — {agent.presence.state}
                                      </option>
                                    ))}
                                  </Select>
                                )}
                              </Field>
                              <Field
                                label={t("migration.form.path")}
                                description={t("migration.form.pathHint")}
                                error={errors.waves?.[waveIndex]?.members?.[memberIndex]?.trust_anchor_path?.message}
                              >
                                {(field) => (
                                  <Input {...field} className="font-mono" {...register(`waves.${waveIndex}.members.${memberIndex}.trust_anchor_path`)} />
                                )}
                              </Field>
                              <div className="flex items-end">
                                <Button
                                  type="button"
                                  variant="destructive-outline"
                                  size="sm"
                                  disabled={members.length <= 1}
                                  aria-label={t("migration.form.removeMember", { number: String(memberIndex + 1) })}
                                  onClick={() => removeMember(waveIndex, memberIndex)}
                                >
                                  <Trash2 className="h-4 w-4" aria-hidden="true" />
                                </Button>
                              </div>
                            </div>
                          ))}
                          <Button type="button" variant="outline" size="sm" onClick={() => addMember(waveIndex)}>
                            <Plus className="h-4 w-4" aria-hidden="true" />
                            {t("migration.form.addMember")}
                          </Button>
                        </CardContent>
                      </Card>
                    );
                  })}
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      appendWave({ id: `wave-${waveFields.length + 1}`, members: [newMember()] });
                      onPlanChanged();
                    }}
                  >
                    <Plus className="h-4 w-4" aria-hidden="true" />
                    {t("migration.form.addWave")}
                  </Button>
                </div>
              ) : null}
              {step === 2 ? (
                <div className="grid gap-4">
                  <h3 className="text-title font-semibold">{t("migration.form.reviewTitle")}</h3>
                  <p className="text-sm text-muted-foreground">{t("migration.form.reviewHelp")}</p>
                  <dl className="grid gap-2 text-sm">
                    <dt className="text-muted-foreground">{t("migration.form.planId")}</dt>
                    <dd>{planForReview.plan_id}</dd>
                    <dt className="text-muted-foreground">{t("migration.form.authority")}</dt>
                    <dd>
                      {selectedVendor
                        ? t("migration.form.vendorIssuerReview", { name: selectedVendor.name || selectedVendor.id })
                        : (selectedAuthority?.common_name ?? planForReview.new_authority_id)}{" "}
                      <code className="break-all">{planForReview.new_authority_id}</code>
                    </dd>
                    <dt className="text-muted-foreground">{t("migration.form.predecessors")}</dt>
                    <dd>{planForReview.revoke_predecessors ? t("migration.form.predecessorsRevoked") : t("migration.form.predecessorsKept")}</dd>
                  </dl>
                  {(planForReview.waves ?? []).map((wave, index) => (
                    <Card key={`${wave.id}-${index}`}>
                      <CardHeader>
                        <CardTitle>
                          {t("migration.form.wave", { number: String(index + 1) })}: {wave.id}
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="grid gap-2 text-sm">
                          {(wave.members ?? []).map((member, memberIndex) => (
                            <li key={`${member.identity_id}-${memberIndex}`} className="grid gap-1">
                              <span>
                                {identities.find((identity) => identity.id === member.identity_id)?.name ?? member.identity_id} →{" "}
                                {member.agent_id === CONTROL_PLANE_EXECUTOR
                                  ? t("migration.form.controlPlaneExecutor")
                                  : (agents.find((agent) => agent.id === member.agent_id)?.name ?? member.agent_id)}
                              </span>
                              {member.agent_id === CONTROL_PLANE_EXECUTOR ? null : <code className="break-all text-caption">{member.trust_anchor_path}</code>}
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  ))}
                  <Button type="button" loading={busy} disabled={!setupReady} onClick={handleSubmit((form) => onAssess(requestFromForm(form)))}>
                    {t("migration.design.assess")}
                  </Button>
                  <p className="text-caption text-muted-foreground">{t("migration.design.readOnly")}</p>
                </div>
              ) : null}
            </StepShell>
          ) : null}
        </>
      )}
    </div>
  );
}
