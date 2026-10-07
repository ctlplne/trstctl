import { useEffect, useMemo, useRef, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type MigrationRunStartRequest } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

type Member = MigrationRunStartRequest["waves"][number]["members"][number];
type PlanForm = {
  plan_id: string;
  new_authority_id: string;
  waves: { id: string; members: Member[] }[];
};

const newMember = (): Member => ({ identity_id: "", agent_id: "", trust_anchor_path: "/etc/trstctl/next-root.pem" });
const initialPlan: PlanForm = {
  plan_id: "",
  new_authority_id: "",
  waves: [{ id: "canary", members: [newMember()] }],
};

const advancedMemberSchema = z.strictObject({
  identity_id: z.string().trim().min(1),
  agent_id: z.string().trim().min(1),
  trust_anchor_path: z.string().trim().min(1),
});
const advancedSchema = z.strictObject({
  plan_id: z.string().trim().min(1),
  new_authority_id: z.string().trim().min(1),
  waves: z.array(z.strictObject({ id: z.string().trim().min(1), ordinal: z.number().int().positive(), members: z.array(advancedMemberSchema).min(1) })).min(1),
});

function parseAdvanced(value: string): MigrationRunStartRequest | null {
  try {
    const parsed = advancedSchema.safeParse(JSON.parse(value));
    if (!parsed.success) return null;
    const plan = parsed.data;
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
  return { ...form, waves: form.waves.map((wave, index) => ({ ...wave, ordinal: index + 1 })) };
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
  const identitiesQuery = useApiQuery(["migration-plan", "identities"], api.identities, { retry: false });
  const agentsQuery = useApiQuery(["migration-plan", "agents"], api.agents, { retry: false });
  const schema = useMemo(() => {
    const required = t("broker.form.required");
    const member = z.object({
      identity_id: z.string().trim().min(1, required),
      agent_id: z.string().trim().min(1, required),
      trust_anchor_path: z.string().trim().min(1, required),
    });
    return z
      .object({
        plan_id: z.string().trim().min(1, required),
        new_authority_id: z.string().trim().min(1, required),
        waves: z.array(z.object({ id: z.string().trim().min(1, required), members: z.array(member).min(1, required) })).min(1, required),
      })
      .superRefine((plan, context) => {
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
  const { fields: waveFields, append: appendWave, remove: removeWave, move: moveWave } = useFieldArray({ control, name: "waves" });
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
  const selectedAuthority = authorities.find((authority) => authority.id === planForReview.new_authority_id);
  const steps: CarouselStep[] = [
    { id: "authority", label: t("migration.form.scopeStep"), description: t("migration.form.scopeHelp") },
    { id: "waves", label: t("migration.form.mapStep"), description: t("migration.form.mapHelp") },
    { id: "review", label: t("migration.form.reviewStep"), description: t("migration.form.reviewHelp") },
  ];

  async function advance() {
    const valid = await trigger(step === 0 ? (["plan_id", "new_authority_id"] as const) : (["waves"] as const));
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
      new_authority_id: parsed.new_authority_id,
      waves: [...parsed.waves].sort((a, b) => a.ordinal - b.ordinal).map(({ id, members }) => ({ id, members })),
    });
    onPlanChanged();
    setStep(0);
    setAdvanced(false);
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
                      </Select>
                    )}
                  </Field>
                </div>
              ) : null}
              {step === 1 ? (
                <div className="grid gap-4">
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
                                error={errors.waves?.[waveIndex]?.members?.[memberIndex]?.trust_anchor_path?.message}
                                required
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
                      {selectedAuthority?.common_name ?? planForReview.new_authority_id} <code className="break-all">{planForReview.new_authority_id}</code>
                    </dd>
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
                                {agents.find((agent) => agent.id === member.agent_id)?.name ?? member.agent_id}
                              </span>
                              <code className="break-all text-caption">{member.trust_anchor_path}</code>
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
