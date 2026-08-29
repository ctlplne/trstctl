import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { ShieldCheck, X } from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type MDMSCEPPolicy, type MDMSCEPPolicyPreview, type MDMSCEPPolicyRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

type PolicyForm = {
  name: string;
  provider: "intune" | "jamf";
  scepEndpoint: string;
  scepProfile: string;
  challengeMode: "intune-jws" | "hmac-dynamic";
  expectedAudience: string;
  trustAnchorRefsJSON: string;
  profileGuidanceJSON: string;
  enabled: boolean;
};

function recordText(message: string) {
  return z.string().superRefine((value, context) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) context.addIssue({ code: "custom", message });
    } catch {
      context.addIssue({ code: "custom", message });
    }
  });
}

function stringifyRecord(value: Record<string, unknown> | undefined): string {
  return value && Object.keys(value).length > 0 ? JSON.stringify(value, null, 2) : "{}";
}

function parseRecord(value: string): Record<string, unknown> {
  const trimmed = value.trim();
  return trimmed ? (JSON.parse(trimmed) as Record<string, unknown>) : {};
}

function defaults(policy?: MDMSCEPPolicy): PolicyForm {
  return {
    name: policy?.name ?? "",
    provider: policy?.provider === "jamf" ? "jamf" : "intune",
    scepEndpoint: policy?.scep_endpoint ?? "/scep/pkiclient.exe",
    scepProfile: policy?.scep_profile ?? "",
    challengeMode: policy?.challenge_mode === "hmac-dynamic" ? "hmac-dynamic" : "intune-jws",
    expectedAudience: policy?.expected_audience ?? "",
    trustAnchorRefsJSON: stringifyRecord(policy?.trust_anchor_refs),
    profileGuidanceJSON: stringifyRecord(policy?.profile_guidance),
    enabled: policy?.enabled ?? true,
  };
}

function requestFrom(values: PolicyForm): MDMSCEPPolicyRequest {
  return {
    name: values.name.trim(),
    provider: values.provider,
    scep_endpoint: values.scepEndpoint.trim(),
    scep_profile: values.scepProfile.trim(),
    challenge_mode: values.challengeMode,
    enabled: values.enabled,
    ...(values.expectedAudience.trim() ? { expected_audience: values.expectedAudience.trim() } : {}),
    trust_anchor_refs: parseRecord(values.trustAnchorRefsJSON),
    profile_guidance: parseRecord(values.profileGuidanceJSON),
  };
}

export function MDMSCEPPolicyDialog({ onClose, onSaved, policy }: { onClose: () => void; onSaved: (saved: MDMSCEPPolicy) => void; policy?: MDMSCEPPolicy }) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [preview, setPreview] = useState<MDMSCEPPolicyPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const schema = useMemo(
    () =>
      z.object({
        name: z.string().trim().min(1, t("protocols.mdm.form.required")),
        provider: z.enum(["intune", "jamf"]),
        scepEndpoint: z.string().trim().min(1, t("protocols.mdm.form.required")),
        scepProfile: z.string().trim().min(1, t("protocols.mdm.form.required")),
        challengeMode: z.enum(["intune-jws", "hmac-dynamic"]),
        expectedAudience: z.string(),
        trustAnchorRefsJSON: recordText(t("protocols.mdm.form.jsonObject")),
        profileGuidanceJSON: recordText(t("protocols.mdm.form.jsonObject")),
        enabled: z.boolean(),
      }),
    [t],
  );
  const form = useForm<PolicyForm>({ resolver: zodResolver(schema), defaultValues: defaults(policy), mode: "onTouched" });
  const watchedValues = useWatch({ control: form.control });
  const steps = useMemo<CarouselStep[]>(
    () => [
      { id: "policy", label: t("protocols.mdm.form.stepPolicy"), description: t("protocols.mdm.form.stepPolicyBody") },
      { id: "trust", label: t("protocols.mdm.form.stepTrust"), description: t("protocols.mdm.form.stepTrustBody") },
      { id: "review", label: t("protocols.mdm.form.stepReview"), description: t("protocols.mdm.form.stepReviewBody") },
    ],
    [t],
  );

  useEffect(() => {
    setPreview(null);
    setPreviewError(null);
    setSaveError(null);
  }, [watchedValues]);

  async function nextFromPolicy() {
    if (await form.trigger(["name", "provider", "scepEndpoint", "scepProfile"])) setStep(1);
  }

  async function loadPreview() {
    if (!(await form.trigger())) return;
    setPreviewing(true);
    setPreviewError(null);
    setSaveError(null);
    setStep(2);
    try {
      const input = requestFrom(form.getValues());
      setPreview(policy ? await api.previewMDMSCEPPolicyUpdate(policy.id, input) : await api.previewMDMSCEPPolicy(input));
    } catch (error) {
      setPreview(null);
      setPreviewError(apiProblemMessage(error, t("protocols.mdm.form.previewFailed")));
    } finally {
      setPreviewing(false);
    }
  }

  async function save(values: PolicyForm) {
    if (!preview?.ready || !preview.effect_free) return;
    setSaving(true);
    setSaveError(null);
    try {
      const input = requestFrom(values);
      const saved = policy ? await api.updateMDMSCEPPolicy(policy.id, input) : await api.createMDMSCEPPolicy(input);
      onSaved(saved);
    } catch (error) {
      setSaveError(apiProblemMessage(error, t("protocols.mdm.form.saveFailed")));
    } finally {
      setSaving(false);
    }
  }

  const titleId = "mdm-scep-policy-form-title";
  const operation = policy ? t("protocols.mdm.form.editTitle") : t("protocols.mdm.form.createTitle");

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-4xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div>
          <h2 id={titleId} className="text-title font-semibold">
            {operation}
          </h2>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{t("protocols.mdm.form.intro")}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("protocols.mdm.form.close")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>

      <form className="p-5" onSubmit={form.handleSubmit(save)}>
        <StepShell
          steps={steps}
          currentIndex={step}
          progressLabel={t("protocols.mdm.form.progress")}
          onPrevious={step > 0 && !previewing && !saving ? () => setStep((current) => current - 1) : undefined}
          onNext={step === 0 ? () => void nextFromPolicy() : step === 1 ? () => void loadPreview() : undefined}
          nextDisabled={previewing || saving}
          nextLabel={step === 1 ? t("protocols.mdm.form.previewAction") : undefined}
        >
          {step === 0 && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("protocols.mdm.form.name")} error={form.formState.errors.name?.message} required>
                {(control) => <Input {...control} {...form.register("name")} autoComplete="off" />}
              </Field>
              <Field label={t("protocols.mdm.form.provider")} error={form.formState.errors.provider?.message} required>
                {(control) => (
                  <Select {...control} {...form.register("provider")}>
                    <option value="intune">{t("protocols.mdm.form.providerIntune")}</option>
                    <option value="jamf">{t("protocols.mdm.form.providerJamf")}</option>
                  </Select>
                )}
              </Field>
              <Field
                label={t("protocols.mdm.form.endpoint")}
                description={t("protocols.mdm.form.endpointHelp")}
                error={form.formState.errors.scepEndpoint?.message}
                required
              >
                {(control) => <Input {...control} {...form.register("scepEndpoint")} autoComplete="off" />}
              </Field>
              <Field
                label={t("protocols.mdm.form.profile")}
                description={t("protocols.mdm.form.profileHelp")}
                error={form.formState.errors.scepProfile?.message}
                required
              >
                {(control) => <Input {...control} {...form.register("scepProfile")} autoComplete="off" />}
              </Field>
              <label className="flex items-center gap-2 text-body font-medium sm:col-span-2">
                <Checkbox {...form.register("enabled")} />
                {t("protocols.mdm.form.enabled")}
              </label>
            </div>
          )}

          {step === 1 && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={t("protocols.mdm.form.challengeMode")} description={t("protocols.mdm.form.challengeHelp")} required>
                {(control) => (
                  <Select {...control} {...form.register("challengeMode")}>
                    <option value="intune-jws">{t("protocols.mdm.form.challengeIntune")}</option>
                    <option value="hmac-dynamic">{t("protocols.mdm.form.challengeHMAC")}</option>
                  </Select>
                )}
              </Field>
              <Field label={t("protocols.mdm.form.audience")} description={t("protocols.mdm.form.audienceHelp")}>
                {(control) => <Input {...control} {...form.register("expectedAudience")} autoComplete="off" />}
              </Field>
              <Field
                className="sm:col-span-2"
                label={t("protocols.mdm.form.references")}
                description={t("protocols.mdm.form.referencesHelp")}
                error={form.formState.errors.trustAnchorRefsJSON?.message}
              >
                {(control) => <Textarea {...control} {...form.register("trustAnchorRefsJSON")} className="min-h-28 font-mono text-xs" spellCheck={false} />}
              </Field>
              <Field
                className="sm:col-span-2"
                label={t("protocols.mdm.form.guidance")}
                description={t("protocols.mdm.form.guidanceHelp")}
                error={form.formState.errors.profileGuidanceJSON?.message}
              >
                {(control) => <Textarea {...control} {...form.register("profileGuidanceJSON")} className="min-h-28 font-mono text-xs" spellCheck={false} />}
              </Field>
            </div>
          )}

          {step === 2 && (
            <div className="grid gap-4">
              {previewing && <LoadingState>{t("protocols.mdm.form.previewing")}</LoadingState>}
              {previewError && (
                <ErrorState title={t("protocols.mdm.form.previewFailed")}>
                  <p>{previewError}</p>
                  <Button className="mt-3" type="button" size="sm" variant="outline" onClick={() => void loadPreview()}>
                    {t("protocols.mdm.form.retryPreview")}
                  </Button>
                </ErrorState>
              )}
              {preview && (
                <section aria-label={t("protocols.mdm.form.previewLabel")} className="grid gap-4 rounded-panel border border-border bg-muted/25 p-4">
                  <div className="flex items-start gap-3">
                    <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
                    <div>
                      <h3 className="font-semibold">{preview.ready ? t("protocols.mdm.form.readyTitle") : t("protocols.mdm.form.blockedTitle")}</h3>
                      <p className="mt-1 text-sm text-muted-foreground">
                        {preview.effect_free ? t("protocols.mdm.form.effectFree") : t("protocols.mdm.form.effectWarning")}
                      </p>
                    </div>
                  </div>
                  <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    <PreviewFact label={t("protocols.mdm.form.operation")} value={preview.operation} />
                    <PreviewFact label={t("protocols.mdm.form.provider")} value={preview.provider} />
                    <PreviewFact label={t("protocols.mdm.form.profile")} value={preview.scep_profile} />
                    <PreviewFact label={t("protocols.mdm.form.challengeMode")} value={preview.challenge_mode} />
                    <PreviewFact label={t("protocols.mdm.form.writes")} value={String(preview.durable_writes.length)} />
                    <PreviewFact label={t("protocols.mdm.form.outsideCalls")} value={String(preview.outside_calls.length)} />
                    <PreviewFact label={t("protocols.mdm.form.signerCalls")} value={String(preview.signer_calls)} />
                    <PreviewFact
                      label={t("protocols.mdm.form.referenceKeys")}
                      value={preview.trust_anchor_reference_keys.join(", ") || t("protocols.mdm.form.none")}
                    />
                  </dl>
                  {preview.blockers.length > 0 && <PreviewList title={t("protocols.mdm.form.blockers")} items={preview.blockers} warning />}
                  <PreviewList title={t("protocols.mdm.form.recovery")} items={preview.recovery_steps} />
                  <p className="text-caption text-muted-foreground">{preview.secret_data_handling}</p>
                </section>
              )}
              {saveError && <ErrorState title={t("protocols.mdm.form.saveFailed")}>{saveError}</ErrorState>}
              <div className="flex flex-wrap justify-end gap-2">
                <Button type="button" variant="outline" onClick={onClose} disabled={saving}>
                  {t("protocols.mdm.form.cancel")}
                </Button>
                <Button type="submit" disabled={!preview?.ready || !preview.effect_free || saving || previewing}>
                  {saving ? t("protocols.mdm.form.saving") : policy ? t("protocols.mdm.form.saveChanges") : t("protocols.mdm.form.createAction")}
                </Button>
              </div>
            </div>
          )}
        </StepShell>
      </form>
    </Dialog>
  );
}

function PreviewFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 border-s-2 border-border ps-3">
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words font-medium">{value}</dd>
    </div>
  );
}

function PreviewList({ items, title, warning = false }: { items: string[]; title: string; warning?: boolean }) {
  if (items.length === 0) return null;
  return (
    <section className={warning ? "rounded-control border border-risk-warning/40 bg-risk-warning/10 p-3" : "border-s-2 border-border ps-3"}>
      <h4 className="text-sm font-semibold">{title}</h4>
      <ol className="mt-1 list-decimal space-y-1 ps-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </section>
  );
}
