import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { CAAuthority, DeploymentTarget, EndpointBinding, EndpointBindingPreview, EndpointIssuer, ExternalCA, Identity, Owner } from "@/lib/api-types.gen";
import { useTranslation } from "@/i18n/I18nProvider";

const platformIssuer: EndpointIssuer = {
  source: "platform",
  id: "trstctl-issuing-ca",
  name: "trstctl issuing CA",
  type: "built-in",
  availability: "available",
};

type FormValues = {
  mode: "enroll" | "replace";
  replace_identity_id: string;
  target_id: string;
  owner_id: string;
  identity_name: string;
  reason: string;
  issuer_key: string;
};

type IssuerOption = EndpointIssuer & { available: boolean };

export function EndpointBindingWorkflow({
  targets,
  identities,
  onComplete,
}: {
  targets: DeploymentTarget[];
  identities: Identity[];
  onComplete: (binding: EndpointBinding, reason: string) => Promise<void> | void;
}) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [owners, setOwners] = useState<Owner[]>([]);
  const [externalCAs, setExternalCAs] = useState<ExternalCA[]>([]);
  const [privateCAs, setPrivateCAs] = useState<CAAuthority[]>([]);
  const [loading, setLoading] = useState(true);
  const [rosterError, setRosterError] = useState<string | null>(null);
  const [issuerWarning, setIssuerWarning] = useState<string | null>(null);
  const [preview, setPreview] = useState<EndpointBindingPreview | null>(null);
  const [busy, setBusy] = useState<"preview" | "execute" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [completed, setCompleted] = useState<EndpointBinding | null>(null);

  const schema = useMemo(
    () =>
      z
        .object({
          mode: z.enum(["enroll", "replace"]),
          replace_identity_id: z.string().trim(),
          target_id: z.string().trim().min(1, t("connectors.binding.required")),
          owner_id: z.string().trim().min(1, t("connectors.binding.required")),
          identity_name: z.string().trim().min(1, t("connectors.binding.required")),
          reason: z.string().trim().min(1, t("connectors.binding.required")),
          issuer_key: z.string().trim().min(1, t("connectors.binding.issuerRequired")),
        })
        .superRefine((values, context) => {
          if (values.mode === "replace" && !values.replace_identity_id) {
            context.addIssue({ code: z.ZodIssueCode.custom, path: ["replace_identity_id"], message: t("connectors.binding.originalRequired") });
          }
        }),
    [t],
  );
  const {
    control,
    register,
    trigger,
    getValues,
    setValue,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { mode: "enroll", replace_identity_id: "", target_id: "", owner_id: "", identity_name: "", reason: "", issuer_key: "" },
  });
  const issuerKey = useWatch({ control, name: "issuer_key" });
  const targetID = useWatch({ control, name: "target_id" });
  const mode = useWatch({ control, name: "mode" });
  const originalID = useWatch({ control, name: "replace_identity_id" });

  useEffect(() => {
    let cancelled = false;
    async function load() {
      // A roster call that throws synchronously (a missing method in a stubbed
      // client, a broken build) must land in the same settled slot as a
      // rejected request, so the page shows the error instead of dying quietly.
      const settle = <T,>(call: () => Promise<T>): Promise<T> => {
        try {
          return call();
        } catch (err) {
          return Promise.reject(err instanceof Error ? err : new Error(String(err)));
        }
      };
      const [ownerResult, externalResult, privateResult] = await Promise.allSettled([
        settle(() => api.owners()),
        settle(() => api.externalCAs()),
        settle(() => api.caAuthorities()),
      ]);
      if (cancelled) return;
      if (ownerResult.status === "fulfilled") setOwners(ownerResult.value ?? []);
      else setRosterError(ownerResult.reason instanceof Error ? ownerResult.reason.message : String(ownerResult.reason));
      const unavailable: string[] = [];
      if (externalResult.status === "fulfilled") setExternalCAs(externalResult.value ?? []);
      else unavailable.push(t("connectors.binding.externalUnavailable"));
      if (privateResult.status === "fulfilled") setPrivateCAs(privateResult.value.items ?? []);
      else unavailable.push(t("connectors.binding.privateUnavailable"));
      setIssuerWarning(unavailable.length > 0 ? unavailable.join(" ") : null);
      setLoading(false);
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [t]);

  const issuerOptions = useMemo<IssuerOption[]>(
    () => [
      { ...platformIssuer, available: true },
      ...externalCAs.map((issuer) => ({
        source: "external" as const,
        id: issuer.id,
        name: issuer.name,
        type: issuer.type,
        availability: issuer.status,
        available: issuer.status === "available",
      })),
      ...privateCAs.map((issuer) => ({
        source: "private" as const,
        id: issuer.id,
        name: issuer.common_name,
        type: issuer.kind,
        availability: issuer.status,
        available: issuer.status === "active",
      })),
    ],
    [externalCAs, privateCAs],
  );
  const selectedIssuer = issuerOptions.find((issuer) => issuerKey === encodeIssuer(issuer));
  const selectedTarget = targets.find((target) => target.id === targetID);
  const selectedTargetVerificationName = targetVerificationName(selectedTarget);
  const replacementCandidates = identities.filter(
    (identity) =>
      ["x509_certificate", "x509"].includes(identity.kind) &&
      ["deployed", "renewal_failed", "revoked"].includes(identity.status) &&
      identity.attributes?.deployment_target_id === targetID &&
      (!selectedTargetVerificationName || identity.name === selectedTargetVerificationName),
  );

  useEffect(() => {
    setValue("replace_identity_id", "");
  }, [targetID, mode, setValue]);

  useEffect(() => {
    if (mode !== "replace" || !originalID) return;
    const original = identities.find((identity) => identity.id === originalID);
    if (!original) return;
    setValue("owner_id", original.owner_id, { shouldDirty: true });
    setValue("identity_name", original.name, { shouldDirty: true });
  }, [identities, mode, originalID, setValue]);

  useEffect(() => {
    if (!selectedTargetVerificationName) return;
    setValue("identity_name", selectedTargetVerificationName, { shouldDirty: true, shouldValidate: true });
  }, [selectedTargetVerificationName, setValue]);

  const steps: CarouselStep[] = [
    { id: "endpoint", label: t("connectors.binding.endpointStep"), description: t("connectors.binding.endpointStepHelp") },
    { id: "issuer", label: t("connectors.binding.issuerStep"), description: t("connectors.binding.issuerStepHelp") },
    { id: "review", label: t("connectors.binding.reviewStep"), description: t("connectors.binding.reviewStepHelp") },
  ];

  async function advance() {
    setActionError(null);
    if (step === 0) {
      if (await trigger(["target_id", "owner_id", "identity_name", "reason", "mode", "replace_identity_id"])) setStep(1);
      return;
    }
    if (!(await trigger("issuer_key"))) return;
    const values = getValues();
    const issuer = decodeIssuer(values.issuer_key);
    if (!issuer) return;
    setBusy("preview");
    try {
      const reviewed = await api.previewEndpointBinding({
        ...(values.mode === "replace" ? { replace_identity_id: values.replace_identity_id } : {}),
        owner_id: values.owner_id.trim(),
        identity_name: values.identity_name.trim(),
        target_id: values.target_id,
        reason: values.reason.trim(),
        issuer,
      });
      if (!reviewed.ready || !reviewed.effect_free || reviewed.preview_writes.length > 0 || reviewed.preview_external_effects.length > 0) {
        throw new Error(t("connectors.binding.previewUnsafe"));
      }
      if (values.mode === "replace" && reviewed.replaced_identity?.id !== values.replace_identity_id) {
        throw new Error(t("connectors.binding.replacementPreviewMissing"));
      }
      setPreview(reviewed);
      setStep(2);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  }

  async function execute() {
    if (!preview || busy) return;
    const values = getValues();
    const issuer = decodeIssuer(values.issuer_key);
    if (!issuer) return;
    setActionError(null);
    setBusy("execute");
    try {
      const binding = await api.createEndpointBinding({
        ...(values.mode === "replace" ? { replace_identity_id: values.replace_identity_id } : {}),
        owner_id: values.owner_id.trim(),
        identity_name: values.identity_name.trim(),
        target_id: values.target_id,
        reason: values.reason.trim(),
        issuer,
        preview_fingerprint: preview.request_fingerprint,
      });
      setCompleted(binding);
      await onComplete(binding, values.reason.trim());
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  }

  function previous() {
    if (step === 2) setPreview(null);
    setActionError(null);
    setStep((current) => Math.max(0, current - 1));
  }

  if (loading) return <LoadingState>{t("connectors.binding.loading")}</LoadingState>;
  if (rosterError) return <ErrorState title={t("connectors.binding.loadFailed")}>{rosterError}</ErrorState>;

  return (
    <div className="grid gap-3">
      {issuerWarning ? <p className="rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm">{issuerWarning}</p> : null}
      <StepShell
        steps={steps}
        currentIndex={step}
        progressLabel={t("connectors.binding.progress")}
        onPrevious={step > 0 && !completed ? previous : undefined}
        onNext={step < 2 ? () => void advance() : undefined}
        nextDisabled={Boolean(busy) || owners.length === 0 || targets.every((target) => !target.enabled)}
        nextLabel={
          step === 0 ? t("connectors.binding.chooseIssuer") : busy === "preview" ? t("connectors.binding.previewing") : t("connectors.binding.preview")
        }
      >
        {step === 0 ? (
          <div className="grid gap-4 md:grid-cols-2">
            <Field label={t("connectors.binding.action")}>
              {(field) => (
                <Select {...field} {...register("mode")}>
                  <option value="enroll">{t("connectors.binding.enrollAction")}</option>
                  <option value="replace">{t("connectors.binding.replaceAction")}</option>
                </Select>
              )}
            </Field>
            <Field label={t("connectors.binding.destination")} description={t("connectors.binding.destinationHelp")} error={errors.target_id?.message} required>
              {(field) => (
                <Select {...field} {...register("target_id")}>
                  <option value="">{t("connectors.binding.selectDestination")}</option>
                  {targets.map((target) => (
                    <option key={target.id} value={target.id} disabled={!target.enabled}>
                      {target.name}
                      {t("connectors.targetReadiness.optionQualifier", { value: target.connector })}
                      {target.enabled ? "" : t("connectors.targetReadiness.optionQualifier", { value: t("connectors.targetReadiness.disabledShort") })}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {mode === "replace" ? (
              <Field
                label={t("connectors.binding.original")}
                description={t("connectors.binding.originalHelp")}
                error={errors.replace_identity_id?.message}
                required
              >
                {(field) => (
                  <Select {...field} {...register("replace_identity_id")}>
                    <option value="">{t("connectors.binding.selectOriginal")}</option>
                    {replacementCandidates.map((identity) => (
                      <option key={identity.id} value={identity.id}>
                        {identity.name} — {identity.id}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            ) : null}
            <Field label={t("connectors.binding.owner")} description={t("connectors.binding.ownerHelp")} error={errors.owner_id?.message} required>
              {(field) => (
                <Select {...field} {...register("owner_id")}>
                  <option value="">{t("connectors.binding.selectOwner")}</option>
                  {owners.map((owner) => (
                    <option key={owner.id} value={owner.id}>
                      {owner.name} — {owner.kind}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field
              label={t("connectors.binding.dnsName")}
              description={
                selectedTargetVerificationName
                  ? t("connectors.binding.dnsPinnedHelp", { name: selectedTargetVerificationName })
                  : t("connectors.binding.dnsHelp")
              }
              error={errors.identity_name?.message}
              required
            >
              {(field) => <Input {...field} {...register("identity_name")} autoComplete="off" readOnly={Boolean(selectedTargetVerificationName)} />}
            </Field>
            <Field
              label={t("connectors.targetReadiness.enrollmentReason")}
              description={t("connectors.binding.reasonHelp")}
              error={errors.reason?.message}
              required
            >
              {(field) => <Input {...field} {...register("reason")} autoComplete="off" />}
            </Field>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="grid gap-4">
            <p className="max-w-3xl text-sm text-muted-foreground">{t("connectors.binding.caAgnostic")}</p>
            <Field label={t("connectors.binding.issuer")} description={t("connectors.binding.issuerHelp")} error={errors.issuer_key?.message} required>
              {(field) => (
                <Select {...field} {...register("issuer_key")}>
                  <option value="">{t("connectors.binding.selectIssuer")}</option>
                  {issuerOptions.map((issuer) => (
                    <option key={encodeIssuer(issuer)} value={encodeIssuer(issuer)} disabled={!issuer.available}>
                      {sourceLabel(issuer.source, t)}: {issuer.name ?? issuer.id} — {issuer.availability ?? t("connectors.binding.statusUnknown")}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {selectedIssuer ? (
              <dl className="grid gap-3 rounded-control border border-border bg-muted/30 p-4 text-sm sm:grid-cols-3">
                <Fact label={t("connectors.binding.caSource")} value={sourceLabel(selectedIssuer.source, t)} />
                <Fact label={t("connectors.binding.caName")} value={selectedIssuer.name ?? selectedIssuer.id} />
                <Fact label={t("connectors.binding.caState")} value={selectedIssuer.availability ?? t("connectors.binding.statusUnknown")} />
              </dl>
            ) : (
              <p className="rounded-control border border-border p-3 text-sm text-muted-foreground">{t("connectors.binding.noIssuerDefault")}</p>
            )}
          </div>
        ) : null}

        {step === 2 && preview ? (
          <div className="grid gap-4">
            <div className="rounded-control border border-status-success/30 bg-status-success/10 p-4">
              <h3 className="font-semibold">{t("connectors.binding.previewReady")}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{t("connectors.binding.zeroEffect")}</p>
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <Fact label={t("connectors.binding.destination")} value={`${preview.target.name} — ${preview.target.connector}`} />
              <Fact label={t("connectors.binding.issuer")} value={`${sourceLabel(preview.issuer.source, t)}: ${preview.issuer.name ?? preview.issuer.id}`} />
              <Fact label={t("connectors.binding.keyCustody")} value={preview.custody.key_origin} />
              <Fact label={t("connectors.binding.owner")} value={owners.find((owner) => owner.id === preview.owner_id)?.name ?? preview.owner_id} />
            </dl>
            <p className="text-sm text-muted-foreground">{preview.custody.detail}</p>
            {preview.replaced_identity ? (
              <Fact label={t("connectors.binding.original")} value={`${preview.replaced_identity.name} — ${preview.replaced_identity.id}`} />
            ) : null}
            <ReviewList title={t("connectors.binding.changes")} items={preview.changes} />
            <ReviewList title={t("connectors.binding.queuedEffects")} items={preview.queued_lifecycle_intents} mono />
            <ReviewList title={t("connectors.binding.recovery")} items={preview.recovery_steps} />
            <ReviewList title={t("connectors.binding.verification")} items={preview.verification_steps} />
            <details className="rounded-control border border-border p-3 text-sm">
              <summary className="cursor-pointer font-medium">{t("connectors.binding.exactContract")}</summary>
              <dl className="mt-3 grid gap-2">
                <Fact label={t("connectors.binding.fingerprint")} value={preview.request_fingerprint} mono />
                <Fact label={t("connectors.binding.targetRevision")} value={preview.target.revision ?? t("connectors.binding.inlineTarget")} mono />
                <Fact label={t("connectors.binding.previewWrites")} value={String(preview.preview_writes.length)} />
                <Fact label={t("connectors.binding.previewCalls")} value={String(preview.preview_external_effects.length)} />
              </dl>
            </details>
            {completed ? (
              <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 p-3 text-sm font-medium">
                {completed.replaced_identity_id
                  ? t("connectors.binding.replacementQueued", { name: completed.identity.name, id: completed.replaced_identity_id })
                  : t("connectors.binding.queued", { name: completed.identity.name })}
              </p>
            ) : (
              <Button type="button" onClick={() => void execute()} disabled={Boolean(busy)}>
                {busy === "execute" ? t("connectors.binding.queueing") : t("connectors.binding.authorize")}
              </Button>
            )}
          </div>
        ) : null}
      </StepShell>
      {actionError ? <ErrorState title={t("connectors.binding.actionFailed")}>{actionError}</ErrorState> : null}
      {selectedTarget && !selectedTarget.enabled ? <p className="text-sm text-status-warning">{t("connectors.targetReadiness.disabledHelp")}</p> : null}
    </div>
  );
}

function targetVerificationName(target: DeploymentTarget | undefined): string {
  const value = target?.config?.verify_server_name;
  return typeof value === "string" ? value.trim() : "";
}

function encodeIssuer(issuer: Pick<EndpointIssuer, "source" | "id">): string {
  return `${issuer.source}:${issuer.id}`;
}

function decodeIssuer(value: string): Pick<EndpointIssuer, "source" | "id"> | null {
  const separator = value.indexOf(":");
  if (separator < 1) return null;
  const source = value.slice(0, separator);
  const id = value.slice(separator + 1);
  if ((source !== "platform" && source !== "private" && source !== "external") || !id) return null;
  return { source, id };
}

function sourceLabel(source: EndpointIssuer["source"], t: ReturnType<typeof useTranslation>["t"]): string {
  if (source === "external") return t("connectors.binding.sourceExternal");
  if (source === "private") return t("connectors.binding.sourcePrivate");
  return t("connectors.binding.sourcePlatform");
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={`${mono ? "font-mono text-xs" : ""} break-words`}>{value}</dd>
    </div>
  );
}

function ReviewList({ title, items, mono = false }: { title: string; items: string[]; mono?: boolean }) {
  return (
    <section>
      <h3 className="text-sm font-semibold">{title}</h3>
      <ul className={`mt-1 grid list-disc gap-1 ps-5 text-sm text-muted-foreground ${mono ? "font-mono text-xs" : ""}`}>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
