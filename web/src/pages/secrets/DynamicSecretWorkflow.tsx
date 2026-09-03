import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound, RotateCw, Trash2 } from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  ApiError,
  api,
  type DynamicLease,
  type DynamicLeasePreview,
  type DynamicLeaseRequest,
  type DynamicSecretProviderCatalog,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilities, useCapabilityAction } from "@/lib/capabilities";
import { useApiQuery } from "@/lib/query";
import { DynamicLeaseMetadata, formatCommandArgv, leaseMetadataOnly, RevealPanel } from "./SecretsPageParts";

type DynamicLeaseForm = {
  provider: string;
  role: string;
  ttlSeconds: number;
};

function newDynamicLeaseIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") return `dynamic-lease-${globalThis.crypto.randomUUID()}`;
  return `dynamic-lease-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function requestKey(request: DynamicLeaseRequest): string {
  return JSON.stringify({ provider: request.provider, role: request.role, ttl_seconds: request.ttl_seconds });
}

function actionIsRunnable(enabled: boolean, state: string): boolean {
  return !enabled || state === "allowed" || state === "scoped";
}

export function DynamicSecretWorkflow({ loadBlocked }: { loadBlocked: boolean }) {
  const { t } = useTranslation();
  const capabilities = useCapabilities();
  const previewAction = useCapabilityAction("F65", "previewDynamicSecretLease");
  const issueAction = useCapabilityAction("F65", "issueDynamicSecretLease");
  const previewRunnable = actionIsRunnable(capabilities.enabled, previewAction.state);
  const issueRunnable = actionIsRunnable(capabilities.enabled, issueAction.state);
  const catalogQuery = useApiQuery(["dynamic-secret-providers"], () => api.dynamicSecretProviders(), { retry: false });
  const catalog = catalogQuery.data;
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<{ requestKey: string; plan: DynamicLeasePreview } | null>(null);
  const [reviewBusy, setReviewBusy] = useState(false);
  const [issueBusy, setIssueBusy] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState<"renew" | "revoke" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryable, setRetryable] = useState(false);
  const [issueKey, setIssueKey] = useState<string | null>(null);
  const [lease, setLease] = useState<DynamicLease | null>(null);
  const [credential, setCredential] = useState<{ leaseID: string; value: string } | null>(null);
  const [extendSeconds, setExtendSeconds] = useState("300");

  const schema = useMemo(
    () =>
      z.object({
        provider: z.string().trim().min(1, t("secrets.dynamic.required")),
        role: z.string().trim().min(1, t("secrets.dynamic.required")),
        ttlSeconds: z.number().int().positive(t("secrets.dynamic.ttlError")),
      }),
    [t],
  );
  const {
    control,
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<DynamicLeaseForm>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { provider: "", role: "", ttlSeconds: 900 },
  });
  const providerID = useWatch({ control, name: "provider" });
  const role = useWatch({ control, name: "role" });
  const ttlSeconds = useWatch({ control, name: "ttlSeconds" });
  const selectedProvider = catalog?.configured_providers.find((provider) => provider.id === providerID) ?? null;
  const selectedSetup = catalog?.supported_providers.find((provider) => provider.type === selectedProvider?.type) ?? null;

  useEffect(() => {
    if (!catalog || catalog.configured_providers.length === 0 || providerID) return;
    const provider = catalog.configured_providers[0];
    setValue("provider", provider.id, { shouldValidate: true });
    setValue("role", provider.allowed_roles[0] ?? "", { shouldValidate: true });
    if (provider.maximum_ttl_seconds > 0) setValue("ttlSeconds", Math.min(900, provider.maximum_ttl_seconds), { shouldValidate: true });
  }, [catalog, providerID, setValue]);

  function invalidateReview() {
    setReview(null);
    setIssueKey(null);
    setRetryable(false);
    setLease(null);
    setCredential(null);
    setError(null);
    setStep(0);
  }

  function selectProvider(id: string) {
    const next = catalog?.configured_providers.find((provider) => provider.id === id);
    invalidateReview();
    setValue("provider", id, { shouldDirty: true, shouldValidate: true });
    setValue("role", next?.allowed_roles[0] ?? "", { shouldDirty: true, shouldValidate: true });
    if (next?.maximum_ttl_seconds) setValue("ttlSeconds", Math.min(900, next.maximum_ttl_seconds), { shouldDirty: true, shouldValidate: true });
  }

  async function reviewPlan(values: DynamicLeaseForm) {
    setReviewBusy(true);
    setError(null);
    setRetryable(false);
    setLease(null);
    setCredential(null);
    const request: DynamicLeaseRequest = {
      provider: values.provider.trim(),
      role: values.role.trim(),
      ttl_seconds: values.ttlSeconds,
    };
    try {
      const plan = await api.previewDynamicLease(request);
      if (!plan.effect_free || plan.preview_writes.length > 0 || plan.preview_external_effects.length > 0) {
        throw new Error(t("secrets.dynamic.previewNotEffectFree"));
      }
      if (!plan.ready || plan.blockers.length > 0) throw new Error(plan.blockers.join(" ") || t("secrets.dynamic.previewBlocked"));
      setReview({ requestKey: requestKey(request), plan });
      setIssueKey(newDynamicLeaseIdempotencyKey());
      setStep(1);
    } catch (failure) {
      setReview(null);
      setIssueKey(null);
      setError(apiProblemMessage(failure, t("secrets.dynamic.previewFailed")));
    } finally {
      setReviewBusy(false);
    }
  }

  async function issueReviewed() {
    if (!review?.plan.ready || !issueKey) {
      setError(t("secrets.dynamic.reviewRequired"));
      return;
    }
    setIssueBusy(true);
    setError(null);
    const plan = review.plan;
    try {
      const issued = await api.issueDynamicLease(
        {
          provider: plan.provider_id,
          role: plan.role,
          ttl_seconds: plan.effective_ttl_seconds,
          preview_fingerprint: plan.request_fingerprint,
        },
        issueKey,
      );
      setLease(leaseMetadataOnly(issued));
      setCredential(issued.credential ? { leaseID: issued.id, value: issued.credential } : null);
      setRetryable(false);
      setStep(2);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        setReview(null);
        setIssueKey(null);
        setRetryable(false);
        setStep(0);
        setError(t("secrets.dynamic.reviewStale"));
      } else {
        setRetryable(!(failure instanceof ApiError) || failure.status >= 500);
        setError(apiProblemMessage(failure, t("secrets.dynamic.issueFailed")));
      }
    } finally {
      setIssueBusy(false);
    }
  }

  async function renewLease() {
    if (!lease) return;
    const extend = Number(extendSeconds);
    if (!Number.isSafeInteger(extend) || extend <= 0) {
      setError(t("secrets.dynamic.extendError"));
      return;
    }
    setLifecycleBusy("renew");
    setError(null);
    try {
      setLease(leaseMetadataOnly(await api.renewDynamicLease(lease.id, { extend_seconds: extend })));
    } catch (failure) {
      setError(apiProblemMessage(failure, t("secrets.dynamic.renewFailed")));
    } finally {
      setLifecycleBusy(null);
    }
  }

  async function revokeLease() {
    if (!lease) return;
    setLifecycleBusy("revoke");
    setError(null);
    setCredential(null);
    try {
      setLease(leaseMetadataOnly(await api.revokeDynamicLease(lease.id)));
    } catch (failure) {
      setError(apiProblemMessage(failure, t("secrets.dynamic.revokeFailed")));
    } finally {
      setLifecycleBusy(null);
    }
  }

  function startAgain() {
    const firstProvider = catalog?.configured_providers[0];
    reset({
      provider: firstProvider?.id ?? "",
      role: firstProvider?.allowed_roles[0] ?? "",
      ttlSeconds: firstProvider?.maximum_ttl_seconds ? Math.min(900, firstProvider.maximum_ttl_seconds) : 900,
    });
    setReview(null);
    setIssueKey(null);
    setRetryable(false);
    setLease(null);
    setCredential(null);
    setError(null);
    setStep(0);
  }

  if (catalogQuery.loading) return <LoadingState>{t("secrets.dynamic.loading")}</LoadingState>;
  if (catalogQuery.error || !catalog) {
    return <ErrorState title={t("secrets.dynamic.catalogFailed")}>{catalogQuery.error ?? t("secrets.dynamic.catalogMissing")}</ErrorState>;
  }

  const configured = catalog.configured_providers;
  const currentRequest: DynamicLeaseRequest = { provider: providerID ?? "", role: role ?? "", ttl_seconds: Number(ttlSeconds) || 0 };
  const currentReview = review?.requestKey === requestKey(currentRequest) ? review.plan : null;
  const configureReady = Boolean(selectedProvider?.ready && role && Number(ttlSeconds) > 0 && previewRunnable && !loadBlocked);
  const steps = [
    {
      id: "configure",
      label: t("secrets.dynamic.configureStep"),
      description: t("secrets.dynamic.configureStepHelp"),
      progressState: configureReady ? ("done" as const) : ("pending" as const),
    },
    {
      id: "review",
      label: t("secrets.dynamic.reviewStep"),
      description: t("secrets.dynamic.reviewStepHelp"),
      progressState: currentReview?.ready ? ("done" as const) : currentReview ? ("blocked" as const) : ("pending" as const),
    },
    {
      id: "verify",
      label: t("secrets.dynamic.verifyStep"),
      description: t("secrets.dynamic.verifyStepHelp"),
      progressState: lease?.state === "revoked" ? ("done" as const) : ("pending" as const),
    },
  ];

  return (
    <section aria-labelledby="dynamic-secrets-heading" className="grid gap-4">
      <div>
        <h2 id="dynamic-secrets-heading" className="text-title font-semibold">
          {t("secrets.dynamic.title")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.dynamic.answer")}</p>
      </div>

      {configured.length === 0 ? (
        <UnavailableState title={t("secrets.dynamic.setupNeeded")}>
          <ul className="list-disc space-y-1 ps-5">
            {catalog.blockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        </UnavailableState>
      ) : null}

      {!previewRunnable || !issueRunnable ? (
        <UnavailableState title={t("secrets.dynamic.permissionBlocked")}>
          {previewAction.unavailable?.detail ?? issueAction.unavailable?.detail ?? t("secrets.dynamic.permissionHelp")}
        </UnavailableState>
      ) : null}

      <StepShell
        steps={steps}
        currentIndex={step}
        nextDisabled={!configureReady || reviewBusy || configured.length === 0}
        nextLabel={reviewBusy ? t("secrets.dynamic.reviewing") : t("secrets.dynamic.reviewAction")}
        onNext={step === 0 ? () => void handleSubmit(reviewPlan)() : undefined}
        onPrevious={step > 0 ? () => setStep(step - 1) : undefined}
        progressLabel={t("secrets.dynamic.progress")}
      >
        {step === 0 ? (
          <div className="grid gap-4">
            <div className="grid gap-4 md:grid-cols-3">
              <Field label={t("secrets.dynamic.provider")} description={t("secrets.dynamic.providerHelp")} error={errors.provider?.message} required>
                {(field) => (
                  <Select {...field} {...register("provider")} value={providerID ?? ""} onChange={(event) => selectProvider(event.target.value)} required>
                    <option value="">{t("secrets.dynamic.chooseProvider")}</option>
                    {configured.map((provider) => (
                      <option key={provider.id} value={provider.id}>
                        {provider.id} — {provider.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("secrets.dynamic.role")} description={t("secrets.dynamic.roleHelp")} error={errors.role?.message} required>
                {(field) => (
                  <Select
                    {...field}
                    {...register("role", { onChange: invalidateReview })}
                    value={role ?? ""}
                    disabled={!selectedProvider}
                    required
                  >
                    <option value="">{t("secrets.dynamic.chooseRole")}</option>
                    {selectedProvider?.allowed_roles.map((allowedRole) => (
                      <option key={allowedRole} value={allowedRole}>
                        {allowedRole}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("secrets.dynamic.ttl")} description={t("secrets.dynamic.ttlHelp")} error={errors.ttlSeconds?.message} required>
                {(field) => (
                  <Input
                    {...field}
                    {...register("ttlSeconds", { valueAsNumber: true, onChange: invalidateReview })}
                    type="number"
                    min="1"
                    max={selectedProvider?.maximum_ttl_seconds || undefined}
                    step="1"
                    required
                  />
                )}
              </Field>
            </div>

            <div className="grid gap-3 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>{selectedProvider ? t("secrets.dynamic.configured", { provider: selectedProvider.id }) : t("secrets.dynamic.notSelected")}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm text-muted-foreground">
                  <p>{catalog.secret_data_handling}</p>
                  {selectedProvider ? (
                    <dl className="grid gap-2 sm:grid-cols-2">
                      <div>
                        <dt>{t("secrets.dynamic.backendType")}</dt>
                        <dd className="font-medium text-foreground">{selectedProvider.label}</dd>
                      </div>
                      <div>
                        <dt>{t("secrets.dynamic.maxTTL")}</dt>
                        <dd className="font-mono text-foreground">{selectedProvider.maximum_ttl_seconds}s</dd>
                      </div>
                    </dl>
                  ) : null}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>{selectedSetup?.label ?? t("secrets.dynamic.requirements")}</CardTitle>
                  {selectedSetup ? <p className="text-sm text-muted-foreground">{selectedSetup.purpose}</p> : null}
                </CardHeader>
                <CardContent>
                  <RequirementList provider={selectedSetup} />
                </CardContent>
              </Card>
            </div>

            <details>
              <summary className="cursor-pointer text-sm font-medium text-primary">{t("secrets.dynamic.allSetups", { count: catalog.supported_providers.length })}</summary>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {catalog.supported_providers.map((provider) => (
                  <Card key={provider.type}>
                    <CardHeader>
                      <CardTitle>{provider.label}</CardTitle>
                      <p className="text-sm text-muted-foreground">{provider.purpose}</p>
                    </CardHeader>
                    <CardContent>
                      <RequirementList provider={provider} requiredOnly />
                    </CardContent>
                  </Card>
                ))}
              </div>
            </details>
          </div>
        ) : null}

        {step === 1 && currentReview ? (
          <div className="grid gap-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">{t("secrets.dynamic.readyTitle")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.dynamic.noPreviewEffects")}</p>
              </div>
              <StatusBadge value="ready" label={t("secrets.dynamic.ready")} tone="success" />
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <ReviewFact label={t("secrets.dynamic.provider")} value={`${currentReview.provider_id} — ${currentReview.provider_label}`} />
              <ReviewFact label={t("secrets.dynamic.role")} value={currentReview.role} />
              <ReviewFact label={t("secrets.dynamic.effectiveTTL")} value={`${currentReview.effective_ttl_seconds}s`} mono />
              <ReviewFact label={t("secrets.dynamic.permission")} value={currentReview.required_permission} mono />
            </dl>
            <div className="grid gap-4 md:grid-cols-3">
              <PlanList title={t("secrets.dynamic.effects")} items={[...currentReview.execute_writes, ...currentReview.execute_external_effects]} />
              <PlanList title={t("secrets.dynamic.recovery")} items={currentReview.recovery_steps} />
              <PlanList title={t("secrets.dynamic.verification")} items={currentReview.verification_steps} />
            </div>
            <div className="rounded-control border border-border bg-muted/40 p-3 text-sm">
              <p className="text-muted-foreground">{t("secrets.dynamic.cliParity")}</p>
              <code className="mt-1 block break-all font-mono text-xs">{formatCommandArgv(currentReview.cli_argv)}</code>
            </div>
            <p className="text-sm text-muted-foreground">{currentReview.secret_data_handling}</p>
            <p className="break-all font-mono text-xs text-muted-foreground">
              {t("secrets.dynamic.fingerprint")}: {currentReview.request_fingerprint}
            </p>
          </div>
        ) : null}

        {step === 2 && lease ? (
          <div className="grid gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="font-semibold">{lease.state === "revoked" ? t("secrets.dynamic.revokedTitle") : t("secrets.dynamic.issuedTitle")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.dynamic.verifyHelp")}</p>
              </div>
              <StatusBadge value={lease.state} label={lease.state} tone={lease.state === "revoked" ? "neutral" : "success"} />
            </div>
            <DynamicLeaseMetadata lease={lease} />
            {credential ? (
              <RevealPanel title={t("secrets.dynamic.credentialTitle", { id: credential.leaseID })} onDismiss={() => setCredential(null)} value={credential.value}>
                {t("secrets.dynamic.credentialHelp")}
              </RevealPanel>
            ) : null}
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-end">
              <Field label={t("secrets.dynamic.extend")} description={t("secrets.dynamic.extendHelp")}>
                {(field) => <Input {...field} type="number" min="1" step="1" value={extendSeconds} onChange={(event) => setExtendSeconds(event.target.value)} />}
              </Field>
              <Button type="button" variant="outline" onClick={() => void renewLease()} disabled={lifecycleBusy !== null || lease.state === "revoked"} loading={lifecycleBusy === "renew"}>
                <RotateCw className="h-4 w-4" aria-hidden="true" />
                {t("secrets.dynamic.renew")}
              </Button>
              <Button type="button" variant="destructive-outline" onClick={() => void revokeLease()} disabled={lifecycleBusy !== null || lease.state === "revoked"} loading={lifecycleBusy === "revoke"}>
                <Trash2 className="h-4 w-4" aria-hidden="true" />
                {t("secrets.dynamic.revoke")}
              </Button>
            </div>
            <PlanList title={t("secrets.dynamic.verification")} items={currentReview?.verification_steps ?? []} />
          </div>
        ) : null}
      </StepShell>

      {error ? <ErrorState title={t("secrets.dynamic.needsAttention")}>{error}</ErrorState> : null}
      <div className="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="ghost" onClick={startAgain} disabled={reviewBusy || issueBusy || lifecycleBusy !== null}>
          {step === 2 ? t("secrets.dynamic.startAgain") : t("secrets.dynamic.cancel")}
        </Button>
        {step === 1 && currentReview ? (
          <Button type="button" onClick={() => void issueReviewed()} disabled={issueBusy || !currentReview.ready || !issueRunnable || loadBlocked} loading={issueBusy}>
            <KeyRound className="h-4 w-4" aria-hidden="true" />
            {retryable ? t("secrets.dynamic.retry") : t("secrets.dynamic.issueReviewed")}
          </Button>
        ) : null}
      </div>
    </section>
  );
}

function RequirementList({
  provider,
  requiredOnly = false,
}: {
  provider: DynamicSecretProviderCatalog["supported_providers"][number] | null | undefined;
  requiredOnly?: boolean;
}) {
  const { t } = useTranslation();
  const requirements = provider?.requirements.filter((requirement) => !requiredOnly || requirement.required) ?? [];
  if (requirements.length === 0) return <p className="text-sm text-muted-foreground">{t("secrets.dynamic.chooseProviderHelp")}</p>;
  return (
    <ul className="space-y-3">
      {requirements.map((requirement) => (
        <li key={requirement.key} className="border-s-2 border-border ps-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{requirement.label}</span>
            <span className="rounded-control border border-border bg-muted/50 px-1.5 py-0.5 text-caption text-muted-foreground">
              {requirement.required ? t("secrets.dynamic.requiredLabel") : t("secrets.dynamic.optionalLabel")}
            </span>
            {requirement.kind === "credential_reference" ? (
              <span className="rounded-control border border-border bg-muted/50 px-1.5 py-0.5 text-caption text-muted-foreground">
                {t("secrets.dynamic.referenceOnly")}
              </span>
            ) : null}
          </div>
          <p className="mt-1 text-muted-foreground">{requirement.description}</p>
          <code className="mt-1 block break-all font-mono text-caption text-foreground">{requirement.key}</code>
        </li>
      ))}
    </ul>
  );
}

function ReviewFact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-all font-medium"}>{value}</dd>
    </div>
  );
}

function PlanList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h4 className="font-medium">{title}</h4>
      <ul className="mt-1 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
