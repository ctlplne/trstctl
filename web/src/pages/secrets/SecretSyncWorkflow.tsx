import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { ShieldCheck } from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type SecretSync, type SecretSyncPreview, type SecretSyncRequest, type SecretSyncTargetCatalog } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilities, useCapabilityAction } from "@/lib/capabilities";

type SecretSyncForm = {
  name: string;
  target: string;
  remoteKey: string;
};

function normalizedRequest(values: SecretSyncForm): SecretSyncRequest {
  const remoteKey = values.remoteKey.trim();
  return {
    name: values.name.trim(),
    target: values.target.trim(),
    ...(remoteKey ? { remote_key: remoteKey } : {}),
  };
}

function requestKey(request: SecretSyncRequest): string {
  return JSON.stringify({ name: request.name, target: request.target, remote_key: request.remote_key ?? request.name });
}

function newSecretSyncIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") return `secret-sync-${globalThis.crypto.randomUUID()}`;
  return `secret-sync-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function actionIsRunnable(enabled: boolean, state: string): boolean {
  return !enabled || state === "allowed" || state === "scoped";
}

function PlanList({ title, items }: { title: string; items: string[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="list-disc space-y-1 ps-5 text-sm text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export function SecretSyncWorkflow({
  catalog,
  initialName,
  loadBlocked,
}: {
  catalog: SecretSyncTargetCatalog | null;
  initialName: string;
  loadBlocked: boolean;
}) {
  const { t } = useTranslation();
  const capabilities = useCapabilities();
  const previewAction = useCapabilityAction("F68", "previewSecretSync");
  const executeAction = useCapabilityAction("F68", "syncSecret");
  const previewRunnable = actionIsRunnable(capabilities.enabled, previewAction.state);
  const executeRunnable = actionIsRunnable(capabilities.enabled, executeAction.state);
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<{ requestKey: string; request: SecretSyncRequest; plan: SecretSyncPreview } | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [executeBusy, setExecuteBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryable, setRetryable] = useState(false);
  const [result, setResult] = useState<SecretSync | null>(null);

  const schema = useMemo(
    () =>
      z.object({
        name: z.string().trim().min(1, t("secrets.sync.required")),
        target: z.string().trim().min(1, t("secrets.sync.required")),
        remoteKey: z.string().trim(),
      }),
    [t],
  );
  const form = useForm<SecretSyncForm>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { name: initialName, target: catalog?.configured_targets[0] ?? "", remoteKey: "" },
  });
  const name = useWatch({ control: form.control, name: "name" }) ?? "";
  const target = useWatch({ control: form.control, name: "target" }) ?? "";
  const remoteKey = useWatch({ control: form.control, name: "remoteKey" }) ?? "";
  const request = normalizedRequest({ name, target, remoteKey });
  const currentReview = review?.requestKey === requestKey(request) ? review : null;
  const configuredTargets = useMemo(
    () =>
      (catalog?.configured_targets ?? []).map((id) => ({
        id,
        label: catalog?.targets.find((candidate) => candidate.id === id)?.name ?? id,
      })),
    [catalog],
  );

  useEffect(() => {
    if (!name && initialName) form.setValue("name", initialName, { shouldValidate: true });
  }, [form, initialName, name]);

  useEffect(() => {
    if (!target && configuredTargets[0]) form.setValue("target", configuredTargets[0].id, { shouldValidate: true });
  }, [configuredTargets, form, target]);

  function invalidateReview() {
    setReview(null);
    setIdempotencyKey(null);
    setRetryable(false);
    setResult(null);
    setError(null);
    setStep(0);
  }

  async function reviewPlan(values: SecretSyncForm) {
    setPreviewBusy(true);
    setError(null);
    setRetryable(false);
    setResult(null);
    const nextRequest = normalizedRequest(values);
    try {
      const plan = await api.previewSecretSync(nextRequest);
      if (!plan.effect_free || plan.preview_writes.length > 0 || plan.preview_external_effects.length > 0) {
        throw new Error(t("secrets.sync.previewUnsafe"));
      }
      if (plan.ready && !plan.request_fingerprint) throw new Error(t("secrets.sync.previewMissingFingerprint"));
      setReview({ requestKey: requestKey(nextRequest), request: nextRequest, plan });
      setIdempotencyKey(plan.ready ? newSecretSyncIdempotencyKey() : null);
      setStep(1);
    } catch (failure) {
      setReview(null);
      setIdempotencyKey(null);
      setError(apiProblemMessage(failure, t("secrets.sync.previewFailed")));
    } finally {
      setPreviewBusy(false);
    }
  }

  async function executeReviewed() {
    if (!currentReview?.plan.ready || !currentReview.plan.request_fingerprint || !idempotencyKey) {
      setError(t("secrets.sync.reviewRequired"));
      return;
    }
    setExecuteBusy(true);
    setError(null);
    try {
      setResult(await api.syncSecret({ ...currentReview.request, preview_fingerprint: currentReview.plan.request_fingerprint }, idempotencyKey));
      setRetryable(false);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        setReview(null);
        setIdempotencyKey(null);
        setRetryable(false);
        setStep(0);
        setError(t("secrets.sync.previewStale"));
      } else {
        setRetryable(!(failure instanceof ApiError) || failure.status >= 500);
        setError(apiProblemMessage(failure, t("secrets.sync.executeFailed")));
      }
    } finally {
      setExecuteBusy(false);
    }
  }

  const configureReady = Boolean(name.trim() && target.trim());
  const steps = [
    {
      id: "configure",
      label: t("secrets.sync.configureStep"),
      description: t("secrets.sync.configureStepHelp"),
      progressState: configureReady ? ("done" as const) : ("pending" as const),
    },
    {
      id: "review",
      label: t("secrets.sync.reviewStep"),
      description: t("secrets.sync.reviewStepHelp"),
      progressState: currentReview?.plan.ready ? ("done" as const) : currentReview ? ("blocked" as const) : ("pending" as const),
    },
  ];

  if (catalog && configuredTargets.length === 0) {
    return <UnavailableState title={t("secrets.sync.noDestinationTitle")}>{t("secrets.sync.noDestinationBody")}</UnavailableState>;
  }

  return (
    <form
      aria-label={t("secrets.sync.formLabel")}
      className="-order-1 grid gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (step === 0) void form.handleSubmit(reviewPlan)();
        else void executeReviewed();
      }}
    >
      {!previewRunnable || !executeRunnable ? (
        <UnavailableState title={t("secrets.sync.permissionBlocked")}>
          {previewAction.unavailable?.detail ?? executeAction.unavailable?.detail ?? t("secrets.sync.permissionHelp")}
        </UnavailableState>
      ) : null}
      <StepShell
        steps={steps}
        currentIndex={step}
        nextDisabled={!configureReady || previewBusy || loadBlocked || !previewRunnable || configuredTargets.length === 0}
        nextLabel={previewBusy ? t("secrets.sync.reviewing") : t("secrets.sync.reviewAction")}
        onNext={step === 0 ? () => void form.handleSubmit(reviewPlan)() : undefined}
        onPrevious={step === 1 ? () => setStep(0) : undefined}
        progressLabel={t("secrets.sync.progress")}
      >
        {step === 0 ? (
          <div className="grid gap-4 md:grid-cols-3">
            <Field label={t("secrets.sync.secretName")} error={form.formState.errors.name?.message} required>
              {(field) => (
                <Input {...field} {...form.register("name", { onChange: invalidateReview })} placeholder={t("secrets.sync.secretNameExample")} required />
              )}
            </Field>
            <Field label={t("secrets.sync.target")} description={t("secrets.sync.targetHelp")} error={form.formState.errors.target?.message} required>
              {(field) => (
                <Select {...field} {...form.register("target", { onChange: invalidateReview })} required>
                  <option value="">{t("secrets.sync.chooseTarget")}</option>
                  {configuredTargets.map((configuredTarget) => (
                    <option key={configuredTarget.id} value={configuredTarget.id}>
                      {configuredTarget.label} — {configuredTarget.id}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t("secrets.sync.remoteKey")} description={t("secrets.sync.remoteKeyHelp")} error={form.formState.errors.remoteKey?.message}>
              {(field) => <Input {...field} {...form.register("remoteKey", { onChange: invalidateReview })} placeholder={t("secrets.sync.remoteKeyExample")} />}
            </Field>
          </div>
        ) : currentReview ? (
          <div className="grid gap-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">{currentReview.plan.ready ? t("secrets.sync.previewReady") : t("secrets.sync.previewBlocked")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.sync.previewNoEffects")}</p>
              </div>
              <StatusBadge
                value={currentReview.plan.ready ? "ready" : "blocked"}
                label={currentReview.plan.ready ? t("secrets.sync.ready") : t("secrets.sync.blocked")}
                tone={currentReview.plan.ready ? "success" : "warning"}
              />
            </div>
            <p className="text-sm font-medium">{t("secrets.sync.versionSummary", { version: currentReview.plan.secret_version })}</p>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-muted-foreground">{t("secrets.sync.secretName")}</dt>
                <dd className="break-all font-medium">{currentReview.plan.name}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.sync.target")}</dt>
                <dd className="break-all font-medium">{currentReview.plan.target}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.sync.remoteKey")}</dt>
                <dd className="break-all font-mono text-xs">{currentReview.plan.remote_key}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.sync.permission")}</dt>
                <dd className="font-mono text-xs">{currentReview.plan.required_permission}</dd>
              </div>
            </dl>
            {currentReview.plan.blockers.length > 0 ? (
              <ErrorState title={t("secrets.sync.previewBlocked")}>
                <ul className="list-disc space-y-1 ps-5">
                  {currentReview.plan.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </ErrorState>
            ) : null}
            <div className="grid gap-4 lg:grid-cols-3">
              <PlanList title={t("secrets.sync.effects")} items={[...currentReview.plan.execute_writes, ...currentReview.plan.execute_external_effects]} />
              <PlanList title={t("secrets.sync.recovery")} items={currentReview.plan.recovery_steps} />
              <PlanList title={t("secrets.sync.verification")} items={currentReview.plan.verification_steps} />
            </div>
            <p className="text-sm text-muted-foreground">{currentReview.plan.secret_data_handling}</p>
            {currentReview.plan.request_fingerprint ? (
              <details>
                <summary className="cursor-pointer text-sm font-medium text-primary">{t("secrets.sync.exactEvidence")}</summary>
                <div className="mt-2">
                  <CredentialChip value={currentReview.plan.request_fingerprint} label={t("secrets.sync.fingerprint")} fullValue />
                </div>
              </details>
            ) : null}
          </div>
        ) : (
          <ErrorState title={t("secrets.sync.previewFailed")}>{t("secrets.sync.reviewRequired")}</ErrorState>
        )}
      </StepShell>
      {error ? <ErrorState title={step === 0 ? t("secrets.sync.previewFailed") : t("secrets.sync.executeFailed")}>{error}</ErrorState> : null}
      {step === 1 && currentReview?.plan.ready ? (
        <div className="flex justify-end">
          <Button type="submit" disabled={executeBusy || !executeRunnable} loading={executeBusy}>
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            {retryable ? t("secrets.sync.retryReviewed") : t("secrets.sync.executeReviewed")}
          </Button>
        </div>
      ) : null}
      {result ? (
        <Card aria-live="polite">
          <CardHeader>
            <CardTitle>{t("secrets.sync.receiptTitle")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-5">
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.secretName")}</p>
              <p>{result.name}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.target")}</p>
              <p>{result.target}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.remoteKey")}</p>
              <p className="break-all font-mono text-xs">{result.remote_key}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.queue")}</p>
              <p>{result.enqueued ? t("secrets.sync.queued") : t("secrets.sync.notQueued")}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.delivery")}</p>
              <p>{result.delivered ? t("secrets.sync.delivered") : t("secrets.sync.notDelivered")}</p>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </form>
  );
}
