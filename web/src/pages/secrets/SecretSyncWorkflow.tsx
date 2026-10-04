import { useEffect, useMemo, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useSearchParams } from "react-router-dom";
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
import { useApiQuery } from "@/lib/query";

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
  const [values, setValues] = useState<SecretSyncForm>(() => ({ name: initialName, target: catalog?.configured_targets[0] ?? "", remoteKey: "" }));
  const [searchParams, setSearchParams] = useSearchParams();
  const jobID = result?.job_id ?? searchParams.get("job_id") ?? "";
  const jobQuery = useApiQuery(["secret-sync-job", jobID], () => api.secretSyncJob(jobID), {
    enabled: Boolean(jobID),
    live: { intervalMs: 5_000 },
    retry: false,
  });
  const receipt = jobQuery.data ?? result;

  const { name, target, remoteKey } = values;
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
    if (!name && initialName) setValues((current) => ({ ...current, name: initialName }));
  }, [initialName, name]);

  useEffect(() => {
    if (!target && configuredTargets[0]) setValues((current) => ({ ...current, target: configuredTargets[0].id }));
  }, [configuredTargets, target]);

  function invalidateReview() {
    setReview(null);
    setIdempotencyKey(null);
    setRetryable(false);
    setResult(null);
    if (searchParams.has("job_id")) {
      const next = new URLSearchParams(searchParams);
      next.delete("job_id");
      setSearchParams(next, { replace: true });
    }
    setError(null);
    setStep(0);
  }

  async function reviewPlan(values: SecretSyncForm) {
    setPreviewBusy(true);
    setError(null);
    setRetryable(false);
    setResult(null);
    if (searchParams.has("job_id")) {
      const next = new URLSearchParams(searchParams);
      next.delete("job_id");
      setSearchParams(next, { replace: true });
    }
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
      const queued = await api.syncSecret({ ...currentReview.request, preview_fingerprint: currentReview.plan.request_fingerprint }, idempotencyKey);
      setResult(queued);
      if (queued.job_id) {
        const next = new URLSearchParams(searchParams);
        next.set("job_id", queued.job_id);
        setSearchParams(next, { replace: true });
      }
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
    return (
      <section id="secret-sync-setup" aria-label={t("secrets.sync.setupTitle")} tabIndex={-1}>
        <UnavailableState title={t("secrets.sync.noDestinationTitle")}>
          <p>{t("secrets.sync.noDestinationBody")}</p>
          <ol className="mt-2 list-decimal space-y-1 ps-5">
            <li>{t("secrets.sync.setupConfig")}</li>
            <li>{t("secrets.sync.setupCredential")}</li>
            <li>{t("secrets.sync.setupRestart")}</li>
          </ol>
        </UnavailableState>
      </section>
    );
  }

  return (
    <form
      id="secret-sync-setup"
      tabIndex={-1}
      aria-label={t("secrets.sync.formLabel")}
      className="-order-1 grid gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (step === 0) void reviewPlan(values);
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
        onNext={step === 0 ? () => void reviewPlan(values) : undefined}
        onPrevious={step === 1 ? () => setStep(0) : undefined}
        progressLabel={t("secrets.sync.progress")}
      >
        {step === 0 ? (
          <div className="grid gap-4 md:grid-cols-3">
            <Field label={t("secrets.sync.secretName")} required>
              {(field) => (
                <Input
                  {...field}
                  value={name}
                  onChange={(event) => {
                    setValues((current) => ({ ...current, name: event.target.value }));
                    invalidateReview();
                  }}
                  placeholder={t("secrets.sync.secretNameExample")}
                  required
                />
              )}
            </Field>
            <Field label={t("secrets.sync.target")} description={t("secrets.sync.targetHelp")} required>
              {(field) => (
                <Select
                  {...field}
                  value={target}
                  onChange={(event) => {
                    setValues((current) => ({ ...current, target: event.target.value }));
                    invalidateReview();
                  }}
                  required
                >
                  <option value="">{t("secrets.sync.chooseTarget")}</option>
                  {configuredTargets.map((configuredTarget) => (
                    <option key={configuredTarget.id} value={configuredTarget.id}>
                      {configuredTarget.label} — {configuredTarget.id}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t("secrets.sync.remoteKey")} description={t("secrets.sync.remoteKeyHelp")}>
              {(field) => (
                <Input
                  {...field}
                  value={remoteKey}
                  onChange={(event) => {
                    setValues((current) => ({ ...current, remoteKey: event.target.value }));
                    invalidateReview();
                  }}
                  placeholder={t("secrets.sync.remoteKeyExample")}
                />
              )}
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
      {receipt ? (
        <Card aria-live="polite">
          <CardHeader>
            <CardTitle>{t("secrets.sync.receiptTitle")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm md:grid-cols-2 xl:grid-cols-5">
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.secretName")}</p>
              <p>{receipt.name}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.target")}</p>
              <p>{receipt.target}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.remoteKey")}</p>
              <p className="break-all font-mono text-xs">{receipt.remote_key}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.queue")}</p>
              <p>{result?.enqueued === false ? t("secrets.sync.notQueued") : t("secrets.sync.queued")}</p>
            </div>
            <div>
              <p className="text-muted-foreground">{t("secrets.sync.delivery")}</p>
              <p>
                {jobQuery.data?.status === "delivered"
                  ? t("secrets.sync.delivered")
                  : jobQuery.data?.status === "failed"
                    ? t("secrets.sync.deliveryFailed")
                    : jobQuery.error
                      ? t("secrets.sync.statusUnavailable")
                      : jobQuery.data?.status === "pending"
                        ? t("secrets.sync.deliveryPending")
                        : t("secrets.sync.checkingDelivery")}
              </p>
            </div>
            <div className="md:col-span-2 xl:col-span-5">
              <p className="text-muted-foreground">{t("secrets.sync.jobID")}</p>
              <p className="break-all font-mono text-xs">{jobID}</p>
              {jobQuery.data ? <p>{t("secrets.sync.attempts", { count: jobQuery.data.attempts })}</p> : null}
              {jobQuery.data?.status === "failed" ? <p>{t("secrets.sync.failedRecovery")}</p> : null}
              {jobQuery.error ? <p>{t("secrets.sync.statusRecovery")}</p> : null}
              <Button type="button" variant="outline" onClick={jobQuery.refetch}>
                {t("secrets.sync.refreshDelivery")}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </form>
  );
}
