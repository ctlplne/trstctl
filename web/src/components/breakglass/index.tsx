import { useEffect, useMemo, useState, type FormEvent } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";

import { CapabilityActionNotice, capabilityExecutionReason } from "@/components/CapabilityTruth";
import { SectionCard } from "@/components/dashboard";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  type BreakglassCeremony,
  type BreakglassIssueIntentRequest,
  type BreakglassIssuePlanPreview,
  type BreakglassIssueResponse,
  type BreakglassReconcileResponse,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";

type IssueForm = { request_id: string; subject: string; csr_der: string; reason: string; ttl_seconds: number };

const initialIssue: IssueForm = { request_id: "", subject: "", csr_der: "", reason: "", ttl_seconds: 900 };

function issueRequest(values: IssueForm): BreakglassIssueIntentRequest {
  return {
    request_id: values.request_id.trim(),
    subject: values.subject.trim(),
    csr_der: values.csr_der.trim(),
    reason: values.reason.trim(),
    ttl_seconds: values.ttl_seconds,
  };
}

function requestKey(request: BreakglassIssueIntentRequest): string {
  return JSON.stringify(request);
}

/** Guided emergency issuance. The browser never selects approvers or edits signer custody. */
export function BreakGlassReconcile() {
  const { t } = useTranslation();
  const previewAction = useCapabilityExecution("F34", "previewBreakglassIssue");
  const ceremonyAction = useCapabilityExecution("F34", "startBreakglassIssueCeremony");
  const issueAction = useCapabilityExecution("F34", "issueBreakglass");
  const reconcileAction = useCapabilityExecution("F34", "reconcileBreakglass");
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<{ requestKey: string; plan: BreakglassIssuePlanPreview } | null>(null);
  const [ceremony, setCeremony] = useState<BreakglassCeremony | null>(null);
  const [issueResult, setIssueResult] = useState<BreakglassIssueResponse | null>(null);
  const [reviewBusy, setReviewBusy] = useState(false);
  const [ceremonyBusy, setCeremonyBusy] = useState(false);
  const [refreshBusy, setRefreshBusy] = useState(false);
  const [issueBusy, setIssueBusy] = useState(false);
  const [onlineError, setOnlineError] = useState<string | null>(null);
  const schema = useMemo(
    () =>
      z.object({
        request_id: z.string().trim().min(1, t("broker.form.required")),
        subject: z.string().trim().min(1, t("broker.form.required")),
        csr_der: z.string().trim().min(1, t("broker.form.required")),
        reason: z.string().trim().min(1, t("broker.form.required")),
        ttl_seconds: z.number().int().positive().max(86400),
      }),
    [t],
  );
  const {
    control,
    register,
    trigger,
    getValues,
    reset,
    formState: { errors },
  } = useForm<IssueForm>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: initialIssue,
  });
  const watched = useWatch({ control });
  const currentRequest = issueRequest({ ...initialIssue, ...watched } as IssueForm);
  const currentRequestKey = requestKey(currentRequest);
  const reviewedPlan = review?.requestKey === currentRequestKey ? review.plan : null;
  const quorumComplete = Boolean(ceremony && (ceremony.status === "approved" || ceremony.approvals >= ceremony.threshold));

  useEffect(() => {
    if (!review || review.requestKey === currentRequestKey) return;
    setReview(null);
    setCeremony(null);
    setIssueResult(null);
    setOnlineError(null);
    setStep(0);
  }, [currentRequestKey, review]);

  async function preview() {
    if (!(await trigger()) || !previewAction.runnable) return;
    const request = issueRequest(getValues());
    setReviewBusy(true);
    setOnlineError(null);
    setIssueResult(null);
    try {
      const plan = await api.previewBreakglassIssue(request);
      setReview({ requestKey: requestKey(request), plan });
      setStep(1);
    } catch (error) {
      setOnlineError(apiProblemMessage(error, t("breakglass.review.failed")));
    } finally {
      setReviewBusy(false);
    }
  }

  async function openCeremony() {
    if (!reviewedPlan?.ready || !ceremonyAction.runnable) return;
    setCeremonyBusy(true);
    setOnlineError(null);
    try {
      setCeremony(await api.startBreakglassIssueCeremony(currentRequest));
      setStep(2);
    } catch (error) {
      setOnlineError(apiProblemMessage(error, t("breakglass.ceremony.failed")));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function refreshCeremony() {
    if (!ceremony) return;
    setRefreshBusy(true);
    setOnlineError(null);
    try {
      setCeremony(await api.caCeremony(ceremony.id));
    } catch (error) {
      setOnlineError(apiProblemMessage(error, t("breakglass.ceremony.refreshFailed")));
    } finally {
      setRefreshBusy(false);
    }
  }

  async function issue() {
    if (!ceremony || !quorumComplete || !issueAction.runnable) return;
    setIssueBusy(true);
    setOnlineError(null);
    try {
      setIssueResult(await api.breakglassIssue({ ...currentRequest, ceremony_id: ceremony.id }));
      setStep(3);
    } catch (error) {
      setOnlineError(apiProblemMessage(error, t("breakglass.issue.errorTitle")));
    } finally {
      setIssueBusy(false);
    }
  }

  function startAgain() {
    reset(initialIssue);
    setReview(null);
    setCeremony(null);
    setIssueResult(null);
    setOnlineError(null);
    setStep(0);
  }

  const steps: CarouselStep[] = [
    { id: "configure", label: t("breakglass.step.configure"), description: t("breakglass.step.configureHelp") },
    { id: "review", label: t("breakglass.step.review"), description: t("breakglass.step.reviewHelp") },
    { id: "approve", label: t("breakglass.step.approve"), description: t("breakglass.step.approveHelp") },
    { id: "verify", label: t("breakglass.step.verify"), description: t("breakglass.step.verifyHelp") },
  ];

  return (
    <SectionCard title={t("breakglass.workspace.title")} description={t("breakglass.workspace.description")}>
      <div className="grid gap-5">
        <div className="grid gap-2">
          <CapabilityActionNotice action={previewAction} />
          <CapabilityActionNotice action={ceremonyAction} />
          <CapabilityActionNotice action={issueAction} />
        </div>
        <StepShell
          steps={steps}
          currentIndex={step}
          progressLabel={t("breakglass.progress")}
          onPrevious={step > 0 && step < 3 ? () => setStep((current) => current - 1) : undefined}
          onNext={step === 0 ? () => void preview() : undefined}
          nextDisabled={reviewBusy || !previewAction.runnable}
          nextLabel={reviewBusy ? t("breakglass.review.busy") : t("breakglass.review.action")}
        >
          {step === 0 ? (
            <div className="grid gap-4">
              <div className="rounded-control border border-border bg-muted/30 p-3 text-sm">
                <p className="font-medium">{t("breakglass.configure.boundaryTitle")}</p>
                <p className="mt-1 text-muted-foreground">{t("breakglass.configure.boundaryHelp")}</p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <Field label={t("breakglass.request.id")} error={errors.request_id?.message} required>
                  {(field) => <Input {...field} {...register("request_id")} placeholder={t("breakglass.request.idPlaceholder")} />}
                </Field>
                <Field label={t("breakglass.request.subject")} error={errors.subject?.message} required>
                  {(field) => <Input {...field} {...register("subject")} placeholder={t("breakglass.request.subjectPlaceholder")} />}
                </Field>
                <Field label={t("breakglass.request.reason")} error={errors.reason?.message} required>
                  {(field) => <Input {...field} {...register("reason")} placeholder={t("breakglass.request.reasonPlaceholder")} />}
                </Field>
                <Field label={t("breakglass.request.ttl")} description={t("breakglass.request.ttlHelp")} error={errors.ttl_seconds?.message} required>
                  {(field) => <Input {...field} type="number" min="1" max="86400" step="1" {...register("ttl_seconds", { valueAsNumber: true })} />}
                </Field>
                <Field
                  className="md:col-span-2"
                  label={t("breakglass.request.csr")}
                  description={t("breakglass.request.csrHelp")}
                  error={errors.csr_der?.message}
                  required
                >
                  {(field) => (
                    <Textarea {...field} className="min-h-32 font-mono text-xs" {...register("csr_der")} placeholder={t("breakglass.request.csrPlaceholder")} />
                  )}
                </Field>
              </div>
            </div>
          ) : null}

          {step === 1 && reviewedPlan ? (
            <div className="grid gap-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-medium">{t("breakglass.review.noChanges")}</p>
                  <p className="text-sm text-muted-foreground">
                    {t("breakglass.review.quorum", { threshold: reviewedPlan.approval_threshold, count: reviewedPlan.configured_operator_count })}
                  </p>
                </div>
                <StatusBadge
                  value={reviewedPlan.ready ? "ready" : "blocked"}
                  label={reviewedPlan.ready ? t("breakglass.review.ready") : t("breakglass.review.blocked")}
                  tone={reviewedPlan.ready ? "success" : "warning"}
                />
              </div>
              <dl className="grid gap-3 rounded-control border border-border p-3 text-sm md:grid-cols-2">
                <ReviewValue label={t("breakglass.request.subject")} value={reviewedPlan.subject} />
                <ReviewValue label={t("breakglass.request.ttl")} value={`${reviewedPlan.effective_ttl_seconds}s`} />
                <ReviewValue label={t("breakglass.review.requestFingerprint")} value={reviewedPlan.request_fingerprint} mono />
                <ReviewValue label={t("breakglass.review.csrFingerprint")} value={reviewedPlan.csr_sha256} mono />
              </dl>
              <div className="grid gap-2">
                {reviewedPlan.prerequisites.map((item) => (
                  <div key={item.id} className="flex items-start gap-3 rounded-control border border-border p-3 text-sm">
                    <StatusBadge
                      value={item.ready ? "ready" : "blocked"}
                      label={item.ready ? t("breakglass.review.ready") : t("breakglass.review.blocked")}
                      tone={item.ready ? "success" : "warning"}
                    />
                    <div>
                      <p>{item.detail}</p>
                      {!item.ready && item.remediation ? <p className="mt-1 text-muted-foreground">{item.remediation}</p> : null}
                    </div>
                  </div>
                ))}
              </div>
              {reviewedPlan.blockers.length ? <ErrorState title={t("breakglass.review.blocked")}>{reviewedPlan.blockers.join(" ")}</ErrorState> : null}
              <Card>
                <CardHeader>
                  <CardTitle>{t("breakglass.review.executionTitle")}</CardTitle>
                </CardHeader>
                <CardContent className="grid gap-3 text-sm md:grid-cols-2">
                  <EvidenceList title={t("breakglass.review.writes")} items={reviewedPlan.execution_writes} />
                  <EvidenceList title={t("breakglass.review.signerCalls")} items={reviewedPlan.execution_signer_calls} />
                  <EvidenceList title={t("breakglass.review.recovery")} items={reviewedPlan.recovery_steps} />
                  <EvidenceList title={t("breakglass.review.verify")} items={reviewedPlan.verification_steps} />
                </CardContent>
              </Card>
              <div>
                <Button type="button" disabled={!reviewedPlan.ready || ceremonyBusy || !ceremonyAction.runnable} onClick={() => void openCeremony()}>
                  {ceremonyBusy ? t("breakglass.ceremony.opening") : t("breakglass.ceremony.open")}
                </Button>
              </div>
            </div>
          ) : null}

          {step === 2 && ceremony ? (
            <div className="grid gap-4">
              <div className="rounded-control border border-border p-4">
                <p className="text-sm text-muted-foreground">{t("breakglass.ceremony.id")}</p>
                <p className="mt-1 break-all font-mono text-sm">{ceremony.id}</p>
                <p className="mt-3 font-medium">{t("breakglass.ceremony.progress", { approvals: ceremony.approvals, threshold: ceremony.threshold })}</p>
                <p className="mt-1 text-sm text-muted-foreground">{t("breakglass.ceremony.help")}</p>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button type="button" variant="outline" disabled={refreshBusy} onClick={() => void refreshCeremony()}>
                  {refreshBusy ? t("breakglass.ceremony.refreshing") : t("breakglass.ceremony.refresh")}
                </Button>
                <Button type="button" disabled={!quorumComplete || issueBusy || !issueAction.runnable} onClick={() => void issue()}>
                  {issueBusy ? t("breakglass.issue.busy") : t("breakglass.issue.execute")}
                </Button>
              </div>
            </div>
          ) : null}

          {step === 3 && issueResult ? (
            <div className="grid gap-4">
              <div role="status" className="rounded-control border border-status-success/40 bg-status-success/10 p-4">
                <p className="font-medium">{t("breakglass.issue.status", { count: issueResult.reconciled })}</p>
                <p className="mt-1 text-sm text-muted-foreground">{t("breakglass.issue.audit", { event: issueResult.audit_event_type })}</p>
              </div>
              <EvidenceList title={t("breakglass.review.verify")} items={reviewedPlan?.verification_steps ?? []} />
              <div>
                <Button type="button" variant="outline" onClick={startAgain}>
                  {t("breakglass.startAgain")}
                </Button>
              </div>
            </div>
          ) : null}
        </StepShell>
        {onlineError ? <ErrorState title={t("breakglass.issue.errorTitle")}>{onlineError}</ErrorState> : null}
        <OfflineReconciliation action={reconcileAction} />
      </div>
    </SectionCard>
  );
}

function OfflineReconciliation({ action }: { action: ReturnType<typeof useCapabilityExecution> }) {
  const { t } = useTranslation();
  const [bundles, setBundles] = useState("");
  const [result, setResult] = useState<BreakglassReconcileResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function reconcile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!action.runnable) {
      setError(capabilityExecutionReason(action, t));
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(bundles);
    } catch {
      setError(t("breakglass.reconcile.invalid"));
      return;
    }
    const list = Array.isArray(parsed) ? parsed : [parsed];
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.breakglassReconcile({ bundles: list as never }));
    } catch (caught) {
      setError(apiProblemMessage(caught, t("breakglass.reconcile.failed")));
    } finally {
      setBusy(false);
    }
  }
  return (
    <details className="rounded-panel border border-border bg-card">
      <summary className="cursor-pointer px-4 py-3 font-medium">{t("breakglass.reconcile.title")}</summary>
      <div className="grid gap-3 border-t border-border p-4">
        <p className="text-sm text-muted-foreground">{t("breakglass.reconcile.description")}</p>
        <CapabilityActionNotice action={action} />
        <form onSubmit={(event) => void reconcile(event)} className="grid gap-3">
          <Field label={t("breakglass.reconcile.label")} description={t("breakglass.reconcile.help")} required>
            {(field) => (
              <Textarea
                {...field}
                value={bundles}
                onChange={(event) => setBundles(event.target.value)}
                rows={6}
                className="font-mono text-xs"
                placeholder='[{"request_id":"…","subject":"…","approvals":["…"],"cert_der":"…","signature":"…","issued_at":"…","reason":"…"}]'
              />
            )}
          </Field>
          <div>
            <Button type="submit" disabled={busy || !bundles.trim() || !action.runnable}>
              {busy ? t("breakglass.reconcile.busy") : t("breakglass.reconcile.action")}
            </Button>
          </div>
        </form>
        {error ? <ErrorState title={t("breakglass.reconcile.failed")}>{error}</ErrorState> : null}
        {result ? (
          <p role="status" className="rounded-control border border-border p-3 text-sm">
            {t("breakglass.reconcile.status", { count: result.reconciled })}
          </p>
        ) : null}
      </div>
    </details>
  );
}

function ReviewValue({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}

function EvidenceList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <p className="font-medium">{title}</p>
      <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
