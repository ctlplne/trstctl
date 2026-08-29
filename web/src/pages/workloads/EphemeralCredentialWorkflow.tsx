import { useMemo, useState } from "react";
import { CheckCircle2, Clipboard, Clock3, RotateCcw, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type EphemeralCredential, type EphemeralCredentialPreview, type EphemeralCredentialRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";

type ReviewedPlan = { key: string; value: EphemeralCredentialPreview };

function newRequestID(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") return `jit-${globalThis.crypto.randomUUID()}`;
  return `jit-${Date.now()}`;
}

export function EphemeralCredentialWorkflow() {
  const { t } = useTranslation();
  const previewAction = useCapabilityExecution("F25", "previewEphemeralCredential");
  const issueAction = useCapabilityExecution("F25", "issueEphemeralCredential");
  const [step, setStep] = useState(0);
  const [requestID, setRequestID] = useState(newRequestID);
  const [method, setMethod] = useState("");
  const [payload, setPayload] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [ttlSeconds, setTTLSeconds] = useState("600");
  const [reviewed, setReviewed] = useState<ReviewedPlan | null>(null);
  const [result, setResult] = useState<EphemeralCredential | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const request = useMemo<EphemeralCredentialRequest>(() => {
    const ttl = Number(ttlSeconds);
    return {
      request_id: requestID.trim(),
      method: method.trim(),
      payload_base64: payload.trim(),
      public_key_pem: publicKey.trim(),
      ...(Number.isFinite(ttl) ? { ttl_seconds: ttl } : {}),
    };
  }, [method, payload, publicKey, requestID, ttlSeconds]);
  const requestKey = JSON.stringify(request);
  const exactPlan = reviewed?.key === requestKey ? reviewed.value : null;
  const steps = useMemo<CarouselStep[]>(
    () => [
      { id: "request", label: t("workloads.ephemeral.stepRequest"), description: t("workloads.ephemeral.stepRequestBody") },
      { id: "review", label: t("workloads.ephemeral.stepReview"), description: t("workloads.ephemeral.stepReviewBody") },
      { id: "result", label: t("workloads.ephemeral.stepResult"), description: t("workloads.ephemeral.stepResultBody") },
    ],
    [t],
  );

  function invalidatePlan() {
    setReviewed(null);
    setResult(null);
    setPreviewError(null);
    setIssueError(null);
    setCopied(false);
  }

  function change(setter: (value: string) => void, value: string) {
    setter(value);
    invalidatePlan();
  }

  async function preview() {
    if (!previewAction.runnable) return;
    setPreviewing(true);
    setPreviewError(null);
    setIssueError(null);
    setStep(1);
    try {
      const value = await api.previewEphemeralCredential(request);
      setReviewed({ key: requestKey, value });
    } catch (error) {
      setReviewed(null);
      setPreviewError(apiProblemMessage(error, t("workloads.ephemeral.previewFailedFallback")));
    } finally {
      setPreviewing(false);
    }
  }

  async function issue() {
    if (!exactPlan?.ready || !exactPlan.effect_free || !issueAction.runnable) return;
    setIssuing(true);
    setIssueError(null);
    try {
      const value = await api.requestEphemeralCredential(request);
      setResult(value);
      setStep(2);
      if (value.state === "issued") setPayload("");
    } catch (error) {
      setIssueError(apiProblemMessage(error, t("workloads.ephemeral.issueFailedFallback")));
    } finally {
      setIssuing(false);
    }
  }

  async function copyCertificate() {
    if (!result?.certificate_pem) return;
    try {
      await navigator.clipboard.writeText(result.certificate_pem);
      setCopied(true);
    } catch (error) {
      setIssueError(apiProblemMessage(error, t("workloads.ephemeral.copyFailedFallback")));
    }
  }

  function reset() {
    setStep(0);
    setRequestID(newRequestID());
    setMethod("");
    setPayload("");
    setPublicKey("");
    setTTLSeconds("600");
    setReviewed(null);
    setResult(null);
    setPreviewError(null);
    setIssueError(null);
    setCopied(false);
  }

  const requiredInputMissing = !request.request_id || !request.method || !request.payload_base64 || !request.public_key_pem;

  return (
    <section className="grid gap-4" aria-labelledby="ephemeral-credential-heading">
      <div>
        <h3 id="ephemeral-credential-heading" className="text-title font-semibold">
          {t("workloads.ephemeral.heading")}
        </h3>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("workloads.ephemeral.description")}</p>
      </div>
      <CapabilityActionNotice action={step === 0 ? previewAction : issueAction} />
      <StepShell
        steps={steps}
        currentIndex={step}
        progressLabel={t("workloads.ephemeral.progress")}
        onPrevious={step === 1 && !previewing && !issuing ? () => setStep(0) : undefined}
        onNext={step === 0 ? () => void preview() : undefined}
        nextDisabled={previewing || issuing || requiredInputMissing || !previewAction.runnable}
        nextLabel={t("workloads.ephemeral.previewAction")}
      >
        {step === 0 ? (
          <div className="grid gap-4 md:grid-cols-2">
            <Field label={t("workloads.ephemeral.requestID")} description={t("workloads.ephemeral.requestIDHelp")} required>
              {(control) => <Input {...control} value={requestID} onChange={(event) => change(setRequestID, event.target.value)} autoComplete="off" />}
            </Field>
            <Field label={t("workloads.ephemeral.method")} description={t("workloads.ephemeral.methodHelp")} required>
              {(control) => (
                <Input
                  {...control}
                  value={method}
                  onChange={(event) => change(setMethod, event.target.value)}
                  autoComplete="off"
                  placeholder={t("workloads.ephemeral.methodPlaceholder")}
                />
              )}
            </Field>
            <Field label={t("workloads.ephemeral.proof")} description={t("workloads.ephemeral.proofHelp")} className="md:col-span-2" required>
              {(control) => (
                <Textarea
                  {...control}
                  value={payload}
                  onChange={(event) => change(setPayload, event.target.value)}
                  className="min-h-24 font-mono text-xs"
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
            </Field>
            <Field label={t("workloads.ephemeral.publicKey")} description={t("workloads.ephemeral.publicKeyHelp")} className="md:col-span-2" required>
              {(control) => (
                <Textarea
                  {...control}
                  value={publicKey}
                  onChange={(event) => change(setPublicKey, event.target.value)}
                  className="min-h-28 font-mono text-xs"
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
            </Field>
            <Field label={t("workloads.ephemeral.ttl")} description={t("workloads.ephemeral.ttlHelp")}>
              {(control) => <Input {...control} type="number" min={1} value={ttlSeconds} onChange={(event) => change(setTTLSeconds, event.target.value)} />}
            </Field>
            <p className="self-end text-sm text-muted-foreground">{t("workloads.ephemeral.inputSafety")}</p>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="grid gap-4">
            {previewing ? <LoadingState>{t("workloads.ephemeral.previewing")}</LoadingState> : null}
            {previewError ? (
              <ErrorState title={t("workloads.ephemeral.previewFailedTitle")}>
                <p>{previewError}</p>
                <Button className="mt-3" type="button" size="sm" variant="outline" onClick={() => void preview()}>
                  <RotateCcw className="h-4 w-4" aria-hidden="true" />
                  {t("workloads.ephemeral.retryPreview")}
                </Button>
              </ErrorState>
            ) : null}
            {exactPlan ? <PlanReview plan={exactPlan} /> : null}
            {issueError ? <ErrorState title={t("workloads.ephemeral.issueFailedTitle")}>{issueError}</ErrorState> : null}
            <div className="flex justify-end">
              <Button type="button" onClick={() => void issue()} disabled={!exactPlan?.ready || !exactPlan.effect_free || issuing || !issueAction.runnable}>
                {issuing ? t("workloads.ephemeral.submitting") : t("workloads.ephemeral.submitAction")}
              </Button>
            </div>
          </div>
        ) : null}

        {step === 2 && result ? (
          <Result
            result={result}
            issuing={issuing}
            copied={copied}
            issueError={issueError}
            recoverySteps={reviewed?.value.recovery_steps ?? []}
            onCheck={() => void issue()}
            onCopy={() => void copyCertificate()}
            onReset={reset}
          />
        ) : null}
      </StepShell>
    </section>
  );
}

function PlanReview({ plan }: { plan: EphemeralCredentialPreview }) {
  const { t } = useTranslation();
  return (
    <section className="grid gap-4 rounded-panel border border-border bg-muted/25 p-comfortable" aria-label={t("workloads.ephemeral.planLabel")}>
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
        <div>
          <h4 className="font-semibold">{plan.ready ? t("workloads.ephemeral.readyTitle") : t("workloads.ephemeral.blockedTitle")}</h4>
          <p className="mt-1 text-sm text-muted-foreground">{t("workloads.ephemeral.effectFree")}</p>
        </div>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact label={t("workloads.ephemeral.trustDomain")} value={plan.trust_domain} />
        <Fact label={t("workloads.ephemeral.effectiveTTL")} value={t("workloads.ephemeral.seconds", { count: plan.effective_ttl_seconds })} />
        <Fact label={t("workloads.ephemeral.approvals")} value={String(plan.required_approvals)} />
        <Fact label={t("workloads.ephemeral.approvalWindow")} value={t("workloads.ephemeral.seconds", { count: plan.approval_ttl_seconds })} />
      </dl>
      {plan.ttl_defaulted || plan.ttl_clamped ? (
        <p className="border-s-2 border-status-warning ps-3 text-sm text-muted-foreground">
          {plan.ttl_defaulted
            ? t("workloads.ephemeral.ttlDefaulted", { count: plan.effective_ttl_seconds })
            : t("workloads.ephemeral.ttlClamped", { count: plan.effective_ttl_seconds })}
        </p>
      ) : null}
      <dl className="grid gap-3 sm:grid-cols-2">
        <Fact label={t("workloads.ephemeral.proofDigest")} value={plan.payload_sha256} mono />
        <Fact label={t("workloads.ephemeral.keyDigest")} value={plan.public_key_sha256} mono />
      </dl>
      {plan.supported_methods.length > 0 ? <PlanList title={t("workloads.ephemeral.supportedMethods")} items={plan.supported_methods} /> : null}
      {plan.blockers.length > 0 ? <PlanList title={t("workloads.ephemeral.blockers")} items={plan.blockers} warning /> : null}
      <PlanList title={t("workloads.ephemeral.steps")} items={plan.steps} numbered />
      <div className="grid gap-3 lg:grid-cols-2">
        <PlanList title={t("workloads.ephemeral.submissionEffects")} items={[...plan.submission_writes, ...plan.submission_external_effects]} />
        <PlanList title={t("workloads.ephemeral.issuanceEffects")} items={[...plan.issuance_writes, ...plan.issuance_signer_calls]} />
      </div>
      <PlanList title={t("workloads.ephemeral.dataHandling")} items={plan.data_handling} />
    </section>
  );
}

function Result({
  result,
  issuing,
  copied,
  issueError,
  recoverySteps,
  onCheck,
  onCopy,
  onReset,
}: {
  result: EphemeralCredential;
  issuing: boolean;
  copied: boolean;
  issueError: string | null;
  recoverySteps: string[];
  onCheck: () => void;
  onCopy: () => void;
  onReset: () => void;
}) {
  const { t } = useTranslation();
  const pending = result.state === "awaiting_approval";
  return (
    <div className="grid gap-4" aria-live="polite">
      <section
        className={`rounded-panel border p-comfortable ${pending ? "border-status-warning/35 bg-status-warning/5" : "border-status-success/35 bg-status-success/5"}`}
      >
        <div className="flex items-start gap-3">
          {pending ? (
            <Clock3 className="mt-0.5 h-5 w-5 text-status-warning" aria-hidden="true" />
          ) : (
            <CheckCircle2 className="mt-0.5 h-5 w-5 text-status-success" aria-hidden="true" />
          )}
          <div>
            <h4 className="font-semibold">{pending ? t("workloads.ephemeral.pendingTitle") : t("workloads.ephemeral.issuedTitle")}</h4>
            <p className="mt-1 text-sm text-muted-foreground">{pending ? t("workloads.ephemeral.pendingBody") : t("workloads.ephemeral.issuedBody")}</p>
          </div>
        </div>
        <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label={t("workloads.ephemeral.approvalRequest")} value={result.approval_request_id} mono />
          <Fact label={t("workloads.ephemeral.intentDigest")} value={result.intent_digest} mono />
          <Fact label={t("workloads.ephemeral.approvalCount")} value={`${result.approvals}/${result.required_approvals}`} />
          <Fact
            label={pending ? t("workloads.ephemeral.approvalExpires") : t("workloads.ephemeral.credentialExpires")}
            value={pending ? result.expires_at : (result.not_after ?? "-")}
          />
        </dl>
      </section>
      {issueError ? <ErrorState title={t("workloads.ephemeral.issueFailedTitle")}>{issueError}</ErrorState> : null}
      {pending ? (
        <div className="flex flex-wrap justify-end gap-2">
          <Link to="/approvals" className={buttonVariants({ variant: "outline" })}>
            {t("workloads.ephemeral.openApprovals")}
          </Link>
          <Button type="button" onClick={onCheck} disabled={issuing}>
            {issuing ? t("workloads.ephemeral.checking") : t("workloads.ephemeral.checkAction")}
          </Button>
        </div>
      ) : (
        <div className="grid gap-3">
          {result.certificate_pem ? (
            <details className="rounded-panel border border-border p-3">
              <summary className="cursor-pointer font-medium">{t("workloads.ephemeral.certificateDisclosure")}</summary>
              <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-control bg-muted p-3 font-mono text-xs">
                {result.certificate_pem}
              </pre>
              <Button className="mt-3" type="button" size="sm" variant="outline" onClick={onCopy}>
                <Clipboard className="h-4 w-4" aria-hidden="true" />
                {copied ? t("workloads.ephemeral.copied") : t("workloads.ephemeral.copyCertificate")}
              </Button>
            </details>
          ) : null}
          <p className="text-sm text-muted-foreground">{t("workloads.ephemeral.noPrivateKey")}</p>
          <div className="flex justify-end">
            <Button type="button" variant="outline" onClick={onReset}>
              {t("workloads.ephemeral.startAnother")}
            </Button>
          </div>
        </div>
      )}
      {recoverySteps.length > 0 ? <PlanList title={t("workloads.ephemeral.recovery")} items={recoverySteps} /> : null}
    </div>
  );
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className={`mt-1 break-all text-sm ${mono ? "font-mono text-xs" : "font-medium"}`}>{value || "-"}</dd>
    </div>
  );
}

function PlanList({ title, items, numbered = false, warning = false }: { title: string; items: string[]; numbered?: boolean; warning?: boolean }) {
  const Tag = numbered ? "ol" : "ul";
  return (
    <section className={warning ? "rounded-control border border-status-warning/40 bg-status-warning/10 p-3" : "rounded-control border border-border p-3"}>
      <h5 className="text-sm font-semibold">{title}</h5>
      <Tag className={`mt-2 grid gap-1 text-sm text-muted-foreground ${numbered ? "list-decimal ps-5" : "list-disc ps-5"}`}>
        {items.map((item, index) => (
          <li key={`${index}-${item}`}>{item}</li>
        ))}
      </Tag>
    </section>
  );
}
