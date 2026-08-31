import { useMemo, useRef, useState, type ReactNode } from "react";
import { CheckCircle2, Clipboard, RotateCcw, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { ApiError, api, type AttestedSVID, type AttestedSVIDPreview } from "@/lib/api";
import type { AttestedSVIDRequest } from "@/lib/api-types.gen";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";

const methods: Array<{ value: AttestedSVIDRequest["method"]; labelKey: MessageKey }> = [
  { value: "k8s_sat", labelKey: "workloads.attestation.methodKubernetesServiceAccount" },
  { value: "github_oidc", labelKey: "workloads.attestation.methodGithubOIDC" },
  { value: "aws_iid", labelKey: "workloads.attestation.methodAwsInstanceIdentity" },
  { value: "azure_imds", labelKey: "workloads.attestation.methodAzureIMDS" },
  { value: "gcp_iit", labelKey: "workloads.attestation.methodGcpInstanceIdentity" },
  { value: "tpm", labelKey: "workloads.attestation.methodTpmQuote" },
];

type ResultMetadata = Pick<AttestedSVID, "credential_id" | "subject" | "not_after">;

export function AttestedSVIDWorkflow({
  onIssued,
  onFailure,
}: {
  onIssued: (result: AttestedSVID) => void;
  onFailure: (method: string, message: string) => void;
}) {
  const { t, formatDateTime } = useTranslation();
  const previewAction = useCapabilityExecution("F30", "previewAttestedSVID");
  const issueAction = useCapabilityExecution("F30", "issueAttestedSVID");
  const [step, setStep] = useState(0);
  const [method, setMethod] = useState<AttestedSVIDRequest["method"]>("k8s_sat");
  const [payload, setPayload] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [ttl, setTTL] = useState("600");
  const [reviewed, setReviewed] = useState<{ key: string; plan: AttestedSVIDPreview } | null>(null);
  const [result, setResult] = useState<ResultMetadata | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const retryKey = useRef<string | null>(null);
  // Public certificate only. No proof, claims, or private key is kept in result
  // metadata or rendered in the DOM; copying the certificate is deliberate.
  const certificate = useRef("");
  const request = useMemo<AttestedSVIDRequest>(
    () => ({
      method,
      payload_base64: payload.trim(),
      public_key_pem: publicKey.trim(),
      ttl_seconds: Number(ttl),
    }),
    [method, payload, publicKey, ttl],
  );
  const requestKey = JSON.stringify(request);
  const exactPlan = reviewed?.key === requestKey ? reviewed.plan : null;
  const inputValid = Boolean(request.payload_base64 && request.public_key_pem && Number.isSafeInteger(request.ttl_seconds) && Number(ttl) >= 0);
  const steps = useMemo<CarouselStep[]>(
    () => [
      { id: "request", label: t("workloads.ephemeral.stepRequest"), description: t("workloads.ephemeral.stepRequestBody") },
      { id: "review", label: t("workloads.ephemeral.stepReview"), description: t("workloads.attested.reviewBody") },
      { id: "result", label: t("workloads.attested.resultStep"), description: t("workloads.attested.resultBody") },
    ],
    [t],
  );

  function invalidate() {
    setReviewed(null);
    setPreviewError(null);
    setIssueError(null);
    setResult(null);
    setCopied(false);
    retryKey.current = null;
    certificate.current = "";
  }

  async function preview() {
    if (!previewAction.runnable || !inputValid || previewing || issuing) return;
    setPreviewing(true);
    setPreviewError(null);
    setStep(1);
    try {
      setReviewed({ key: requestKey, plan: await api.previewAttestedSVID(request) });
    } catch (error) {
      setReviewed(null);
      setPreviewError(apiProblemMessage(error, t("workloads.ephemeral.previewFailedFallback")));
    } finally {
      setPreviewing(false);
    }
  }

  async function issue() {
    if (!exactPlan?.ready || !exactPlan.effect_free || !issueAction.runnable || issuing) return;
    setIssuing(true);
    setIssueError(null);
    try {
      retryKey.current ??= globalThis.crypto.randomUUID();
      const value = await api.issueAttestedSVID(request, retryKey.current);
      onIssued(value);
      certificate.current = value.certificate_pem;
      setResult({ credential_id: value.credential_id, subject: value.subject, not_after: value.not_after });
      setPayload("");
      setPublicKey("");
      // The exact request key contains proof bytes. Drop the reviewed request
      // after success instead of retaining it behind the result screen.
      setReviewed(null);
      retryKey.current = null;
      setStep(2);
    } catch (error) {
      const message =
        error instanceof ApiError && error.status >= 500
          ? t("workloads.attested.serverFailure")
          : apiProblemMessage(error, t("workloads.attestation.issueErrorFallback"));
      setIssueError(message);
      onFailure(request.method, message);
    } finally {
      setIssuing(false);
    }
  }

  async function copyCertificate() {
    try {
      await navigator.clipboard.writeText(certificate.current);
      setCopied(true);
    } catch (error) {
      setIssueError(apiProblemMessage(error, t("workloads.attested.copyFailed")));
    }
  }

  return (
    <section id="attested-svid-issue-form" aria-labelledby="attested-issue-heading" className="grid gap-4">
      <div>
        <h3 id="attested-issue-heading" className="text-title font-semibold">
          {t("workloads.attestation.issueHeading")}
        </h3>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("workloads.attested.description")}</p>
      </div>
      <CapabilityActionNotice action={step === 0 ? previewAction : issueAction} />
      <StepShell
        steps={steps}
        currentIndex={step}
        progressLabel={t("workloads.attested.progress")}
        onPrevious={step === 1 && !previewing && !issuing ? () => setStep(0) : undefined}
        onNext={step === 0 ? () => void preview() : undefined}
        nextDisabled={!inputValid || previewing || issuing || !previewAction.runnable}
        nextLabel={t("workloads.ephemeral.previewAction")}
      >
        {step === 0 ? (
          <div className="grid gap-4 md:grid-cols-2">
            <Field label={t("workloads.attestation.method")} description={t("workloads.attested.methodHelp")} required>
              {(control) => (
                <Select
                  {...control}
                  value={method}
                  onChange={(event) => {
                    setMethod(event.target.value as AttestedSVIDRequest["method"]);
                    invalidate();
                  }}
                >
                  {methods.map((item) => (
                    <option key={item.value} value={item.value}>
                      {t(item.labelKey)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t("workloads.attestation.svidTTL")} description={t("workloads.ephemeral.ttlHelp")}>
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  min={0}
                  step={1}
                  value={ttl}
                  onChange={(event) => {
                    setTTL(event.target.value);
                    invalidate();
                  }}
                />
              )}
            </Field>
            <Field label={t("workloads.attestation.proofPayload")} description={t("workloads.ephemeral.proofHelp")} className="md:col-span-2" required>
              {(control) => (
                <Textarea
                  {...control}
                  value={payload}
                  onChange={(event) => {
                    setPayload(event.target.value);
                    invalidate();
                  }}
                  className="min-h-24 font-mono text-xs"
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
            </Field>
            <Field label={t("workloads.attestation.publicKey")} description={t("workloads.ephemeral.publicKeyHelp")} className="md:col-span-2" required>
              {(control) => (
                <Textarea
                  {...control}
                  value={publicKey}
                  onChange={(event) => {
                    setPublicKey(event.target.value);
                    invalidate();
                  }}
                  className="min-h-28 font-mono text-xs"
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
            </Field>
            <p className="text-sm text-muted-foreground md:col-span-2">{t("workloads.ephemeral.inputSafety")}</p>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="grid gap-4">
            {previewing ? <LoadingState>{t("workloads.ephemeral.previewing")}</LoadingState> : null}
            {previewError ? (
              <ErrorState title={t("workloads.ephemeral.previewFailedTitle")}>
                <p>{previewError}</p>
                <Button className="mt-3" type="button" variant="outline" onClick={() => void preview()}>
                  <RotateCcw className="h-4 w-4" aria-hidden="true" />
                  {t("workloads.ephemeral.retryPreview")}
                </Button>
              </ErrorState>
            ) : null}
            {exactPlan ? <PlanReview plan={exactPlan} /> : null}
            {issueError ? <ErrorState title={t("workloads.attestation.issueErrorTitle")}>{issueError}</ErrorState> : null}
            <div className="flex justify-end">
              <Button type="button" onClick={() => void issue()} disabled={!exactPlan?.ready || !exactPlan.effect_free || issuing || !issueAction.runnable}>
                {issuing ? t("workloads.attested.issuing") : issueError ? t("workloads.attested.retryIssue") : t("workloads.attested.issue")}
              </Button>
            </div>
          </div>
        ) : null}

        {step === 2 && result ? (
          <div className="grid gap-4" role="status">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="mt-1 h-5 w-5 text-status-success" aria-hidden="true" />
              <div>
                <h4 className="font-semibold">{t("workloads.attested.issuedTitle")}</h4>
                <p className="mt-1 text-sm text-muted-foreground">{t("workloads.attested.issuedBody")}</p>
              </div>
            </div>
            <dl className="grid gap-3 sm:grid-cols-2">
              <Fact
                label={t("workloads.ephemeral.credentialExpires")}
                value={
                  <time dateTime={result.not_after} title={result.not_after}>
                    {formatDateTime(result.not_after)}
                  </time>
                }
              />
              <Fact label={t("workloads.attested.subject")} value={result.subject} />
            </dl>
            <p className="text-sm text-muted-foreground">{t("workloads.ephemeral.noPrivateKey")}</p>
            {issueError ? (
              <p role="alert" className="text-sm text-muted-foreground">
                {issueError}
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" onClick={() => void copyCertificate()}>
                <Clipboard className="h-4 w-4" aria-hidden="true" />
                {copied ? t("workloads.ephemeral.copied") : t("workloads.ephemeral.copyCertificate")}
              </Button>
              <Link className={buttonVariants({ variant: "outline" })} to="/certificates">
                {t("workloads.attested.openInventory")}
              </Link>
              <Link className={buttonVariants({ variant: "outline" })} to="/audit">
                {t("workloads.attested.openAudit")}
              </Link>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  invalidate();
                  setStep(0);
                }}
              >
                {t("workloads.ephemeral.startAnother")}
              </Button>
            </div>
          </div>
        ) : null}
      </StepShell>
    </section>
  );
}

function PlanReview({ plan }: { plan: AttestedSVIDPreview }) {
  const { t } = useTranslation();
  return (
    <section className="grid gap-4 rounded-panel border border-border bg-muted/25 p-comfortable" aria-label={t("workloads.attested.planLabel")}>
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
        <div>
          <h4 className="font-semibold">{plan.ready && plan.effect_free ? t("workloads.attested.ready") : t("workloads.ephemeral.blockedTitle")}</h4>
          <p className="mt-1 text-sm text-muted-foreground">{plan.effect_free ? t("workloads.ephemeral.effectFree") : t("workloads.attested.previewUnsafe")}</p>
        </div>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact label={t("workloads.ephemeral.trustDomain")} value={plan.trust_domain} />
        <Fact label={t("workloads.attestation.method")} value={plan.method} />
        <Fact label={t("workloads.ephemeral.effectiveTTL")} value={t("workloads.ephemeral.seconds", { count: plan.effective_ttl_seconds })} />
        <Fact label={t("workloads.attested.permission")} value={plan.required_permission} />
      </dl>
      <p className="text-sm text-muted-foreground">{t("workloads.attested.proofDeferred")}</p>
      {plan.ttl_defaulted || plan.ttl_clamped ? (
        <p className="border-s-2 border-status-warning ps-3 text-sm text-muted-foreground">
          {plan.ttl_defaulted
            ? t("workloads.ephemeral.ttlDefaulted", { count: plan.effective_ttl_seconds })
            : t("workloads.ephemeral.ttlClamped", { count: plan.effective_ttl_seconds })}
        </p>
      ) : null}
      {plan.blockers.length ? <List title={t("workloads.ephemeral.blockers")} items={plan.blockers} /> : null}
      <List title={t("workloads.ephemeral.steps")} items={plan.steps} />
      <List title={t("workloads.attested.effects")} items={[...plan.execution_writes, ...plan.execution_external_effects, ...plan.execution_signer_calls]} />
      <List title={t("workloads.ephemeral.recovery")} items={plan.recovery_steps} />
      <details className="rounded-panel border border-border p-3">
        <summary className="cursor-pointer text-sm font-medium">{t("workloads.attested.exactEvidence")}</summary>
        <div className="mt-3 grid gap-4">
          <dl className="grid gap-3 sm:grid-cols-2">
            <Fact label={t("workloads.ephemeral.proofDigest")} value={plan.payload_sha256} />
            <Fact label={t("workloads.ephemeral.keyDigest")} value={plan.public_key_sha256} />
          </dl>
          <List title={t("workloads.ephemeral.supportedMethods")} items={plan.supported_methods} />
          <List title={t("workloads.ephemeral.dataHandling")} items={plan.data_handling} />
        </div>
      </details>
    </section>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-words font-mono text-sm">{value}</dd>
    </div>
  );
}

function List({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <section>
      <h5 className="text-sm font-semibold">{title}</h5>
      <ul className="mt-2 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
