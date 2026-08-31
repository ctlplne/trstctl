import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Link } from "react-router-dom";
import { useAuth } from "@/auth/AuthProvider";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { CredentialChip } from "@/components/CredentialChip";
import { WorkloadIdentityHandoff } from "@/components/WorkloadIdentityHandoff";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell } from "@/components/wizard/StepShell";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type BrokerAgentIdentity } from "@/lib/api";
import type { BrokerAgentIdentityPreview, BrokerAgentIdentityRequest } from "@/lib/api-types.gen";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";
import { invalidateAppQueryKeys } from "@/lib/query";
import { BrokerIdentityHistory } from "./BrokerIdentityHistory";
import { BrokerPlanReview } from "./BrokerPlanReview";

const defaultValues = { agent: "", method: "k8s_sat", scopes: "", ttl: "0", proof: "", publicKey: "", task: "" };
type FormValues = typeof defaultValues;
type Receipt = Pick<BrokerAgentIdentity, "certificate_id" | "subject" | "not_after" | "spiffe_id">;

/** The session key drops both the form and late async results across a tenant
 * or actor change. No proof, task body, key or request is put in a query key,
 * browser storage, URL, preview evidence, or the durable history cache. */
export function BrokerIdentityWorkflow() {
  const { user } = useAuth();
  const scope = `${user?.tenant_id ?? "workbench"}:${user?.subject ?? "workbench"}`;
  return <BrokerWorkspace key={scope} scope={scope} />;
}

function BrokerWorkspace({ scope }: { scope: string }) {
  const { t, formatDateTime } = useTranslation();
  const previewAction = useCapabilityExecution("F61", "previewBrokerAgentIdentity");
  const issueAction = useCapabilityExecution("F61", "issueBrokerAgentIdentity");
  const [opened, setOpened] = useState(false);
  const [step, setStep] = useState(0);
  const [plan, setPlan] = useState<BrokerAgentIdentityPreview | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempted, setAttempted] = useState(false);
  const [abandonOpen, setAbandonOpen] = useState(false);
  const [reviewedOutcome, setReviewedOutcome] = useState(false);
  const [copied, setCopied] = useState(false);
  const [recoveryLabel, setRecoveryLabel] = useState<string | null>(null);
  const alive = useRef(true);
  const inFlight = useRef(false);
  const exactCommand = useRef<BrokerAgentIdentityRequest | null>(null);
  const retryKey = useRef<string | null>(null);
  const certificate = useRef("");
  const abandonButton = useRef<HTMLButtonElement>(null);
  const planReady = Boolean(
    plan?.ready &&
    plan.effect_free &&
    !plan.blockers.length &&
    !plan.preview_writes.length &&
    !plan.preview_external_effects.length &&
    !plan.preview_signer_calls.length &&
    plan.capability === "agent_broker" &&
    plan.attestation_verification === "execution_only" &&
    plan.policy_evaluation === "execution_only" &&
    ["not_requested", "execution_only"].includes(plan.task_envelope_verification),
  );
  const required = t("broker.form.required");
  const base64 = z
    .string()
    .trim()
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/, t("broker.form.base64"));
  const schema = z.object({
    agent: z.string().trim().min(1, required),
    method: z.string().trim().min(1, required),
    scopes: z
      .string()
      .trim()
      .min(1, required)
      .refine((value) => value.split(",").every((part) => part.trim()), t("broker.form.scopesError")),
    ttl: z
      .string()
      .trim()
      .refine((value) => /^\d+$/.test(value) && Number.isSafeInteger(Number(value)), t("broker.form.ttlError")),
    proof: base64.refine((value) => value.length > 0, required),
    publicKey: z
      .string()
      .trim()
      .refine((value) => /^-----BEGIN PUBLIC KEY-----\s+[A-Za-z0-9+/=\r\n]+\s+-----END PUBLIC KEY-----$/.test(value), t("broker.form.publicKeyError")),
    task: base64,
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues });

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      exactCommand.current = null;
      retryKey.current = null;
      certificate.current = "";
    };
  }, []);

  function clearRequest() {
    exactCommand.current = null;
    retryKey.current = null;
    setRecoveryLabel(null);
    certificate.current = "";
    reset(defaultValues);
    setPlan(null);
    setReceipt(null);
    setError(null);
    setAttempted(false);
    setCopied(false);
    setAbandonOpen(false);
    setReviewedOutcome(false);
    setStep(0);
  }

  async function preview(values: FormValues) {
    if (inFlight.current || attempted || !previewAction.runnable) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    setPlan(null);
    setStep(1);
    const command: BrokerAgentIdentityRequest = {
      agent_id: values.agent,
      method: values.method,
      scopes: values.scopes.split(",").map((value) => value.trim()),
      ttl_seconds: Number(values.ttl),
      payload_base64: values.proof,
      public_key_pem: values.publicKey,
      ...(values.task ? { task_envelope_base64: values.task } : {}),
    };
    exactCommand.current = command;
    try {
      const result = await api.previewBrokerAgentIdentity(command);
      if (alive.current) setPlan(result);
    } catch (failure) {
      if (alive.current) setError(apiProblemMessage(failure, t("workloads.ephemeral.previewFailedFallback")));
    } finally {
      inFlight.current = false;
      if (alive.current) setBusy(false);
    }
  }

  async function issue() {
    if (inFlight.current || !planReady || !exactCommand.current || !issueAction.runnable) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    setAttempted(true);
    try {
      retryKey.current ??= globalThis.crypto.randomUUID();
      setRecoveryLabel(retryKey.current);
      const result = await api.issueBrokerAgentIdentity(exactCommand.current, retryKey.current);
      if (!alive.current) return;
      certificate.current = result.certificate_pem;
      setReceipt({ certificate_id: result.certificate_id, subject: result.subject, not_after: result.not_after, spiffe_id: result.spiffe_id });
      exactCommand.current = null;
      retryKey.current = null;
      setRecoveryLabel(null);
      reset(defaultValues);
      setPlan(null);
      setStep(2);
      invalidateAppQueryKeys([
        ["broker-history", scope],
        ["broker-detail", scope],
      ]);
    } catch (failure) {
      if (alive.current)
        setError(failure instanceof ApiError && failure.status < 500 ? apiProblemMessage(failure, t("broker.issue.failed")) : t("broker.issue.uncertain"));
    } finally {
      inFlight.current = false;
      if (alive.current) setBusy(false);
    }
  }

  async function copyCertificate() {
    try {
      await navigator.clipboard.writeText(certificate.current);
      if (alive.current) setCopied(true);
    } catch {
      if (alive.current) setError(t("workloads.attested.copyFailed"));
    }
  }

  return (
    <section id="broker" aria-labelledby="broker-heading" className="grid gap-5 border-y border-border py-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="broker-heading" className="text-title font-semibold">
            {t("source.ai.agent.nhi.broker.3c610aca90")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("broker.description")}</p>
        </div>
        {!opened ? (
          <Button type="button" disabled={!previewAction.runnable} onClick={() => setOpened(true)}>
            {t("broker.start")}
          </Button>
        ) : null}
      </div>
      {!opened ? <CapabilityActionNotice action={previewAction} /> : null}
      <BrokerIdentityHistory scope={scope} />
      {opened ? (
        <div className="grid gap-3">
          <CapabilityActionNotice action={step === 0 ? previewAction : issueAction} />
          <StepShell
            currentIndex={step}
            steps={[
              { id: "request", label: t("workloads.ephemeral.stepRequest"), description: t("broker.requestBody") },
              { id: "review", label: t("workloads.ephemeral.stepReview"), description: t("broker.reviewBody") },
              { id: "proof", label: t("broker.prove"), description: t("broker.proveBody") },
            ]}
            progressLabel={t("broker.progress")}
            onPrevious={
              step === 1 && !busy && !attempted
                ? () => {
                    setPlan(null);
                    exactCommand.current = null;
                    setStep(0);
                    setError(null);
                  }
                : undefined
            }
            onNext={step === 0 ? () => void handleSubmit(preview)() : undefined}
            nextDisabled={busy || !previewAction.runnable}
            nextLabel={t("workloads.ephemeral.previewAction")}
          >
            {step === 0 ? (
              <form onSubmit={(event) => void handleSubmit(preview)(event)} className="grid gap-4 md:grid-cols-2" aria-label={t("broker.start")}>
                <Field label={t("source.agent.id.510bce732d")} required error={errors.agent?.message}>
                  {(control) => <Input {...control} {...register("agent")} autoComplete="off" />}
                </Field>
                <Field label={t("source.broker.method.86e0708911")} required error={errors.method?.message} description={t("workloads.attested.methodHelp")}>
                  {(control) => (
                    <Select {...control} {...register("method")}>
                      <option value="k8s_sat">{t("workloads.attestation.methodKubernetesServiceAccount")}</option>
                      <option value="github_oidc">{t("workloads.attestation.methodGithubOIDC")}</option>
                      <option value="aws_iid">{t("workloads.attestation.methodAwsInstanceIdentity")}</option>
                      <option value="azure_imds">{t("workloads.attestation.methodAzureIMDS")}</option>
                      <option value="gcp_iit">{t("workloads.attestation.methodGcpInstanceIdentity")}</option>
                      <option value="tpm">{t("workloads.attestation.methodTpmQuote")}</option>
                    </Select>
                  )}
                </Field>
                <Field label={t("source.broker.scopes.60ad7540e2")} required error={errors.scopes?.message} description={t("broker.scopesHelp")}>
                  {(control) => <Input {...control} {...register("scopes")} autoComplete="off" />}
                </Field>
                <Field label={t("source.broker.ttl.seconds.7112a719ce")} error={errors.ttl?.message} description={t("workloads.ephemeral.ttlHelp")}>
                  {(control) => <Input {...control} {...register("ttl")} type="number" min={0} step={1} />}
                </Field>
                <Field
                  label={t("source.broker.proof.payload.base64.caf8633720")}
                  required
                  error={errors.proof?.message}
                  description={t("workloads.ephemeral.proofHelp")}
                  className="md:col-span-2"
                >
                  {(control) => <Textarea {...control} {...register("proof")} autoComplete="off" spellCheck={false} className="font-mono" />}
                </Field>
                <Field
                  label={t("source.broker.public.key.a2341b0f4e")}
                  required
                  error={errors.publicKey?.message}
                  description={t("workloads.ephemeral.publicKeyHelp")}
                  className="md:col-span-2"
                >
                  {(control) => <Textarea {...control} {...register("publicKey")} autoComplete="off" spellCheck={false} className="font-mono" />}
                </Field>
                <Field label={t("broker.task")} error={errors.task?.message} description={t("broker.taskHelp")} className="md:col-span-2">
                  {(control) => <Textarea {...control} {...register("task")} autoComplete="off" spellCheck={false} className="font-mono" />}
                </Field>
                <p className="text-sm text-muted-foreground md:col-span-2">{t("broker.inputSafety")}</p>
                <Link to="/workloads?workflow=attester-trust#attester-trust-source-form" className="text-sm underline">
                  {t("broker.configureTrust")}
                </Link>
              </form>
            ) : null}
            {step === 1 ? (
              <div className="grid gap-4">
                {busy ? <LoadingState>{t(attempted ? "workloads.attested.issuing" : "workloads.ephemeral.previewing")}</LoadingState> : null}
                {plan ? <BrokerPlanReview plan={plan} ready={planReady} /> : null}
                {error ? (
                  <ErrorState title={t("broker.issue.failed")}>
                    <p>{error}</p>
                    {attempted ? <p className="mt-2">{t("broker.retryHelp")}</p> : null}
                  </ErrorState>
                ) : null}
                {attempted && recoveryLabel ? (
                  <details>
                    <summary className="cursor-pointer text-sm">{t("broker.recoveryKey")}</summary>
                    <div className="mt-2">
                      <CredentialChip value={recoveryLabel} label={t("broker.recoveryKey")} />
                    </div>
                  </details>
                ) : null}
                <div className="flex flex-wrap justify-end gap-2">
                  {attempted && !busy ? (
                    <Button ref={abandonButton} type="button" variant="outline" onClick={() => setAbandonOpen(true)}>
                      {t("broker.differentRequest")}
                    </Button>
                  ) : null}
                  <Button type="button" loading={busy && attempted} disabled={busy || !planReady || !issueAction.runnable} onClick={() => void issue()}>
                    {t(attempted ? "workloads.attested.retryIssue" : "workloads.attested.issue")}
                  </Button>
                </div>
              </div>
            ) : null}
            {step === 2 && receipt ? (
              <div className="grid gap-4">
                <h3 className="font-semibold" aria-live="polite">
                  {t("broker.issued")}
                </h3>
                <p className="text-sm text-muted-foreground">{t("broker.proveBody")}</p>
                <dl className="grid min-w-0 gap-3 sm:grid-cols-2">
                  <div className="min-w-0">
                    <dt>{t("source.subject.6897128384")}</dt>
                    <dd className="break-words">{receipt.subject}</dd>
                  </div>
                  <div>
                    <dt>{t("source.expires.f6725f3af0")}</dt>
                    <dd>
                      <time dateTime={receipt.not_after} title={receipt.not_after}>
                        {formatDateTime(receipt.not_after)}
                      </time>
                    </dd>
                  </div>
                </dl>
                <CredentialChip value={receipt.certificate_id} label={t("broker.certificateID")} />
                <WorkloadIdentityHandoff spiffeID={receipt.spiffe_id} />
                {error ? <p role="alert">{error}</p> : null}
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" onClick={() => void copyCertificate()}>
                    {t(copied ? "workloads.ephemeral.copied" : "workloads.ephemeral.copyCertificate")}
                  </Button>
                  <Link
                    className={buttonVariants({ variant: "outline" })}
                    to={`/workloads?workflow=broker&broker_id=${encodeURIComponent(receipt.certificate_id)}#broker`}
                  >
                    {t("broker.openRecord")}
                  </Link>
                  <Link className={buttonVariants({ variant: "outline" })} to="/audit?feature=F61">
                    {t("workloads.attested.openAudit")}
                  </Link>
                  <Button type="button" variant="outline" onClick={clearRequest}>
                    {t("workloads.ephemeral.startAnother")}
                  </Button>
                </div>
              </div>
            ) : null}
          </StepShell>
        </div>
      ) : null}
      <Dialog
        open={abandonOpen}
        onClose={() => setAbandonOpen(false)}
        titleId="broker-abandon-title"
        descriptionId="broker-abandon-body"
        returnFocusRef={abandonButton}
        panelClassName="absolute left-1/2 top-1/2 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-panel border border-border bg-background p-comfortable shadow-elevation3"
      >
        <h2 id="broker-abandon-title" className="text-title font-semibold">
          {t("broker.differentRequest")}
        </h2>
        <p id="broker-abandon-body" className="mt-3 text-sm">
          {t("broker.abandonWarning")}
        </p>
        <Link to="/audit?feature=F61" className="mt-3 block underline">
          {t("workloads.attested.openAudit")}
        </Link>
        <label className="mt-3 flex items-start gap-2 text-sm">
          <input type="checkbox" checked={reviewedOutcome} onChange={(event) => setReviewedOutcome(event.target.checked)} />
          {t("broker.reviewedOutcome")}
        </label>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button type="button" variant="outline" onClick={() => setAbandonOpen(false)}>
            {t("source.cancel.19766ed6cc")}
          </Button>
          <Button type="button" variant="destructive" disabled={!reviewedOutcome} onClick={clearRequest}>
            {t("broker.clearRequest")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}
