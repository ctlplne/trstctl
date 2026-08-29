import { useMemo, useState } from "react";
import { CheckCircle2, RotateCcw, ShieldCheck } from "lucide-react";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation, type I18nContextValue } from "@/i18n/I18nProvider";
import { api, type SSHCertificate, type SSHCertificatePreview, type SSHCertificateRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";

type ReviewedPlan = { key: string; value: SSHCertificatePreview };

function splitValues(input: string): string[] {
  return input
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function extensionMap(input: string): Record<string, string> {
  return Object.fromEntries(splitValues(input).map((name) => [name, ""]));
}

export function SSHCertificateWorkflow() {
  const { t } = useTranslation();
  const previewAction = useCapabilityExecution("F43", "previewSSHCertificate");
  const issueAction = useCapabilityExecution("F43", "issueSSHCertificate");
  const [step, setStep] = useState(0);
  const [certificateType, setCertificateType] = useState<SSHCertificateRequest["certificate_type"]>("host");
  const [publicKey, setPublicKey] = useState("");
  const [keyID, setKeyID] = useState("edge-1.internal");
  const [principals, setPrincipals] = useState("edge-1.internal");
  const [ttlSeconds, setTTLSeconds] = useState("3600");
  const [sourceAddresses, setSourceAddresses] = useState("");
  const [forceCommand, setForceCommand] = useState("");
  const [extensions, setExtensions] = useState("");
  const [reviewed, setReviewed] = useState<ReviewedPlan | null>(null);
  const [issued, setIssued] = useState<SSHCertificate | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [certificateOpen, setCertificateOpen] = useState(false);

  const request = useMemo<SSHCertificateRequest>(() => {
    const ttl = Number(ttlSeconds);
    const criticalOptions: Record<string, string> = {};
    const sources = splitValues(sourceAddresses);
    if (sources.length > 0) criticalOptions["source-address"] = sources.join(",");
    if (forceCommand.trim()) criticalOptions["force-command"] = forceCommand.trim();
    return {
      certificate_type: certificateType,
      public_key: publicKey.trim(),
      key_id: keyID.trim(),
      principals: splitValues(principals),
      ...(Number.isFinite(ttl) ? { ttl_seconds: ttl } : {}),
      critical_options: certificateType === "user" ? criticalOptions : {},
      extensions: certificateType === "user" ? extensionMap(extensions) : {},
    };
  }, [certificateType, extensions, forceCommand, keyID, principals, publicKey, sourceAddresses, ttlSeconds]);
  const requestKey = JSON.stringify(request);
  const exactPlan = reviewed?.key === requestKey ? reviewed.value : null;
  const steps = useMemo<CarouselStep[]>(
    () => [
      { id: "request", label: t("sshTrust.certificate.stepRequest"), description: t("sshTrust.certificate.stepRequestBody") },
      { id: "review", label: t("sshTrust.certificate.stepReview"), description: t("sshTrust.certificate.stepReviewBody") },
      { id: "result", label: t("sshTrust.certificate.stepResult"), description: t("sshTrust.certificate.stepResultBody") },
    ],
    [t],
  );

  function invalidate() {
    setReviewed(null);
    setIssued(null);
    setError(null);
    setCertificateOpen(false);
  }

  function change(setter: (value: string) => void, value: string) {
    setter(value);
    invalidate();
  }

  async function preview() {
    if (!previewAction.runnable) return;
    setStep(1);
    setPreviewing(true);
    setError(null);
    try {
      const value = await api.previewSSHCertificate(request);
      setReviewed({ key: requestKey, value });
    } catch (cause) {
      setReviewed(null);
      setError(apiProblemMessage(cause, t("sshTrust.certificate.previewFailed")));
    } finally {
      setPreviewing(false);
    }
  }

  async function issue() {
    if (!exactPlan?.ready || !exactPlan.effect_free || !issueAction.runnable) return;
    setIssuing(true);
    setError(null);
    try {
      const value = await api.issueSSHCertificate(request);
      setIssued(value);
      setPublicKey("");
      setStep(2);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("sshTrust.certificate.issueFailed")));
    } finally {
      setIssuing(false);
    }
  }

  function reset() {
    setStep(0);
    setCertificateType("host");
    setPublicKey("");
    setKeyID("edge-1.internal");
    setPrincipals("edge-1.internal");
    setTTLSeconds("3600");
    setSourceAddresses("");
    setForceCommand("");
    setExtensions("");
    setReviewed(null);
    setIssued(null);
    setError(null);
    setCertificateOpen(false);
  }

  const requiredMissing = !request.public_key || !request.key_id || request.principals.length === 0;

  return (
    <section className="grid gap-4" aria-labelledby="ssh-certificate-workflow-heading">
      <div>
        <h2 id="ssh-certificate-workflow-heading" className="text-title font-semibold">
          {t("sshTrust.certificate.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.certificate.description")}</p>
      </div>
      <CapabilityActionNotice action={step === 0 ? previewAction : issueAction} />
      <StepShell
        steps={steps}
        currentIndex={step}
        progressLabel={t("sshTrust.certificate.progress")}
        onPrevious={step === 1 && !previewing && !issuing ? () => setStep(0) : undefined}
        onNext={step === 0 ? () => void preview() : undefined}
        nextDisabled={requiredMissing || previewing || issuing || !previewAction.runnable}
        nextLabel={t("sshTrust.certificate.previewAction")}
      >
        {step === 0 ? (
          <div className="grid gap-4 md:grid-cols-2">
            <Field label={t("sshTrust.certificate.type")} description={t("sshTrust.certificate.typeHelp")} required>
              {(control) => (
                <Select
                  {...control}
                  value={certificateType}
                  onChange={(event) => {
                    setCertificateType(event.target.value as SSHCertificateRequest["certificate_type"]);
                    invalidate();
                  }}
                >
                  <option value="host">{t("sshTrust.certificate.host")}</option>
                  <option value="user">{t("sshTrust.certificate.user")}</option>
                </Select>
              )}
            </Field>
            <Field label={t("sshTrust.certificate.keyID")} description={t("sshTrust.certificate.keyIDHelp")} required>
              {(control) => <Input {...control} value={keyID} onChange={(event) => change(setKeyID, event.target.value)} autoComplete="off" />}
            </Field>
            <Field
              label={t("sshTrust.certificate.publicKey")}
              description={t("sshTrust.certificate.publicKeyHelp")}
              className="md:col-span-2"
              required
            >
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
            <Field label={t("sshTrust.certificate.principals")} description={t("sshTrust.certificate.principalsHelp")} required>
              {(control) => (
                <Textarea {...control} value={principals} onChange={(event) => change(setPrincipals, event.target.value)} className="min-h-20 font-mono text-xs" />
              )}
            </Field>
            <Field label={t("sshTrust.certificate.ttl")} description={t("sshTrust.certificate.ttlHelp")}>
              {(control) => <Input {...control} type="number" min={1} value={ttlSeconds} onChange={(event) => change(setTTLSeconds, event.target.value)} />}
            </Field>
            {certificateType === "user" ? (
              <>
                <Field label={t("sshTrust.certificate.sourceAddresses")} description={t("sshTrust.certificate.sourceAddressesHelp")}>
                  {(control) => (
                    <Textarea
                      {...control}
                      value={sourceAddresses}
                      onChange={(event) => change(setSourceAddresses, event.target.value)}
                      className="min-h-20 font-mono text-xs"
                    />
                  )}
                </Field>
                <Field label={t("sshTrust.certificate.forceCommand")} description={t("sshTrust.certificate.forceCommandHelp")}>
                  {(control) => <Input {...control} value={forceCommand} onChange={(event) => change(setForceCommand, event.target.value)} className="font-mono text-xs" />}
                </Field>
                <Field
                  label={t("sshTrust.certificate.extensions")}
                  description={t("sshTrust.certificate.extensionsHelp")}
                  className="md:col-span-2"
                >
                  {(control) => (
                    <Textarea {...control} value={extensions} onChange={(event) => change(setExtensions, event.target.value)} className="min-h-20 font-mono text-xs" />
                  )}
                </Field>
              </>
            ) : null}
            <p className="md:col-span-2 border-s-2 border-brand-accent ps-3 text-sm text-muted-foreground">{t("sshTrust.certificate.privateKeyBoundary")}</p>
          </div>
        ) : null}

        {step === 1 ? (
          <div className="grid gap-4">
            {previewing ? <LoadingState>{t("sshTrust.certificate.previewing")}</LoadingState> : null}
            {error ? (
              <ErrorState title={t("sshTrust.certificate.previewFailedTitle")}>
                <p>{error}</p>
                <Button type="button" size="sm" variant="outline" className="mt-3" onClick={() => void preview()}>
                  <RotateCcw className="h-4 w-4" aria-hidden="true" />
                  {t("sshTrust.certificate.retryPreview")}
                </Button>
              </ErrorState>
            ) : null}
            {exactPlan ? <SSHCertificatePlan plan={exactPlan} /> : null}
            <div className="flex justify-end">
              <Button type="button" disabled={!exactPlan?.ready || !exactPlan.effect_free || issuing || !issueAction.runnable} onClick={() => void issue()}>
                {issuing
                  ? t("sshTrust.certificate.issuing")
                  : t(exactPlan?.certificate_type === "user" ? "sshTrust.certificate.issueUser" : "sshTrust.certificate.issueHost")}
              </Button>
            </div>
          </div>
        ) : null}

        {step === 2 && issued ? (
          <section className="grid gap-4" aria-labelledby="ssh-certificate-issued-heading">
            <div className="flex items-start gap-3">
              <CheckCircle2 className="mt-0.5 h-5 w-5 text-status-success" aria-hidden="true" />
              <div>
                <h3 id="ssh-certificate-issued-heading" className="text-title font-semibold">
                  {t(issued.certificate_type === "user" ? "sshTrust.certificate.userIssued" : "sshTrust.certificate.hostIssued")}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("sshTrust.certificate.serial", { serial: issued.serial })}</p>
              </div>
            </div>
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Fact label={t("sshTrust.certificate.resultName")} value={issued.key_id} />
              <Fact label={t("sshTrust.certificate.resultPrincipals")} value={issued.principals.join(", ")} />
              <Fact label={t("sshTrust.certificate.resultExpiry")} value={issued.valid_before} />
              <Fact label={t("sshTrust.certificate.resultKRL")} value={String(issued.krl_version)} />
            </dl>
            <p className="border-s-2 border-status-warning ps-3 text-sm text-muted-foreground">{t("sshTrust.certificate.deliveryBoundary")}</p>
            <details className="text-sm" onToggle={(event) => setCertificateOpen(event.currentTarget.open)}>
              <summary className="cursor-pointer font-medium text-foreground">{t("sshTrust.certificate.showCertificate")}</summary>
              {certificateOpen ? <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-all rounded-control bg-muted p-3 font-mono text-xs">{issued.certificate}</pre> : null}
            </details>
            <div>
              <Button type="button" variant="outline" onClick={reset}>
                {t("sshTrust.certificate.startAnother")}
              </Button>
            </div>
          </section>
        ) : null}
      </StepShell>
    </section>
  );
}

function SSHCertificatePlan({ plan }: { plan: SSHCertificatePreview }) {
  const { t } = useTranslation();
  return (
    <section className="grid gap-4 rounded-panel border border-border bg-muted/25 p-comfortable" aria-label={t("sshTrust.certificate.planLabel")}>
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 className="text-title font-semibold">{plan.ready ? t("sshTrust.certificate.ready") : t("sshTrust.certificate.blocked")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("sshTrust.certificate.effectFree")}</p>
        </div>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact label={t("sshTrust.certificate.resultType")} value={plan.certificate_type} />
        <Fact label={t("sshTrust.certificate.resultName")} value={plan.key_id} />
        <Fact label={t("sshTrust.certificate.resultPrincipals")} value={plan.principals.join(", ")} />
        <Fact label={t("sshTrust.certificate.resultTTL")} value={durationLabel(t, plan.effective_ttl_seconds)} />
      </dl>
      {plan.ttl_defaulted ? <p className="border-s-2 border-status-warning ps-3 text-sm">{t("sshTrust.certificate.ttlDefaulted")}</p> : null}
      {plan.ttl_clamped ? (
        <p className="border-s-2 border-status-warning ps-3 text-sm">
          {t("sshTrust.certificate.ttlClamped", {
            requested: durationAdjective(t, plan.requested_ttl_seconds),
            effective: durationLabel(t, plan.effective_ttl_seconds),
          })}
        </p>
      ) : null}
      <dl className="grid gap-3 sm:grid-cols-2">
        <Fact label={t("sshTrust.certificate.subjectFingerprint")} value={plan.public_key_fingerprint} mono />
        <Fact label={t("sshTrust.certificate.authorityFingerprint")} value={plan.authority_fingerprint} mono />
      </dl>
      <div className="grid gap-3 lg:grid-cols-2">
        <PlanList title={t("sshTrust.certificate.previewEffects")} items={[...plan.preview_writes, ...plan.preview_external_effects, ...plan.preview_signer_calls]} empty={t("sshTrust.certificate.none")} />
        <PlanList title={t("sshTrust.certificate.issueEffects")} items={[...plan.issuance_writes, ...plan.issuance_external_effects, ...plan.issuance_signer_calls]} />
      </div>
      <PlanList title={t("sshTrust.certificate.recovery")} items={plan.recovery_steps} />
      <PlanList title={t("sshTrust.certificate.dataHandling")} items={plan.secret_data_handling} />
    </section>
  );
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words text-sm font-medium"}>{value}</dd>
    </div>
  );
}

function PlanList({ title, items, empty }: { title: string; items: string[]; empty?: string }) {
  return (
    <section className="border-s border-border ps-3">
      <h4 className="text-sm font-medium">{title}</h4>
      {items.length > 0 ? (
        <ul className="mt-1 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-1 text-sm text-muted-foreground">{empty}</p>
      )}
    </section>
  );
}

function durationLabel(t: I18nContextValue["t"], seconds: number): string {
  if (seconds > 0 && seconds%3600 === 0) return t("sshTrust.certificate.hours", { count: seconds / 3600 });
  if (seconds > 0 && seconds%60 === 0) return t("sshTrust.certificate.minutes", { count: seconds / 60 });
  return t("sshTrust.certificate.seconds", { count: seconds });
}

function durationAdjective(t: I18nContextValue["t"], seconds: number): string {
  if (seconds > 0 && seconds%3600 === 0) return t("sshTrust.certificate.hourAdjective", { count: seconds / 3600 });
  if (seconds > 0 && seconds%60 === 0) return t("sshTrust.certificate.minuteAdjective", { count: seconds / 60 });
  return t("sshTrust.certificate.secondAdjective", { count: seconds });
}
