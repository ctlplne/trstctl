import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Cable, CheckCircle2, FileKey2, KeyRound, Loader2, Network, RotateCcw, Server, ShieldCheck } from "lucide-react";
import { ApiError, api, type Agent, type EnrollmentToken, type Identity, type Owner, type ProtocolProfileStatus } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { forgetIssuedIdentity, markOnboardingComplete, recallIssuedIdentity, rememberIssuedIdentity, resetOnboarding } from "@/lib/onboardingState";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { useCapabilityExecution } from "@/lib/capabilities";
import { buildAgentInstallPlan } from "@/lib/agentInstall";

type WizardStepID = "issuer" | "protocols" | "certificate" | "integrations" | "agent" | "complete";

function optionalCatalogIsUnavailable(reason: unknown): boolean {
  return reason instanceof ApiError && [404, 501, 503].includes(reason.status);
}

function optionalCatalog<T>(result: PromiseSettledResult<T>): T | undefined {
  if (result.status === "fulfilled") return result.value;
  if (optionalCatalogIsUnavailable(result.reason)) return undefined;
  throw result.reason;
}

function onboardingSteps(t: ReturnType<typeof useTranslation>["t"]): CarouselStep[] {
  return [
    {
      id: "issuer",
      label: t("wizard.issuer.stepLabel"),
      description: t("wizard.issuer.stepDescription"),
    },
    { id: "protocols", label: t("wizard.protocols.stepLabel"), description: t("wizard.protocols.stepDescription") },
    {
      id: "certificate",
      label: translateNow("source.issue.certificate.ff84c7ec37"),
      description: translateNow("source.create.the.first.workload.identity.and.iss.e199fc813f"),
    },
    {
      id: "integrations",
      label: t("wizard.integrations.stepLabel"),
      description: t("wizard.integrations.stepDescription"),
    },
    {
      id: "agent",
      label: t("wizard.agent.stepLabel"),
      description: t("wizard.agent.stepDescription"),
    },
    {
      id: "complete",
      label: translateNow("source.complete.143b270a32"),
      description: translateNow("source.latch.this.first.run.guide.and.jump.into.d.708bd1e5a1"),
    },
  ];
}

/** Wizard is the first-run flow (F12): a fresh install proves signer health,
 * activates the explicit eval enrollment profile when configured, issues its
 * first certificate, optionally proves integrations or enrolls an agent, then latches a browser-local completion
 * flag (see lib/onboardingState) so the dashboard stops prompting setup on later
 * visits. "Reopen setup guide" clears the flag. */
export function Wizard({ pollMs = 4000 }: { pollMs?: number }) {
  const { t } = useTranslation();
  const steps = onboardingSteps(t);
  const [stepIndex, setStepIndex] = useState(0);
  const [issuerReady, setIssuerReady] = useState(false);
  const [issuerName, setIssuerName] = useState<string | null>(null);
  const [issuerProof, setIssuerProof] = useState<string | null>(null);
  const [protocolSummary, setProtocolSummary] = useState<string | null>(null);
  const [certificate, setCertificate] = useState<Identity | null>(null);
  const [integrationSummary, setIntegrationSummary] = useState<string | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [agentDeferred, setAgentDeferred] = useState(false);
  const [completed, setCompleted] = useState(false);

  const currentStep = steps[stepIndex]?.id as WizardStepID;

  // Resume after a reload: if this browser already issued the first certificate,
  // re-read that identity from the server and treat the certificate step as done
  // only when the server still reports it issued or deployed. A stale or foreign
  // id is forgotten and the form is shown as before, so nothing is trusted from
  // storage alone and no second certificate is needed to continue.
  useEffect(() => {
    if (certificate) return;
    const remembered = recallIssuedIdentity();
    if (!remembered) return;
    let cancelled = false;
    api
      .getIdentity(remembered)
      .then((identity) => {
        if (cancelled) return;
        if (identity && (identity.status === "issued" || identity.status === "deployed")) {
          setCertificate(identity);
          setStepIndex((current) => {
            const certificateIndex = steps.findIndex((step) => step.id === "certificate");
            return current < certificateIndex ? certificateIndex : current;
          });
        } else {
          forgetIssuedIdentity();
        }
      })
      .catch(() => {
        if (!cancelled) forgetIssuedIdentity();
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const nextEnabled =
    (currentStep === "issuer" && issuerReady) ||
    (currentStep === "protocols" && Boolean(protocolSummary)) ||
    (currentStep === "certificate" && Boolean(certificate)) ||
    (currentStep === "integrations" && Boolean(integrationSummary)) ||
    (currentStep === "agent" && (Boolean(agent) || agentDeferred));

  function resetWizard() {
    setStepIndex(0);
    setIssuerReady(false);
    setIssuerName(null);
    setIssuerProof(null);
    setProtocolSummary(null);
    setCertificate(null);
    setIntegrationSummary(null);
    setAgent(null);
    setAgentDeferred(false);
    setCompleted(false);
    forgetIssuedIdentity();
    resetOnboarding();
  }

  function markComplete() {
    setCompleted(true);
    markOnboardingComplete();
  }

  if (completed) {
    return (
      <section aria-labelledby="wizard-heading" className="mx-auto grid max-w-3xl gap-6">
        <PageHeader
          title={translateNow("source.set.up.trstctl.b56c208e41")}
          titleId="wizard-heading"
          description="First-run guide completed — trstctl will not prompt setup again on this browser."
        />
        <section className="ui-panel grid gap-4 p-comfortable" aria-labelledby="setup-complete-heading">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-1 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
            <div>
              <h2 id="setup-complete-heading" className="text-title font-semibold">
                {translateNow("source.setup.complete.aadaf35950")}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {certificate?.name ?? translateNow("source.your.first.certificate.d48ee36f3a")} is tracked. trstctl will alert before expiry; renewal is a
                manual, one-click action today.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/certificates"
              className="inline-flex min-h-10 items-center justify-center rounded-control bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-elevation1 transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              {translateNow("source.track.and.renew.certificates.f0f36882b6")}
            </Link>
            <Button type="button" variant="outline" onClick={resetWizard}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              {translateNow("source.reopen.setup.guide.0f10355fd2")}
            </Button>
          </div>
        </section>
      </section>
    );
  }

  return (
    <section aria-labelledby="wizard-heading" className="mx-auto grid max-w-3xl gap-6">
      <PageHeader
        title={translateNow("source.set.up.trstctl.b56c208e41")}
        titleId="wizard-heading"
        description={t("wizard.header.description")}
        technicalDetails={t("wizard.header.technicalDetails")}
      />

      <StepShell
        steps={steps}
        currentIndex={stepIndex}
        onPrevious={() => setStepIndex((current) => Math.max(0, current - 1))}
        onNext={currentStep === "complete" ? undefined : () => setStepIndex((current) => Math.min(steps.length - 1, current + 1))}
        nextDisabled={!nextEnabled}
        nextLabel={nextLabel(currentStep, t)}
      >
        {currentStep === "issuer" && (
          <IssuerStep
            ready={issuerReady}
            issuerName={issuerName}
            proof={issuerProof}
            onReady={(name, proof) => {
              setIssuerName(name);
              setIssuerProof(proof);
              setIssuerReady(true);
            }}
          />
        )}
        {currentStep === "protocols" && <ProtocolProfileStep onReady={setProtocolSummary} />}
        {currentStep === "certificate" && (
          <CertificateStep
            certificate={certificate}
            onIssued={(identity) => {
              setCertificate(identity);
              rememberIssuedIdentity(identity.id);
            }}
          />
        )}
        {currentStep === "integrations" && certificate && <IntegrationProofStep identity={certificate} onReady={setIntegrationSummary} />}
        {currentStep === "agent" && (
          <AgentStep
            pollMs={pollMs}
            agent={agent}
            deferred={agentDeferred}
            onAgent={(nextAgent) => {
              setAgent(nextAgent);
              setAgentDeferred(false);
            }}
            onDefer={setAgentDeferred}
          />
        )}
        {currentStep === "complete" && (
          <CompleteStep
            certificateName={certificate?.name ?? null}
            issuerName={issuerName}
            protocolSummary={protocolSummary}
            integrationSummary={integrationSummary}
            agent={agent}
            agentDeferred={agentDeferred}
            onComplete={markComplete}
          />
        )}
      </StepShell>
    </section>
  );
}

function ProtocolProfileStep({ onReady }: { onReady: (summary: string) => void }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ProtocolProfileStatus | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activating, setActivating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadStatus() {
    setLoading(true);
    setError(null);
    try {
      const next = await api.protocolProfileStatus();
      setStatus(next);
      setUnavailable(false);
      if (next.active) onReady(t("wizard.protocols.summaryActive"));
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Production deployments keep protocols config-controlled. A missing
        // eval control is expected there and must not trap first-run setup.
        setUnavailable(true);
        onReady(t("wizard.protocols.summaryOperator"));
      } else {
        setError(t("wizard.protocols.statusError", { error: String(err instanceof Error ? err.message : err) }));
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadStatus();
    // This is a one-time server-state read when the carousel mounts this step.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function activate() {
    setActivating(true);
    setError(null);
    try {
      const next = await api.activateProtocolProfile();
      if (!next.active) throw new Error(t("wizard.protocols.inactiveError"));
      setStatus(next);
      onReady(t("wizard.protocols.summaryActive"));
    } catch (err) {
      setError(t("wizard.protocols.activationError", { error: String(err instanceof Error ? err.message : err) }));
    } finally {
      setActivating(false);
    }
  }

  return (
    <section aria-labelledby="step-protocols-heading" className="grid gap-4">
      <div className="flex items-start gap-3">
        <Network className="mt-1 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 id="step-protocols-heading" className="text-title font-semibold">
            {t("wizard.protocols.heading")}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("wizard.protocols.description")}</p>
        </div>
      </div>

      {loading && (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t("wizard.protocols.loading")}
        </p>
      )}
      {status && (
        <div className="grid gap-3">
          <p className="text-sm text-muted-foreground">{t("wizard.protocols.responders", { protocols: status.protocols.join(", ") })}</p>
          {status.active ? (
            <div className="grid gap-1">
              <p className="flex items-center gap-2 text-sm font-medium text-status-success">
                <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                {t("wizard.protocols.active")}
              </p>
              <p className="text-xs text-muted-foreground">{t("wizard.protocols.readinessNote")}</p>
            </div>
          ) : (
            <Button type="button" className="justify-self-start" onClick={() => void activate()} disabled={activating}>
              {activating && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
              {t("wizard.protocols.activate")}
            </Button>
          )}
        </div>
      )}
      {unavailable && <p className="text-sm text-muted-foreground">{t("wizard.protocols.unavailable")}</p>}
      {error && (
        <div className="grid justify-items-start gap-2">
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
          <Button type="button" variant="outline" onClick={() => void loadStatus()} disabled={loading}>
            {t("wizard.protocols.retry")}
          </Button>
        </div>
      )}
    </section>
  );
}

function IssuerStep({
  issuerName,
  onReady,
  proof,
  ready,
}: {
  issuerName: string | null;
  onReady: (name: string, proof: string) => void;
  proof: string | null;
  ready: boolean;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirmIssuer() {
    setBusy(true);
    setError(null);
    try {
      const [system, issuers] = await Promise.all([api.platformSystem(), api.issuers()]);
      const signer = system.dependencies.find((dependency) => dependency.name.toLowerCase() === "signer");
      if (system.signer_mode === "none" || !signer?.ready) {
        throw new Error(t("wizard.issuer.signerUnhealthy", { error: signer?.error ?? t("wizard.issuer.signerMissing") }));
      }
      const selected = issuers.find((issuer) => issuer.internal) ?? issuers[0];
      if (selected) {
        onReady(selected.name, t("wizard.issuer.readyNamed", { name: selected.name }));
      } else {
        onReady(t("wizard.issuer.builtinName"), t("wizard.issuer.readyBuiltIn"));
      }
    } catch (err) {
      setError(t("wizard.issuer.error", { error: String(err instanceof Error ? err.message : err) }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="step-issuer-heading" className="grid gap-4">
      <div className="flex items-start gap-3">
        <Server className="mt-1 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 id="step-issuer-heading" className="text-title font-semibold">
            {t("wizard.issuer.heading")}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("wizard.issuer.description")}</p>
        </div>
      </div>
      {ready ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {proof ?? t("wizard.issuer.readyNamed", { name: issuerName ?? t("wizard.issuer.builtinName") })}
        </p>
      ) : (
        <Button type="button" className="justify-self-start" onClick={() => void confirmIssuer()} disabled={busy}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {t("wizard.issuer.check")}
        </Button>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </section>
  );
}

function CertificateStep({ certificate, onIssued }: { certificate: Identity | null; onIssued: (identity: Identity) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [applicationID, setApplicationID] = useState("");
  const [environment, setEnvironment] = useState("");
  const [alertContact, setAlertContact] = useState("");
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const [createdOwner, setCreatedOwner] = useState<Owner | null>(null);
  const [wildcardAck, setWildcardAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const serviceName = name.trim() || "first-service";
  const isWildcard = serviceName.startsWith("*.");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (!applicationID.trim() || !environment.trim() || !ownershipConfirmed) {
        throw new Error(t("wizard.certificate.ownerRequired"));
      }
      // DP2-013: an owner without an alert contact is unreachable, and every
      // wizard-issued certificate then opened as an owner gap. The contact is part
      // of naming the owner, not a later chore.
      if (!alertContact.trim() || !alertContact.includes("@")) {
        throw new Error(t("wizard.certificate.ownerAlertContactRequired"));
      }
      let owner = createdOwner;
      if (!owner) {
        owner = await api.createOwner({
          kind: "workload",
          name: serviceName,
          service: serviceName,
          application_id: applicationID.trim(),
          environment: environment.trim(),
          email: alertContact.trim(),
        });
        setCreatedOwner(owner);
      }
      if (!owner.ownership_complete) {
        throw new Error(t("wizard.certificate.ownerNotReady"));
      }
      if (!owner.ownership_current) {
        owner = await api.attestOwner(owner.id);
        setCreatedOwner(owner);
      }
      if (!owner.ownership_complete || !owner.ownership_current) {
        throw new Error(t("wizard.certificate.ownerNotReady"));
      }
      const issued = await api.issueCertificate({
        name: serviceName,
        ownerId: owner.id,
        ...(isWildcard ? { wildcardBlastRadiusAcknowledged: wildcardAck } : {}),
      });
      onIssued(issued);
    } catch (err) {
      setError(`Could not issue the certificate: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="step-cert-heading" className="grid gap-4">
      <div className="flex items-start gap-3">
        <FileKey2 className="mt-1 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 id="step-cert-heading" className="text-title font-semibold">
            {translateNow("source.issue.your.first.certificate.8fbb374ce0")}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Name the service this certificate belongs to. This action uses an operator credential with certificate issuance authority; setup and agent tokens
            cannot issue certificates.
          </p>
        </div>
      </div>
      <label htmlFor="svc-name" className="grid gap-1 text-sm font-medium">
        {translateNow("source.service.name.1bb8870cc0")}
        <input
          id="svc-name"
          value={name}
          onChange={(event) => {
            setName(event.target.value);
            if (!event.target.value.trim().startsWith("*.")) setWildcardAck(false);
          }}
          className="w-full rounded-control border border-border bg-background px-3 py-2 text-body"
          placeholder={translateNow("source.payments.api.682a1c47a1")}
        />
      </label>
      <fieldset className="grid gap-3 rounded-control border border-border bg-muted/20 p-3">
        <legend className="px-1 text-sm font-semibold">{t("wizard.certificate.ownerHeading")}</legend>
        <p className="text-sm text-muted-foreground">{t("wizard.certificate.ownerHelp")}</p>
        <label htmlFor="wizard-owner-application-id" className="grid gap-1 text-sm font-medium">
          {t("owners.readiness.applicationID")}
          <input
            id="wizard-owner-application-id"
            value={applicationID}
            onChange={(event) => setApplicationID(event.target.value)}
            className="w-full rounded-control border border-border bg-background px-3 py-2 text-body"
            placeholder={t("owners.readiness.applicationPlaceholder")}
          />
        </label>
        <label htmlFor="wizard-owner-environment" className="grid gap-1 text-sm font-medium">
          {t("owners.readiness.environment")}
          <input
            id="wizard-owner-environment"
            value={environment}
            onChange={(event) => setEnvironment(event.target.value)}
            className="w-full rounded-control border border-border bg-background px-3 py-2 text-body"
            placeholder={t("owners.readiness.environmentPlaceholder")}
          />
        </label>
        <label htmlFor="wizard-owner-alert-contact" className="grid gap-1 text-sm font-medium">
          {t("wizard.certificate.ownerAlertContact")}
          <input
            id="wizard-owner-alert-contact"
            type="email"
            className="ui-input"
            value={alertContact}
            onChange={(event) => setAlertContact(event.target.value)}
            placeholder={t("wizard.certificate.ownerAlertContactPlaceholder")}
            required
          />
          <span className="text-xs font-normal text-muted-foreground">{t("wizard.certificate.ownerAlertContactHelp")}</span>
        </label>
        <label className="flex items-start gap-2 text-sm font-medium" htmlFor="wizard-owner-confirm">
          <input
            id="wizard-owner-confirm"
            type="checkbox"
            aria-label={t("wizard.certificate.ownerConfirm")}
            checked={ownershipConfirmed}
            onChange={(event) => setOwnershipConfirmed(event.target.checked)}
            className="mt-1 h-4 w-4 rounded border-border"
          />
          <span>
            {t("wizard.certificate.ownerConfirm")}
            <span className="block text-xs font-normal text-muted-foreground">{t("wizard.certificate.ownerConfirmHelp")}</span>
          </span>
        </label>
      </fieldset>
      {isWildcard && (
        <label className="flex items-start gap-2 text-sm font-medium" htmlFor="wizard-wildcard-ack">
          <input
            id="wizard-wildcard-ack"
            type="checkbox"
            checked={wildcardAck}
            onChange={(event) => setWildcardAck(event.target.checked)}
            className="mt-1 h-4 w-4 rounded border-border"
          />
          <span>
            {translateNow("source.acknowledge.wildcard.blast.radius.868520eb71")}
            <span className="block text-xs font-normal text-muted-foreground">DNS-01 validation is required; renewal uses the lifecycle scheduler.</span>
          </span>
        </label>
      )}
      {certificate ? (
        <div className="flex flex-wrap items-center gap-3">
          <p className="flex items-center gap-2 text-sm font-medium text-status-success">
            <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
            {certificate.name} {translateNow("source.was.issued.fe1574675b")}
          </p>
          <Link to="/certificates" className="text-sm font-medium text-brand-accent underline underline-offset-2 hover:text-foreground">
            {t("wizard.certificate.openInventory")}
          </Link>
        </div>
      ) : (
        <Button
          type="submit"
          className="justify-self-start"
          disabled={busy || !applicationID.trim() || !environment.trim() || !ownershipConfirmed || (isWildcard && !wildcardAck)}
        >
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {translateNow("source.issue.certificate.ff84c7ec37")}
        </Button>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}

function IntegrationProofStep({ identity, onReady }: { identity: Identity; onReady: (summary: string) => void }) {
  const { t } = useTranslation();
  const externalCAList = useCapabilityExecution("F4", "listExternalCAs");
  const externalCAIssue = useCapabilityExecution("F4", "issueExternalCA");
  const [connectorKinds, setConnectorKinds] = useState<Array<{ kind: string; name: string }>>([]);
  const [externalCAs, setExternalCAs] = useState<Array<{ id: string; name: string }>>([]);
  const [connectorKind, setConnectorKind] = useState("nginx");
  const [targetName, setTargetName] = useState("first-nginx");
  const [targetConfig, setTargetConfig] = useState('{"base_url":"https://nginx.example"}');
  const [externalCAID, setExternalCAID] = useState("");
  const [csrPEM, setCSRPEM] = useState("");
  const [dnsNames, setDNSNames] = useState("");
  const [leaseProvider, setLeaseProvider] = useState("postgres");
  const [leaseRole, setLeaseRole] = useState("readonly");
  const [connectorStatus, setConnectorStatus] = useState<string | null>(null);
  const [externalCAStatus, setExternalCAStatus] = useState<string | null>(null);
  const [leaseStatus, setLeaseStatus] = useState<string | null>(null);
  const [loadingCatalogs, setLoadingCatalogs] = useState(true);
  const [catalogFailed, setCatalogFailed] = useState(false);
  const [catalogAttempt, setCatalogAttempt] = useState(0);
  const [busy, setBusy] = useState<"connector" | "external-ca" | "lease" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (externalCAList.checking) return;
    let active = true;
    setLoadingCatalogs(true);
    setCatalogFailed(false);
    setConnectorKinds([]);
    setExternalCAs([]);
    const externalCARead = externalCAList.runnable ? api.externalCAs() : Promise.resolve([]);
    void Promise.allSettled([api.connectorCatalog(), externalCARead])
      .then(([catalogResult, caResult]) => {
        if (!active) return;
        try {
          const kinds = (optionalCatalog(catalogResult)?.items ?? []).map(({ kind, name }) => ({ kind, name }));
          const availableCAs = (optionalCatalog(caResult) ?? []).map(({ id, name }) => ({ id, name }));
          setConnectorKinds(kinds);
          if (kinds.length > 0) {
            setConnectorKind((current) => {
              const next = kinds.some((item) => item.kind === current) ? current : kinds[0].kind;
              setTargetName(`first-${next}`);
              return next;
            });
          }
          setExternalCAs(availableCAs);
          setExternalCAID(availableCAs[0]?.id ?? "");
        } catch {
          setExternalCAID("");
          setCatalogFailed(true);
        }
      })
      .finally(() => {
        if (active) setLoadingCatalogs(false);
      });
    return () => {
      active = false;
    };
    // Catalog discovery is one served read when this optional carousel step mounts.
  }, [catalogAttempt, externalCAList.checking, externalCAList.runnable]);

  useEffect(() => {
    if (connectorStatus && externalCAStatus && leaseStatus) {
      onReady("Connector deployment, upstream-CA issuance, and dynamic-secret lease proven");
    }
  }, [connectorStatus, externalCAStatus, leaseStatus, onReady]);

  async function deployConnector(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("connector");
    setError(null);
    try {
      const parsed = JSON.parse(targetConfig) as unknown;
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("target config must be a JSON object");
      const target = await api.createConnectorTarget({ name: targetName.trim(), connector: connectorKind, config: parsed as Record<string, unknown> });
      await api.deployConnectorTarget(target.id, { identity_id: identity.id, reason: "first-run connector verification" });
      setConnectorStatus(`${connectorKind} target ${target.name} accepted the deployment`);
    } catch (err) {
      setError(`Connector deployment failed: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(null);
    }
  }

  async function issueExternalCA(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (!externalCAIssue.runnable) {
      setError(
        `External-CA issuance is unavailable: ${
          externalCAIssue.unavailable?.detail ??
          (externalCAIssue.state === "denied" ? translateNow("capabilities.reason.permissionBlocked") : translateNow("capabilities.reason.notAttached"))
        }`,
      );
      return;
    }
    setBusy("external-ca");
    try {
      const issued = await api.issueExternalCA(externalCAID, {
        csr_pem: csrPEM,
        dns_names: dnsNames
          .split(",")
          .map((name) => name.trim())
          .filter(Boolean),
        ttl_seconds: 900,
      });
      setExternalCAStatus(`${issued.issuer} issued serial ${issued.serial}`);
    } catch (err) {
      setError(`External-CA issuance failed: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(null);
    }
  }

  async function issueLease(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("lease");
    setError(null);
    try {
      const lease = await api.issueDynamicLease({ provider: leaseProvider.trim(), role: leaseRole.trim(), ttl_seconds: 900 });
      // Deliberately retain only metadata. The one-time credential returned by
      // the API is neither rendered nor copied into component state.
      setLeaseStatus(`${lease.provider}/${lease.role} lease ${lease.id} is ${lease.state}`);
    } catch (err) {
      setError(`Dynamic-secret lease failed: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(null);
    }
  }

  const noConfiguredCatalogs = !loadingCatalogs && !catalogFailed && connectorKinds.length === 0 && externalCAs.length === 0;

  return (
    <section aria-labelledby="step-integrations-heading" className="grid gap-5">
      <div className="flex items-start gap-3">
        <Cable className="mt-1 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 id="step-integrations-heading" className="text-title font-semibold">
            {t("wizard.integrations.heading")}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("wizard.integrations.description")}</p>
        </div>
      </div>

      {loadingCatalogs && (
        <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> {t("wizard.integrations.loading")}
        </p>
      )}

      {noConfiguredCatalogs ? (
        <div role="status" className="rounded-control border border-border bg-muted/30 p-4 text-sm">
          <p>{t("wizard.integrations.noneConfigured")}</p>
        </div>
      ) : null}

      {catalogFailed ? (
        <div role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          <p className="font-medium">{t("wizard.integrations.catalogError")}</p>
          <Button type="button" variant="outline" className="mt-3" onClick={() => setCatalogAttempt((current) => current + 1)}>
            {t("admin.system.tryAgain")}
          </Button>
        </div>
      ) : null}

      {connectorKinds.length > 0 ? (
        <form onSubmit={deployConnector} className="grid gap-3 rounded-control border border-border p-4" aria-labelledby="connector-proof-heading">
          <h4 id="connector-proof-heading" className="font-semibold">
            {t("wizard.integrations.connector.heading")}
          </h4>
          <div className="grid gap-3 sm:grid-cols-2">
            <label htmlFor="wizard-connector-kind" className="grid gap-1 text-sm font-medium">
              {translateNow("source.connector.8f0d706fff")}
              <select
                id="wizard-connector-kind"
                value={connectorKind}
                onChange={(event) => {
                  setConnectorKind(event.target.value);
                  setTargetName(`first-${event.target.value}`);
                }}
                className="rounded-control border border-border bg-background px-3 py-2"
              >
                {connectorKinds.length === 0 && <option value={connectorKind}>{connectorKind}</option>}
                {connectorKinds.map((item) => (
                  <option key={item.kind} value={item.kind}>
                    {item.name} ({item.kind})
                  </option>
                ))}
              </select>
            </label>
            <label htmlFor="wizard-connector-target" className="grid gap-1 text-sm font-medium">
              {t("wizard.integrations.connector.targetName")}
              <input
                id="wizard-connector-target"
                value={targetName}
                onChange={(event) => setTargetName(event.target.value)}
                className="rounded-control border border-border bg-background px-3 py-2"
              />
            </label>
          </div>
          <label htmlFor="wizard-connector-config" className="grid gap-1 text-sm font-medium">
            {t("wizard.integrations.connector.config")}
            <textarea
              id="wizard-connector-config"
              value={targetConfig}
              onChange={(event) => setTargetConfig(event.target.value)}
              rows={3}
              spellCheck={false}
              className="rounded-control border border-border bg-background px-3 py-2 font-mono text-caption"
            />
          </label>
          {connectorStatus ? (
            <ProofStatus text={connectorStatus} />
          ) : (
            <Button type="submit" className="justify-self-start" disabled={busy !== null || !targetName.trim()}>
              {busy === "connector" && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}{" "}
              {translateNow("source.deploy.through.connector.47966b95ca")}
            </Button>
          )}
        </form>
      ) : null}

      {externalCAs.length > 0 ? (
        <form onSubmit={issueExternalCA} className="grid gap-3 rounded-control border border-border p-4" aria-labelledby="external-ca-proof-heading">
          <h4 id="external-ca-proof-heading" className="font-semibold">
            {t("wizard.integrations.externalCA.heading")}
          </h4>
          <label htmlFor="wizard-external-ca" className="grid gap-1 text-sm font-medium">
            {t("wizard.integrations.externalCA.label")}
            <select
              id="wizard-external-ca"
              value={externalCAID}
              onChange={(event) => setExternalCAID(event.target.value)}
              className="rounded-control border border-border bg-background px-3 py-2"
            >
              {externalCAs.length === 0 && <option value="">{t("wizard.integrations.externalCA.none")}</option>}
              {externalCAs.map((ca) => (
                <option key={ca.id} value={ca.id}>
                  {ca.name}
                </option>
              ))}
            </select>
          </label>
          <label htmlFor="wizard-external-ca-csr" className="grid gap-1 text-sm font-medium">
            {t("wizard.integrations.externalCA.csr")}
            <textarea
              id="wizard-external-ca-csr"
              value={csrPEM}
              onChange={(event) => setCSRPEM(event.target.value)}
              rows={4}
              spellCheck={false}
              placeholder={translateNow("source.begin.certificate.request.929bb0afef")}
              className="rounded-control border border-border bg-background px-3 py-2 font-mono text-caption"
            />
          </label>
          <label htmlFor="wizard-external-ca-dns" className="grid gap-1 text-sm font-medium">
            {t("wizard.integrations.externalCA.dns")}
            <input
              id="wizard-external-ca-dns"
              value={dnsNames}
              onChange={(event) => setDNSNames(event.target.value)}
              placeholder={t("wizard.integrations.externalCA.dnsPlaceholder")}
              className="rounded-control border border-border bg-background px-3 py-2"
            />
          </label>
          {externalCAStatus ? (
            <ProofStatus text={externalCAStatus} />
          ) : (
            <Button type="submit" className="justify-self-start" disabled={busy !== null || !externalCAID || !csrPEM.trim()}>
              {busy === "external-ca" && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}{" "}
              {translateNow("source.issue.through.external.ca.671d1a629f")}
            </Button>
          )}
        </form>
      ) : null}

      <details className="rounded-control border border-border bg-card">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium">{t("wizard.integrations.leaseDisclosure")}</summary>
        <form onSubmit={issueLease} className="grid gap-3 border-t border-border p-4" aria-labelledby="lease-proof-heading">
          <div className="flex items-start gap-2">
            <KeyRound className="mt-0.5 h-4 w-4 text-brand-accent" aria-hidden="true" />
            <h4 id="lease-proof-heading" className="font-semibold">
              {t("wizard.integrations.lease.heading")}
            </h4>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label htmlFor="wizard-lease-provider" className="grid gap-1 text-sm font-medium">
              {t("wizard.integrations.lease.provider")}
              <input
                id="wizard-lease-provider"
                value={leaseProvider}
                onChange={(event) => setLeaseProvider(event.target.value)}
                className="rounded-control border border-border bg-background px-3 py-2"
              />
            </label>
            <label htmlFor="wizard-lease-role" className="grid gap-1 text-sm font-medium">
              {t("wizard.integrations.lease.role")}
              <input
                id="wizard-lease-role"
                value={leaseRole}
                onChange={(event) => setLeaseRole(event.target.value)}
                className="rounded-control border border-border bg-background px-3 py-2"
              />
            </label>
          </div>
          {leaseStatus ? (
            <ProofStatus text={leaseStatus} />
          ) : (
            <Button type="submit" className="justify-self-start" disabled={busy !== null || !leaseProvider.trim() || !leaseRole.trim()}>
              {busy === "lease" && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />} {translateNow("source.issue.dynamic.lease.7f0d0fe084")}
            </Button>
          )}
        </form>
      </details>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button
        type="button"
        variant="ghost"
        className="justify-self-start"
        onClick={() => onReady("Integration proof skipped; configure systems and reopen setup")}
      >
        {t("wizard.integrations.skip")}
      </Button>
    </section>
  );
}

function ProofStatus({ text }: { text: string }) {
  return (
    <p className="flex items-center gap-2 text-sm font-medium text-status-success">
      <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
      {text}
    </p>
  );
}

function AgentStep({
  agent,
  deferred,
  onAgent,
  onDefer,
  pollMs,
}: {
  agent: Agent | null;
  deferred: boolean;
  onAgent: (agent: Agent) => void;
  onDefer: (deferred: boolean) => void;
  pollMs: number;
}) {
  const { t } = useTranslation();
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const [agentIdentity, setAgentIdentity] = useState("");
  const [tokenIdentity, setTokenIdentity] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [minting, setMinting] = useState(false);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (agent) return undefined;
    const id = window.setInterval(() => {
      void check();
    }, pollMs);
    return () => window.clearInterval(id);
    // check is intentionally not a dependency; each tick uses the latest setter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent, pollMs]);

  async function mintToken() {
    setError(null);
    setMinting(true);
    try {
      const allowedIdentity = agentIdentity.trim();
      const result = await api.createEnrollmentToken(allowedIdentity ? { allowed_identity: allowedIdentity } : undefined);
      setToken(result);
      setTokenIdentity(allowedIdentity);
      onDefer(false);
    } catch (err) {
      setError(`Could not mint an enrollment token: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setMinting(false);
    }
  }

  async function check() {
    setChecking(true);
    try {
      const list = await api.agents();
      const first = list[0];
      if (first) onAgent(first);
    } catch {
      // Transient network errors are retried by the next poll or manual check.
    } finally {
      setChecking(false);
    }
  }

  const origin = typeof window !== "undefined" ? window.location.origin : "https://trstctl.example";
  const nameArg = (token ? tokenIdentity : agentIdentity).trim() || "edge-agent-1";
  const installPlan = buildAgentInstallPlan({
    origin,
    agentName: nameArg,
    roles: token?.roles,
    agentServer: token?.agent_server,
    agentServerName: token?.agent_server_name,
    multiline: true,
  });

  return (
    <section aria-labelledby="step-agent-heading" className="grid gap-4">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-1 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 id="step-agent-heading" className="text-title font-semibold">
            {t("wizard.agent.heading")}
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("wizard.agent.description")}</p>
        </div>
      </div>
      <div className="grid gap-2 sm:grid-cols-[minmax(12rem,18rem)_auto] sm:items-end">
        <label className="grid gap-1 text-sm font-medium">
          {translateNow("source.agent.identity.698c87920a")}
          <input
            className="rounded-control border border-border bg-background px-3 py-2 text-sm font-normal"
            placeholder={translateNow("source.node.a.66570ff05a")}
            value={agentIdentity}
            onChange={(event) => setAgentIdentity(event.target.value)}
            disabled={minting}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <Button type="button" className="justify-self-start" onClick={() => void mintToken()} disabled={minting}>
          {minting && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {translateNow("source.mint.enrollment.token.b50d28fa1d")}
        </Button>
      </div>
      {token && (
        <div>
          <p className="text-caption font-medium text-muted-foreground">{translateNow("source.bootstrap.token.2996dc8b78")}</p>
          <code className="mt-1 block break-all rounded-control bg-muted px-3 py-2 text-caption">{token.token}</code>
        </div>
      )}
      <p className="text-caption text-muted-foreground">{t("wizard.agent.commandIntro")}</p>
      {!token ? (
        <p className="rounded-control border border-border bg-muted/40 p-3 text-caption text-muted-foreground" role="status">
          {t("wizard.agent.commandPending")}
        </p>
      ) : installPlan.blockedReason ? (
        <p className="rounded-control border border-status-warning/40 bg-status-warning/10 p-3 text-caption" role="alert">
          {installPlan.blockedReason}
        </p>
      ) : (
        <pre className="overflow-x-auto rounded-control border border-border bg-muted p-3 text-caption" aria-label={t("wizard.agent.commandLabel")}>
          <code>{installPlan.command}</code>
        </pre>
      )}
      {agent ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.agent.11b39c9377")} {agent.name} {translateNow("source.registered.dfd1beafbf")}
        </p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          {checking && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {translateNow("source.waiting.for.the.agent.to.register.3e78d9c8a6")}
        </p>
      )}
      <Button type="button" variant="outline" className="justify-self-start" onClick={() => void check()}>
        {translateNow("source.check.for.agent.1649b814df")}
      </Button>
      {deferred ? (
        <div className="grid justify-items-start gap-2 border-s-2 border-border ps-3 text-sm text-muted-foreground">
          <p>{t("wizard.agent.skipped")}</p>
          <Button type="button" variant="ghost" onClick={() => onDefer(false)}>
            {t("wizard.agent.resume")}
          </Button>
        </div>
      ) : (
        <Button type="button" variant="ghost" className="justify-self-start" onClick={() => onDefer(true)}>
          {t("wizard.agent.skip")}
        </Button>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </section>
  );
}

function CompleteStep({
  agent,
  agentDeferred,
  certificateName,
  integrationSummary,
  issuerName,
  protocolSummary,
  onComplete,
}: {
  agent: Agent | null;
  agentDeferred: boolean;
  certificateName: string | null;
  integrationSummary: string | null;
  issuerName: string | null;
  protocolSummary: string | null;
  onComplete: () => void;
}) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="step-complete-heading" className="grid gap-4">
      <h3 id="step-complete-heading" className="flex items-center gap-2 text-title font-semibold">
        <CheckCircle2 className="h-5 w-5 text-status-success" aria-hidden="true" />
        {translateNow("source.ready.for.certificate.operations.e99f6e538f")}
      </h3>
      <dl className="grid gap-3 sm:grid-cols-2">
        <SummaryItem label="Issuer" value={issuerName ?? "Internal CA"} />
        <SummaryItem label="Protocols" value={protocolSummary ?? "Not configured"} />
        <SummaryItem label="Certificate" value={certificateName ?? "first-service"} />
        <SummaryItem label="Integrations" value={integrationSummary ?? "Not exercised"} />
        <SummaryItem label="Agent" value={agent?.name ?? t(agentDeferred ? "wizard.agent.summaryDeferred" : "wizard.agent.summaryMissing")} />
      </dl>
      <p className="text-sm text-muted-foreground">{translateNow("source.trstctl.will.track.this.credential.and.ale.258f3fc1df")}</p>
      <Button type="button" className="justify-self-start" onClick={onComplete}>
        {translateNow("source.complete.setup.fe3da4e70b")}
      </Button>
    </section>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-control border border-border bg-muted/40 p-3">
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className="mt-1 truncate text-sm font-medium">{value}</dd>
    </div>
  );
}

function nextLabel(step: WizardStepID, t: ReturnType<typeof useTranslation>["t"]): string {
  if (step === "issuer") return t("wizard.protocols.next");
  if (step === "protocols") return "Next: issue certificate";
  if (step === "certificate") return "Next: prove integrations";
  if (step === "integrations") return t("wizard.agent.nextOptional");
  if (step === "agent") return t("wizard.agent.nextReview");
  return "Next";
}
