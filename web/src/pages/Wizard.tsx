import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Cable, CheckCircle2, FileKey2, KeyRound, Loader2, Network, RotateCcw, Server, ShieldCheck } from "lucide-react";
import { ApiError, api, type Agent, type EnrollmentToken, type Identity, type ProtocolProfileStatus } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { markOnboardingComplete, resetOnboarding } from "@/lib/onboardingState";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

type WizardStepID = "issuer" | "protocols" | "certificate" | "integrations" | "agent" | "complete";

function onboardingSteps(t: ReturnType<typeof useTranslation>["t"]): CarouselStep[] {
  return [
    { id: "issuer", label: translateNow("source.connect.issuer.abc8382bc1"), description: translateNow("source.confirm.the.signer.backed.internal.ca.or.c.b20abca15c") },
    { id: "protocols", label: t("wizard.protocols.stepLabel"), description: t("wizard.protocols.stepDescription") },
    { id: "certificate", label: translateNow("source.issue.certificate.ff84c7ec37"), description: translateNow("source.create.the.first.workload.identity.and.iss.e199fc813f") },
    {
      id: "integrations",
      label: t("wizard.integrations.stepLabel"),
      description: t("wizard.integrations.stepDescription"),
    },
    { id: "agent", label: translateNow("source.enroll.agent.8592144d44"), description: translateNow("source.mint.a.one.time.enrollment.token.and.wait.41e91b176b") },
    { id: "complete", label: translateNow("source.complete.143b270a32"), description: translateNow("source.latch.this.first.run.guide.and.jump.into.d.708bd1e5a1") },
  ];
}

/** Wizard is the first-run flow (F12): a fresh install confirms an issuer,
 * activates the explicit eval enrollment profile when configured, issues its
 * first certificate, proves configured integrations through their served routes,
 * enrolls an agent, then latches a browser-local completion
 * flag (see lib/onboardingState) so the dashboard stops prompting setup on later
 * visits. "Reopen setup guide" clears the flag. */
export function Wizard({ pollMs = 4000 }: { pollMs?: number }) {
  const { t } = useTranslation();
  const steps = onboardingSteps(t);
  const [stepIndex, setStepIndex] = useState(0);
  const [issuerReady, setIssuerReady] = useState(false);
  const [issuerName, setIssuerName] = useState<string | null>(null);
  const [protocolSummary, setProtocolSummary] = useState<string | null>(null);
  const [certificate, setCertificate] = useState<Identity | null>(null);
  const [integrationSummary, setIntegrationSummary] = useState<string | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [completed, setCompleted] = useState(false);

  const currentStep = steps[stepIndex]?.id as WizardStepID;
  const nextEnabled =
    (currentStep === "issuer" && issuerReady) ||
    (currentStep === "protocols" && Boolean(protocolSummary)) ||
    (currentStep === "certificate" && Boolean(certificate)) ||
    (currentStep === "integrations" && Boolean(integrationSummary)) ||
    (currentStep === "agent" && Boolean(agent));

  function resetWizard() {
    setStepIndex(0);
    setIssuerReady(false);
    setIssuerName(null);
    setProtocolSummary(null);
    setCertificate(null);
    setIntegrationSummary(null);
    setAgent(null);
    setCompleted(false);
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
                {translateNow("source.setup.complete.aadaf35950")}</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {certificate?.name ?? "Your first certificate"} is tracked. trstctl will alert before expiry; renewal is a manual, one-click action today.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/certificates"
              className="inline-flex min-h-10 items-center justify-center rounded-control bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-elevation1 transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              {translateNow("source.track.and.renew.certificates.f0f36882b6")}</Link>
            <Button type="button" variant="outline" onClick={resetWizard}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              {translateNow("source.reopen.setup.guide.0f10355fd2")}</Button>
          </div>
        </section>
      </section>
    );
  }

  return (
    <section aria-labelledby="wizard-heading" className="mx-auto grid max-w-3xl gap-6">
      <PageHeader title={translateNow("source.set.up.trstctl.b56c208e41")} titleId="wizard-heading" description={t("wizard.header.description")} />

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
            onReady={(name) => {
              setIssuerName(name);
              setIssuerReady(true);
            }}
          />
        )}
        {currentStep === "protocols" && <ProtocolProfileStep onReady={setProtocolSummary} />}
        {currentStep === "certificate" && <CertificateStep certificate={certificate} onIssued={setCertificate} />}
        {currentStep === "integrations" && certificate && <IntegrationProofStep identity={certificate} onReady={setIntegrationSummary} />}
        {currentStep === "agent" && <AgentStep pollMs={pollMs} agent={agent} onAgent={setAgent} />}
        {currentStep === "complete" && (
          <CompleteStep
            certificateName={certificate?.name ?? null}
            issuerName={issuerName}
            protocolSummary={protocolSummary}
            integrationSummary={integrationSummary}
            agent={agent}
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
            <p className="flex items-center gap-2 text-sm font-medium text-status-success">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              {t("wizard.protocols.active")}
            </p>
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

function IssuerStep({ issuerName, onReady, ready }: { issuerName: string | null; onReady: (name: string) => void; ready: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirmIssuer() {
    setBusy(true);
    setError(null);
    try {
      const issuers = await api.issuers();
      onReady(issuers.find((issuer) => issuer.internal)?.name ?? issuers[0]?.name ?? "Internal CA");
    } catch (err) {
      setError(`Could not confirm issuer readiness: ${String(err instanceof Error ? err.message : err)}`);
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
            {translateNow("source.connect.an.issuer.c155ecb073")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {translateNow("source.a.fresh.trstctl.server.provisions.a.signer.a1ee587e50")}</p>
        </div>
      </div>
      {ready ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {issuerName} {" "}{translateNow("source.is.ready.17f5581890")}</p>
      ) : (
        <Button type="button" className="justify-self-start" onClick={() => void confirmIssuer()} disabled={busy}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {translateNow("source.use.internal.ca.2181607010")}</Button>
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
  const [name, setName] = useState("");
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
      const issued = await api.issueCertificate({
        name: serviceName,
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
            {translateNow("source.issue.your.first.certificate.8fbb374ce0")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Name the service this certificate belongs to. This action uses an operator credential with certificate issuance authority; setup and agent tokens
            cannot issue certificates.
          </p>
        </div>
      </div>
      <label htmlFor="svc-name" className="grid gap-1 text-sm font-medium">
        {translateNow("source.service.name.1bb8870cc0")}<input
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
            {translateNow("source.acknowledge.wildcard.blast.radius.868520eb71")}<span className="block text-xs font-normal text-muted-foreground">DNS-01 validation is required; renewal uses the lifecycle scheduler.</span>
          </span>
        </label>
      )}
      {certificate ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {certificate.name} {" "}{translateNow("source.was.issued.fe1574675b")}</p>
      ) : (
        <Button type="submit" className="justify-self-start" disabled={busy || (isWildcard && !wildcardAck)}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {translateNow("source.issue.certificate.ff84c7ec37")}</Button>
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
  const [busy, setBusy] = useState<"connector" | "external-ca" | "lease" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.all([api.connectorCatalog(), api.externalCAs()])
      .then(([catalog, cas]) => {
        if (!active) return;
        const kinds = catalog.items.map(({ kind, name }) => ({ kind, name }));
        setConnectorKinds(kinds);
        if (kinds.length > 0 && !kinds.some((item) => item.kind === connectorKind)) {
          setConnectorKind(kinds[0].kind);
          setTargetName(`first-${kinds[0].kind}`);
        }
        const availableCAs = cas.map(({ id, name }) => ({ id, name }));
        setExternalCAs(availableCAs);
        setExternalCAID(availableCAs[0]?.id ?? "");
      })
      .catch((err) => {
        if (active) setError(`Could not load integration catalogs: ${String(err instanceof Error ? err.message : err)}`);
      })
      .finally(() => {
        if (active) setLoadingCatalogs(false);
      });
    return () => {
      active = false;
    };
    // Catalog discovery is one served read when this optional carousel step mounts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
    setBusy("external-ca");
    setError(null);
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

      <form onSubmit={deployConnector} className="grid gap-3 rounded-control border border-border p-4" aria-labelledby="connector-proof-heading">
        <h4 id="connector-proof-heading" className="font-semibold">
          {t("wizard.integrations.connector.heading")}
        </h4>
        <div className="grid gap-3 sm:grid-cols-2">
          <label htmlFor="wizard-connector-kind" className="grid gap-1 text-sm font-medium">
            {translateNow("source.connector.8f0d706fff")}<select
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
            {busy === "connector" && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />} {" "}{translateNow("source.deploy.through.connector.47966b95ca")}</Button>
        )}
      </form>

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
            {busy === "external-ca" && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />} {" "}{translateNow("source.issue.through.external.ca.671d1a629f")}</Button>
        )}
      </form>

      <form onSubmit={issueLease} className="grid gap-3 rounded-control border border-border p-4" aria-labelledby="lease-proof-heading">
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
            {busy === "lease" && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />} {" "}{translateNow("source.issue.dynamic.lease.7f0d0fe084")}</Button>
        )}
      </form>

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

function AgentStep({ agent, onAgent, pollMs }: { agent: Agent | null; onAgent: (agent: Agent) => void; pollMs: number }) {
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
  const enrollPath = token?.enroll_path || "/enroll/bootstrap";
  const nameArg = (token ? tokenIdentity : agentIdentity).trim();
  const command = [
    "trstctl-agent",
    `--enroll-url ${origin}${enrollPath}`,
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    "--server <control-plane-grpc:9443>",
    `--name ${nameArg ? shellArg(nameArg) : "<agent-name>"}`,
    "--ca-bundle ./trstctl-ca.pem",
  ].join(" ");

  return (
    <section aria-labelledby="step-agent-heading" className="grid gap-4">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-1 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        <div>
          <h3 id="step-agent-heading" className="text-title font-semibold">
            {translateNow("source.enroll.an.agent.43dbb20757")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {translateNow("source.save.the.one.time.token.with.0600.permissi.b35e2c6935")}</p>
        </div>
      </div>
      <div className="grid gap-2 sm:grid-cols-[minmax(12rem,18rem)_auto] sm:items-end">
        <label className="grid gap-1 text-sm font-medium">
          {translateNow("source.agent.identity.698c87920a")}<input
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
          {translateNow("source.mint.enrollment.token.b50d28fa1d")}</Button>
      </div>
      {token && (
        <div>
          <p className="text-caption font-medium text-muted-foreground">{translateNow("source.bootstrap.token.2996dc8b78")}</p>
          <code className="mt-1 block break-all rounded-control bg-muted px-3 py-2 text-caption">{token.token}</code>
        </div>
      )}
      <pre className="overflow-x-auto rounded-control border border-border bg-muted p-3 text-caption">
        <code>{command}</code>
      </pre>
      {agent ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.agent.11b39c9377")}{" "}{agent.name} {" "}{translateNow("source.registered.dfd1beafbf")}</p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          {checking && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          {translateNow("source.waiting.for.the.agent.to.register.3e78d9c8a6")}</p>
      )}
      <Button type="button" variant="outline" className="justify-self-start" onClick={() => void check()}>
        {translateNow("source.check.for.agent.1649b814df")}</Button>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </section>
  );
}

function shellArg(value: string): string {
  if (/^[A-Za-z0-9._:/@-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function CompleteStep({
  agent,
  certificateName,
  integrationSummary,
  issuerName,
  protocolSummary,
  onComplete,
}: {
  agent: Agent | null;
  certificateName: string | null;
  integrationSummary: string | null;
  issuerName: string | null;
  protocolSummary: string | null;
  onComplete: () => void;
}) {
  return (
    <section aria-labelledby="step-complete-heading" className="grid gap-4">
      <h3 id="step-complete-heading" className="flex items-center gap-2 text-title font-semibold">
        <CheckCircle2 className="h-5 w-5 text-status-success" aria-hidden="true" />
        {translateNow("source.ready.for.certificate.operations.e99f6e538f")}</h3>
      <dl className="grid gap-3 sm:grid-cols-2">
        <SummaryItem label="Issuer" value={issuerName ?? "Internal CA"} />
        <SummaryItem label="Protocols" value={protocolSummary ?? "Not configured"} />
        <SummaryItem label="Certificate" value={certificateName ?? "first-service"} />
        <SummaryItem label="Integrations" value={integrationSummary ?? "Not exercised"} />
        <SummaryItem label="Agent" value={agent?.name ?? "not enrolled"} />
      </dl>
      <p className="text-sm text-muted-foreground">{translateNow("source.trstctl.will.track.this.credential.and.ale.258f3fc1df")}</p>
      <Button type="button" className="justify-self-start" onClick={onComplete}>
        {translateNow("source.complete.setup.fe3da4e70b")}</Button>
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
  if (step === "integrations") return "Next: enroll agent";
  if (step === "agent") return "Next: complete setup";
  return "Next";
}
