import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, FileKey2, Loader2, Network, RotateCcw, Server, ShieldCheck } from "lucide-react";
import { ApiError, api, type Agent, type EnrollmentToken, type ProtocolProfileStatus } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { markOnboardingComplete, resetOnboarding } from "@/lib/onboardingState";
import { useTranslation } from "@/i18n/I18nProvider";

type WizardStepID = "issuer" | "protocols" | "certificate" | "agent" | "complete";

function onboardingSteps(t: ReturnType<typeof useTranslation>["t"]): CarouselStep[] {
  return [
    { id: "issuer", label: "Connect issuer", description: "Confirm the signer-backed internal CA or connect an upstream authority later." },
    { id: "protocols", label: t("wizard.protocols.stepLabel"), description: t("wizard.protocols.stepDescription") },
    { id: "certificate", label: "Issue certificate", description: "Create the first workload identity and issue it with an operator credential." },
    { id: "agent", label: "Enroll agent", description: "Mint a one-time enrollment token and wait for the first in-network agent." },
    { id: "complete", label: "Complete", description: "Latch this first-run guide and jump into day-two certificate operations." },
  ];
}

/** Wizard is the first-run flow (F12): a fresh install confirms an issuer,
 * activates the explicit eval enrollment profile when configured, issues its
 * first certificate, enrolls an agent, then latches a browser-local completion
 * flag (see lib/onboardingState) so the dashboard stops prompting setup on later
 * visits. "Reopen setup guide" clears the flag. */
export function Wizard({ pollMs = 4000 }: { pollMs?: number }) {
  const { t } = useTranslation();
  const steps = onboardingSteps(t);
  const [stepIndex, setStepIndex] = useState(0);
  const [issuerReady, setIssuerReady] = useState(false);
  const [issuerName, setIssuerName] = useState<string | null>(null);
  const [protocolSummary, setProtocolSummary] = useState<string | null>(null);
  const [certificateName, setCertificateName] = useState<string | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [completed, setCompleted] = useState(false);

  const currentStep = steps[stepIndex]?.id as WizardStepID;
  const nextEnabled =
    (currentStep === "issuer" && issuerReady) ||
    (currentStep === "protocols" && Boolean(protocolSummary)) ||
    (currentStep === "certificate" && Boolean(certificateName)) ||
    (currentStep === "agent" && Boolean(agent));

  function resetWizard() {
    setStepIndex(0);
    setIssuerReady(false);
    setIssuerName(null);
    setProtocolSummary(null);
    setCertificateName(null);
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
          title="Set up trstctl"
          titleId="wizard-heading"
          description="First-run guide completed — trstctl will not prompt setup again on this browser."
        />
        <section className="ui-panel grid gap-4 p-comfortable" aria-labelledby="setup-complete-heading">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-1 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
            <div>
              <h2 id="setup-complete-heading" className="text-title font-semibold">
                Setup complete
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {certificateName ?? "Your first certificate"} is tracked. trstctl will alert before expiry; renewal is a manual, one-click action today.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/certificates"
              className="inline-flex min-h-10 items-center justify-center rounded-control bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-elevation1 transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              Track and renew certificates
            </Link>
            <Button type="button" variant="outline" onClick={resetWizard}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              Reopen setup guide
            </Button>
          </div>
        </section>
      </section>
    );
  }

  return (
    <section aria-labelledby="wizard-heading" className="mx-auto grid max-w-3xl gap-6">
      <PageHeader title="Set up trstctl" titleId="wizard-heading" description={t("wizard.header.description")} />

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
        {currentStep === "certificate" && <CertificateStep certificateName={certificateName} onIssued={setCertificateName} />}
        {currentStep === "agent" && <AgentStep pollMs={pollMs} agent={agent} onAgent={setAgent} />}
        {currentStep === "complete" && (
          <CompleteStep certificateName={certificateName} issuerName={issuerName} protocolSummary={protocolSummary} agent={agent} onComplete={markComplete} />
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
            Connect an issuer
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            A fresh trstctl server provisions a signer-backed internal X.509 CA at boot. Confirm it before the first certificate is issued.
          </p>
        </div>
      </div>
      {ready ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {issuerName} is ready.
        </p>
      ) : (
        <Button type="button" className="justify-self-start" onClick={() => void confirmIssuer()} disabled={busy}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Use internal CA
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

function CertificateStep({ certificateName, onIssued }: { certificateName: string | null; onIssued: (name: string) => void }) {
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
      await api.issueCertificate({
        name: serviceName,
        ...(isWildcard ? { wildcardBlastRadiusAcknowledged: wildcardAck } : {}),
      });
      onIssued(serviceName);
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
            Issue your first certificate
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Name the service this certificate belongs to. This action uses an operator credential with certificate issuance authority; setup and agent tokens
            cannot issue certificates.
          </p>
        </div>
      </div>
      <label htmlFor="svc-name" className="grid gap-1 text-sm font-medium">
        Service name
        <input
          id="svc-name"
          value={name}
          onChange={(event) => {
            setName(event.target.value);
            if (!event.target.value.trim().startsWith("*.")) setWildcardAck(false);
          }}
          className="w-full rounded-control border border-border bg-background px-3 py-2 text-body"
          placeholder="payments-api"
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
            Acknowledge wildcard blast radius
            <span className="block text-xs font-normal text-muted-foreground">DNS-01 validation is required; renewal uses the lifecycle scheduler.</span>
          </span>
        </label>
      )}
      {certificateName ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {certificateName} was issued.
        </p>
      ) : (
        <Button type="submit" className="justify-self-start" disabled={busy || (isWildcard && !wildcardAck)}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Issue certificate
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
            Enroll an agent
          </h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Save the one-time token with 0600 permissions, then run the agent where it can reach the control plane. Agent enrollment tokens cannot issue
            certificates.
          </p>
        </div>
      </div>
      <div className="grid gap-2 sm:grid-cols-[minmax(12rem,18rem)_auto] sm:items-end">
        <label className="grid gap-1 text-sm font-medium">
          Agent identity
          <input
            className="rounded-control border border-border bg-background px-3 py-2 text-sm font-normal"
            placeholder="node-a"
            value={agentIdentity}
            onChange={(event) => setAgentIdentity(event.target.value)}
            disabled={minting}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <Button type="button" className="justify-self-start" onClick={() => void mintToken()} disabled={minting}>
          {minting && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Mint enrollment token
        </Button>
      </div>
      {token && (
        <div>
          <p className="text-caption font-medium text-muted-foreground">Bootstrap token</p>
          <code className="mt-1 block break-all rounded-control bg-muted px-3 py-2 text-caption">{token.token}</code>
        </div>
      )}
      <pre className="overflow-x-auto rounded-control border border-border bg-muted p-3 text-caption">
        <code>{command}</code>
      </pre>
      {agent ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          Agent {agent.name} registered.
        </p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          {checking && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Waiting for the agent to register...
        </p>
      )}
      <Button type="button" variant="outline" className="justify-self-start" onClick={() => void check()}>
        Check for agent
      </Button>
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
  issuerName,
  protocolSummary,
  onComplete,
}: {
  agent: Agent | null;
  certificateName: string | null;
  issuerName: string | null;
  protocolSummary: string | null;
  onComplete: () => void;
}) {
  return (
    <section aria-labelledby="step-complete-heading" className="grid gap-4">
      <h3 id="step-complete-heading" className="flex items-center gap-2 text-title font-semibold">
        <CheckCircle2 className="h-5 w-5 text-status-success" aria-hidden="true" />
        Ready for certificate operations
      </h3>
      <dl className="grid gap-3 sm:grid-cols-2">
        <SummaryItem label="Issuer" value={issuerName ?? "Internal CA"} />
        <SummaryItem label="Protocols" value={protocolSummary ?? "Not configured"} />
        <SummaryItem label="Certificate" value={certificateName ?? "first-service"} />
        <SummaryItem label="Agent" value={agent?.name ?? "not enrolled"} />
      </dl>
      <p className="text-sm text-muted-foreground">trstctl will track this credential and alert before expiry. Renewal is a manual, one-click action today.</p>
      <Button type="button" className="justify-self-start" onClick={onComplete}>
        Complete setup
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
  if (step === "certificate") return "Next: enroll agent";
  if (step === "agent") return "Next: complete setup";
  return "Next";
}
