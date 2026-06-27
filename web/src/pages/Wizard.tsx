import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, FileKey2, Loader2, RotateCcw, Server, ShieldCheck } from "lucide-react";
import { api, type Agent } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";

type WizardStepID = "issuer" | "certificate" | "agent" | "complete";

const onboardingSteps: CarouselStep[] = [
  { id: "issuer", label: "Connect issuer", description: "Confirm the signer-backed internal CA or connect an upstream authority later." },
  { id: "certificate", label: "Issue certificate", description: "Create the first workload identity and issue it through the control plane." },
  { id: "agent", label: "Enroll agent", description: "Mint a one-time enrollment token and wait for the first in-network agent." },
  { id: "complete", label: "Complete", description: "Latch this first-run guide and jump into day-two certificate operations." },
];

/** Wizard is the first-run flow (F12): a fresh install confirms an issuer,
 * issues its first certificate, enrolls an agent, then closes into an in-memory
 * completion latch. No browser storage is used for onboarding state. */
export function Wizard({ pollMs = 4000 }: { pollMs?: number }) {
  const [stepIndex, setStepIndex] = useState(0);
  const [issuerReady, setIssuerReady] = useState(false);
  const [issuerName, setIssuerName] = useState<string | null>(null);
  const [certificateName, setCertificateName] = useState<string | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [completed, setCompleted] = useState(false);

  const currentStep = onboardingSteps[stepIndex]?.id as WizardStepID;
  const nextEnabled =
    (currentStep === "issuer" && issuerReady) ||
    (currentStep === "certificate" && Boolean(certificateName)) ||
    (currentStep === "agent" && Boolean(agent));

  function resetWizard() {
    setStepIndex(0);
    setIssuerReady(false);
    setIssuerName(null);
    setCertificateName(null);
    setAgent(null);
    setCompleted(false);
  }

  if (completed) {
    return (
      <section aria-labelledby="wizard-heading" className="mx-auto grid max-w-3xl gap-6">
        <PageHeader title="Set up trstctl" titleId="wizard-heading" description="First-run guide completed for this browser session." />
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
      <PageHeader title="Set up trstctl" titleId="wizard-heading" description="Connect an issuer, issue a certificate, enroll an agent, and finish." />

      <StepShell
        steps={onboardingSteps}
        currentIndex={stepIndex}
        onPrevious={() => setStepIndex((current) => Math.max(0, current - 1))}
        onNext={currentStep === "complete" ? undefined : () => setStepIndex((current) => Math.min(onboardingSteps.length - 1, current + 1))}
        nextDisabled={!nextEnabled}
        nextLabel={nextLabel(currentStep)}
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
        {currentStep === "certificate" && <CertificateStep certificateName={certificateName} onIssued={setCertificateName} />}
        {currentStep === "agent" && <AgentStep pollMs={pollMs} agent={agent} onAgent={setAgent} />}
        {currentStep === "complete" && (
          <CompleteStep certificateName={certificateName} issuerName={issuerName} agent={agent} onComplete={() => setCompleted(true)} />
        )}
      </StepShell>
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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    const serviceName = name.trim() || "first-service";
    try {
      await api.issueCertificate({ name: name.trim() || "first-service" });
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
            Name the service this certificate belongs to. trstctl creates the owner and identity, then issues through the configured authority.
          </p>
        </div>
      </div>
      <label htmlFor="svc-name" className="grid gap-1 text-sm font-medium">
        Service name
        <input
          id="svc-name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          className="w-full rounded-control border border-border bg-background px-3 py-2 text-body"
          placeholder="payments-api"
        />
      </label>
      {certificateName ? (
        <p className="flex items-center gap-2 text-sm font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {certificateName} was issued.
        </p>
      ) : (
        <Button type="submit" className="justify-self-start" disabled={busy}>
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
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const minted = useRef(false);

  useEffect(() => {
    if (minted.current) return;
    minted.current = true;
    api
      .createEnrollmentToken()
      .then((result) => setToken(result.token))
      .catch((err) => setError(`Could not mint an enrollment token: ${String(err instanceof Error ? err.message : err)}`));
  }, []);

  useEffect(() => {
    if (agent) return undefined;
    const id = window.setInterval(() => {
      void check();
    }, pollMs);
    return () => window.clearInterval(id);
    // check is intentionally not a dependency; each tick uses the latest setter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent, pollMs]);

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
  const command = [
    "trstctl-agent",
    `--enroll-url ${origin}`,
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    "--server <control-plane-grpc:9443>",
    "--name <agent-name>",
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
            Save the one-time token with 0600 permissions, then run the agent where it can reach the control plane.
          </p>
        </div>
      </div>
      {token && (
        <div>
          <p className="text-caption font-medium text-muted-foreground">Bootstrap token</p>
          <code className="mt-1 block break-all rounded-control bg-muted px-3 py-2 text-caption">{token}</code>
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

function CompleteStep({
  agent,
  certificateName,
  issuerName,
  onComplete,
}: {
  agent: Agent | null;
  certificateName: string | null;
  issuerName: string | null;
  onComplete: () => void;
}) {
  return (
    <section aria-labelledby="step-complete-heading" className="grid gap-4">
      <h3 id="step-complete-heading" className="flex items-center gap-2 text-title font-semibold">
        <CheckCircle2 className="h-5 w-5 text-status-success" aria-hidden="true" />
        Ready for certificate operations
      </h3>
      <dl className="grid gap-3 sm:grid-cols-3">
        <SummaryItem label="Issuer" value={issuerName ?? "Internal CA"} />
        <SummaryItem label="Certificate" value={certificateName ?? "first-service"} />
        <SummaryItem label="Agent" value={agent?.name ?? "not enrolled"} />
      </dl>
      <p className="text-sm text-muted-foreground">
        trstctl will track this credential and alert before expiry. Renewal is a manual, one-click action today.
      </p>
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

function nextLabel(step: WizardStepID): string {
  if (step === "issuer") return "Next: issue certificate";
  if (step === "certificate") return "Next: enroll agent";
  if (step === "agent") return "Next: complete setup";
  return "Next";
}
