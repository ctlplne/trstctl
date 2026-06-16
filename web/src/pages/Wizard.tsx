import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Loader2 } from "lucide-react";
import { api, type Agent, type Issuer } from "@/lib/api";
import { Button } from "@/components/ui/button";

type Step = 1 | 2 | 3 | 4;

const steps = [
  { n: 1, label: "Connect a CA" },
  { n: 2, label: "Install an agent" },
  { n: 3, label: "Issue your first cert" },
];

/** Wizard is the first-run flow (F12; UX target: first cert in <15 minutes): a
 * fresh install connects a CA, installs an agent, and issues its first
 * certificate in three guided steps. `pollMs` controls how often the agent step
 * checks for a freshly-registered agent (tunable for tests). */
export function Wizard({ pollMs = 4000 }: { pollMs?: number }) {
  const [step, setStep] = useState<Step>(1);
  const [issuer, setIssuer] = useState<Issuer | null>(null);
  const [agent, setAgent] = useState<Agent | null>(null);

  return (
    <section aria-labelledby="wizard-heading" className="mx-auto max-w-2xl">
      <h1 id="wizard-heading" className="mb-1 text-2xl font-semibold">
        Set up trstctl
      </h1>
      <p className="mb-6 text-sm text-muted-foreground">
        Three steps to your first certificate.
      </p>

      <ol className="mb-8 flex gap-2" aria-label="Setup progress">
        {steps.map((s) => {
          const state = step > s.n ? "done" : step === s.n ? "current" : "upcoming";
          return (
            <li key={s.n} className="flex flex-1 items-center gap-2 text-sm" aria-current={step === s.n ? "step" : undefined}>
              <span
                className={
                  state === "done"
                    ? "flex h-6 w-6 items-center justify-center rounded-full bg-primary text-primary-foreground"
                    : state === "current"
                      ? "flex h-6 w-6 items-center justify-center rounded-full border-2 border-primary font-medium"
                      : "flex h-6 w-6 items-center justify-center rounded-full border border-border text-muted-foreground"
                }
              >
                {state === "done" ? <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> : s.n}
              </span>
              <span className={state === "upcoming" ? "text-muted-foreground" : ""}>{s.label}</span>
            </li>
          );
        })}
      </ol>

      {step === 1 && (
        <ConnectCAStep
          onConnected={(iss) => {
            setIssuer(iss);
            setStep(2);
          }}
        />
      )}
      {step === 2 && (
        <InstallAgentStep
          pollMs={pollMs}
          agent={agent}
          onAgent={setAgent}
          onContinue={() => setStep(3)}
        />
      )}
      {step === 3 && <IssueCertStep issuer={issuer} onIssued={() => setStep(4)} />}
      {step === 4 && <DoneStep />}
    </section>
  );
}

function ConnectCAStep({ onConnected }: { onConnected: (iss: Issuer) => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const iss = await api.createIssuer({ kind: "x509_ca", name: name.trim() || "Primary CA" });
      onConnected(iss);
    } catch (err) {
      setError(`Could not connect the CA: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="step-ca-heading" className="space-y-4">
      <h2 id="step-ca-heading" className="text-lg font-semibold">
        Connect a Certificate Authority
      </h2>
      <p className="text-sm text-muted-foreground">
        trstctl brokers issuance to your CA. Give this issuer a name to get started.
      </p>
      <div className="space-y-1">
        <label htmlFor="ca-name" className="block text-sm font-medium">
          Certificate Authority name
        </label>
        <input
          id="ca-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          placeholder="e.g. Internal Issuing CA"
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
      <Button type="submit" disabled={busy}>
        {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
        Connect CA
      </Button>
    </form>
  );
}

function InstallAgentStep({
  pollMs,
  agent,
  onAgent,
  onContinue,
}: {
  pollMs: number;
  agent: Agent | null;
  onAgent: (a: Agent) => void;
  onContinue: () => void;
}) {
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const minted = useRef(false);

  // Mint a one-time bootstrap token once, on entering the step.
  useEffect(() => {
    if (minted.current) return;
    minted.current = true;
    api
      .createEnrollmentToken()
      .then((t) => setToken(t.token))
      .catch((err) => setError(`Could not mint an enrollment token: ${String(err)}`));
  }, []);

  // Poll for the agent to register (UX target: first agent in <5 minutes).
  useEffect(() => {
    if (agent) return;
    const id = setInterval(() => {
      void check();
    }, pollMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent, pollMs]);

  async function check() {
    setChecking(true);
    try {
      const list = await api.agents();
      if (list.length > 0) onAgent(list[0]);
    } catch {
      // transient; the next poll retries.
    } finally {
      setChecking(false);
    }
  }

  const origin = typeof window !== "undefined" ? window.location.origin : "https://trstctl.example";
  const command = `trstctl-agent enroll --server ${origin} --token ${token ?? "<minting…>"}`;

  return (
    <section aria-labelledby="step-agent-heading" className="space-y-4">
      <h2 id="step-agent-heading" className="text-lg font-semibold">
        Install an agent
      </h2>
      <p className="text-sm text-muted-foreground">
        Run this on a host inside your network. The agent generates its key locally and enrolls with
        the one-time token — private keys never leave the host.
      </p>
      <pre className="overflow-x-auto rounded-md border border-border bg-muted p-3 text-xs">
        <code>{command}</code>
      </pre>
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}

      {agent ? (
        <p className="flex items-center gap-2 text-sm font-medium text-green-700 dark:text-green-400">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          Agent {agent.name} registered.
        </p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          {checking && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Waiting for the agent to register…
        </p>
      )}

      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={() => void check()}>
          Check for agent
        </Button>
        <Button type="button" onClick={onContinue} disabled={!agent}>
          Continue
        </Button>
      </div>
    </section>
  );
}

function IssueCertStep({ issuer, onIssued }: { issuer: Issuer | null; onIssued: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.issueCertificate({ name: name.trim() || "first-service", issuerId: issuer?.id });
      onIssued();
    } catch (err) {
      setError(`Could not issue the certificate: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="step-cert-heading" className="space-y-4">
      <h2 id="step-cert-heading" className="text-lg font-semibold">
        Issue your first cert
      </h2>
      <p className="text-sm text-muted-foreground">
        Name the service this certificate belongs to. trstctl creates the owner and identity and
        issues it through the CA you connected.
      </p>
      <div className="space-y-1">
        <label htmlFor="svc-name" className="block text-sm font-medium">
          Service name
        </label>
        <input
          id="svc-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          placeholder="e.g. payments-api"
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
      <Button type="submit" disabled={busy}>
        {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
        Issue certificate
      </Button>
    </form>
  );
}

function DoneStep() {
  return (
    <section aria-labelledby="step-done-heading" className="space-y-4">
      <h2 id="step-done-heading" className="flex items-center gap-2 text-lg font-semibold">
        <CheckCircle2 className="h-5 w-5 text-green-600" aria-hidden="true" />
        Your first certificate has been issued
      </h2>
      <p className="text-sm text-muted-foreground">
        You're set up. trstctl will now track, rotate, and renew this credential automatically.
      </p>
      <div className="flex gap-2">
        <Link
          to="/certificates"
          className="inline-flex items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
        >
          View certificates
        </Link>
      </div>
    </section>
  );
}
