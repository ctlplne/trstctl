import { useEffect, useMemo, useState } from "react";
import { Copy, Loader2, RefreshCw, X } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";
import { api, type Agent, type EnrollmentToken } from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

const staleAfterMs = 24 * 60 * 60 * 1000;

export function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const [tokenBusy, setTokenBusy] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function load() {
    setError(null);
    setLoading(true);
    try {
      const list = await api.agents();
      setAgents(list);
      setSelectedID((current) => current ?? list[0]?.id ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function mintToken() {
    setTokenError(null);
    setCopied(false);
    setTokenBusy(true);
    try {
      setToken(await api.createEnrollmentToken());
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : String(err));
    } finally {
      setTokenBusy(false);
    }
  }

  const selected = useMemo(() => agents.find((agent) => agent.id === selectedID) ?? agents[0] ?? null, [agents, selectedID]);
  const command = token ? enrollmentCommand(token) : "";

  async function copyCommand() {
    if (!command) return;
    try {
      await navigator.clipboard?.writeText(command);
      setCopied(true);
    } catch {
      setCopied(true);
    }
  }

  return (
    <section aria-labelledby="agents-heading" className="grid gap-6">
      <PageHeader
        titleId="agents-heading"
        title="Agents"
        description="The in-network agents that deploy and rotate credentials on your hosts. Register a new agent with a one-time enrollment token."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Refresh
          </Button>
        }
      />

      <section aria-labelledby="enrollment-heading" className="border-y border-border py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="enrollment-heading" className="text-title font-semibold">
              Enrollment token
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Mint a one-time bootstrap token. The token stays in component memory only; it is never written to browser storage.
            </p>
          </div>
          <Button type="button" onClick={() => void mintToken()} disabled={tokenBusy}>
            {tokenBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Mint enrollment token
          </Button>
        </div>

        {tokenError && <ErrorState title="Could not mint enrollment token">{tokenError}</ErrorState>}

        {token && (
          <div className="mt-4 grid gap-3 rounded-md border border-border p-3 text-sm">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-medium">Shown once</p>
                <p className="mt-1 text-muted-foreground">
                  Save the token to ./trstctl-bootstrap-token with 0600 permissions, then copy this command. Dismiss clears the token from the page state; the
                  console does not persist it.
                </p>
              </div>
              <Button type="button" variant="ghost" size="sm" onClick={() => setToken(null)}>
                <X className="h-4 w-4" aria-hidden="true" />
                Dismiss
              </Button>
            </div>
            <dl className="grid gap-2">
              <div>
                <dt className="font-medium text-muted-foreground">Bootstrap token</dt>
                <dd className="break-all font-mono text-xs">{token.token}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Install command</dt>
                <dd className="mt-1">
                  <code className="block overflow-x-auto rounded bg-muted px-3 py-2 text-xs">{command}</code>
                </dd>
              </div>
            </dl>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" size="sm" variant="outline" onClick={() => void copyCommand()}>
                <Copy className="h-4 w-4" aria-hidden="true" />
                Copy command
              </Button>
              {copied && <p className="text-xs text-muted-foreground">Copied once from memory.</p>}
            </div>
          </div>
        )}
      </section>

      {error && <ErrorState title="Could not load agents">{error}</ErrorState>}
      {loading && <LoadingState>Loading agents...</LoadingState>}

      {!loading && !error && agents.length === 0 && (
        <EmptyState title="No agents enrolled yet">
          Mint a one-time enrollment token, install an agent inside the tenant network, then refresh this page when it registers.
        </EmptyState>
      )}

      {!loading && !error && agents.length > 0 && (
        <section aria-labelledby="fleet-heading" className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div>
            <h2 id="fleet-heading" className="mb-3 text-title font-semibold">
              Agent fleet
            </h2>
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[52rem]">
                <caption className="sr-only">Registered in-network agents</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Status</th>
                    <th scope="col">Version</th>
                    <th scope="col">Last seen</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((agent) => {
                    const freshness = heartbeatFreshness(agent.last_seen_at);
                    return (
                      <tr key={agent.id} className="align-top">
                        <td className="font-medium">{agent.name}</td>
                        <td>
                          <StatusBadge vocabulary="agent" value={agent.status} />
                        </td>
                        <td className="font-mono text-xs">{agent.version || "-"}</td>
                        <td>
                          <p>{formatDate(agent.last_seen_at)}</p>
                          <p className={freshness.stale ? "text-xs font-medium text-status-warning" : "text-xs text-muted-foreground"}>{freshness.label}</p>
                        </td>
                        <td>
                          <Button type="button" size="sm" variant="outline" onClick={() => setSelectedID(agent.id)}>
                            View details
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          {selected && <AgentDetail agent={selected} />}
        </section>
      )}
    </section>
  );
}

function AgentDetail({ agent }: { agent: Agent }) {
  return (
    <aside aria-labelledby="agent-detail-heading" className="grid content-start gap-3 border-y border-border py-4">
      <div>
        <h2 id="agent-detail-heading" className="text-title font-semibold">
          {agent.name}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">Agent profile, heartbeat, and version details.</p>
      </div>
      <dl className="grid gap-2 text-sm">
        <div>
          <dt className="font-medium text-muted-foreground">Agent ID</dt>
          <dd className="break-all font-mono text-xs">{agent.id}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Status</dt>
          <dd>{agent.status}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Version</dt>
          <dd className="font-mono text-xs">{agent.version || "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Last seen</dt>
          <dd>{formatDate(agent.last_seen_at)}</dd>
        </div>
      </dl>
      <UnavailableState title="Agent telemetry is limited for now">
        Discovery scanning, drift detection, and agent-driven certificate renewal all run in the agent itself. Console views for capabilities, last
        scan, drift summary, and renewal state aren't surfaced here yet — this page shows the live profile and heartbeat fields.
      </UnavailableState>
    </aside>
  );
}

function heartbeatFreshness(lastSeen?: string): { label: string; stale: boolean } {
  if (!lastSeen) return { label: "No heartbeat timestamp", stale: true };
  const ts = Date.parse(lastSeen);
  if (Number.isNaN(ts)) return { label: "Unparseable heartbeat timestamp", stale: true };
  const ageMs = Date.now() - ts;
  if (ageMs > staleAfterMs) return { label: "Stale heartbeat", stale: true };
  return { label: "Fresh heartbeat", stale: false };
}

function formatDate(value?: string): string {
  return formatDateTimePolicy(value);
}

function enrollmentCommand(token: EnrollmentToken): string {
  const origin = typeof window !== "undefined" ? window.location.origin : "https://trstctl.example.test";
  const enrollPath = token.enroll_path || "/enroll/bootstrap";
  return [
    "trstctl-agent",
    `--enroll-url ${origin}${enrollPath}`,
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    "--server <control-plane-grpc:9443>",
    "--name <agent-name>",
    "--ca-bundle ./trstctl-ca.pem",
  ].join(" ");
}
