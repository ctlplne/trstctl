import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, type GraphImpact, type GraphNode, type IncidentExecution, type IncidentExecutionRequest } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";

const defaultExecution: IncidentExecutionRequest = {
  identity_id: "",
  reason: "private key compromise",
  replacement_name: "",
  connector: "nginx",
  target: "",
  delivery_rollback_ref: "",
};

const fleetStages = [
  {
    batch: "Wave 0",
    scope: "issuer inventory and canary service",
    status: "12 percent complete",
    health: "synthetic check passed",
    failed: "0 failed targets",
  },
  {
    batch: "Wave 1",
    scope: "payments and checkout workloads",
    status: "48 percent complete",
    health: "two targets paused for owner review",
    failed: "2 failed targets",
  },
  {
    batch: "Wave 2",
    scope: "remaining edge and appliance targets",
    status: "scheduled",
    health: "resume requires incident commander approval",
    failed: "rollback plan staged",
  },
];

const breakGlassChecklist = [
  "emergency declaration names incident ID, commander, reason, and expiry",
  "quorum approval records two operators outside the affected owner team",
  "offline issue uses signer ceremony evidence and a short TTL",
  "verification checks fingerprint, chain, scope, and tenant before deployment",
  "reconciliation imports the offline event stream delta after control-plane recovery",
  "post-incident checklist rotates emergency material and closes temporary access",
];

export function Incidents() {
  const [form, setForm] = useState<IncidentExecutionRequest>(defaultExecution);
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [executions, setExecutions] = useState<IncidentExecution[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [executeError, setExecuteError] = useState<string | null>(null);
  const [latestExecution, setLatestExecution] = useState<IncidentExecution | null>(null);
  const [showBreakGlassHelp, setShowBreakGlassHelp] = useState(false);
  const [loading, setLoading] = useState(true);
  const [previewing, setPreviewing] = useState(false);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .incidentExecutions({ limit: 10 })
      .then((result) => {
        if (!active) return;
        setExecutions(result.items ?? []);
        setLoadError(null);
      })
      .catch((err) => {
        if (!active) return;
        setLoadError(apiProblemMessage(err, "Could not load incident executions"));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  async function previewBlastRadius() {
    if (!form.identity_id.trim()) {
      setPreviewError("Compromised identity ID is required.");
      return;
    }
    setPreviewing(true);
    setPreviewError(null);
    try {
      const result = await api.graphBlastRadius(`id:${form.identity_id.trim()}`);
      setImpact(result);
    } catch (err) {
      setPreviewError(apiProblemMessage(err, "Could not load blast-radius preview"));
      setImpact(null);
    } finally {
      setPreviewing(false);
    }
  }

  async function executeIncident(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!form.identity_id.trim()) {
      setExecuteError("Compromised identity ID is required.");
      return;
    }
    setExecuting(true);
    setExecuteError(null);
    setLatestExecution(null);
    try {
      const result = await api.executeIncident({
        ...form,
        identity_id: form.identity_id.trim(),
        reason: form.reason?.trim() || "incident execution",
      });
      setExecutions((prev) => [result, ...prev.filter((item) => item.id !== result.id)].slice(0, 10));
      setImpact(result.blast_radius);
      setLatestExecution(result);
    } catch (err) {
      setExecuteError(apiProblemMessage(err, "Could not execute incident"));
    } finally {
      setExecuting(false);
    }
  }

  return (
    <section aria-labelledby="incidents-heading" className="grid gap-6">
      <PageHeader
        titleId="incidents-heading"
        title="Incidents"
        description="Execute credential-compromise remediation with blast-radius evidence, replacement-before-revoke lifecycle actions, connector delivery receipts, failed-target rollback evidence, and sealed audit bundles."
      />

      <section aria-labelledby="execute-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="execute-heading" className="text-title font-semibold">
            Credential compromise execution
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Incident execution issues and deploys a replacement identity before revoking the compromised identity.
          </p>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={executeIncident}>
          <label className="grid gap-1 text-sm font-medium">
            Affected identity
            <input
              className="ui-input font-mono"
              value={form.identity_id}
              onChange={(event) => setForm({ ...form, identity_id: event.target.value })}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            What happened
            <input className="ui-input" value={form.reason ?? ""} onChange={(event) => setForm({ ...form, reason: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Replacement identity name
            <input
              className="ui-input"
              value={form.replacement_name ?? ""}
              onChange={(event) => setForm({ ...form, replacement_name: event.target.value })}
              placeholder="optional"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Delivery method
            <input className="ui-input" value={form.connector ?? ""} onChange={(event) => setForm({ ...form, connector: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Deployment target
            <input
              className="ui-input"
              value={form.target ?? ""}
              onChange={(event) => setForm({ ...form, target: event.target.value })}
              placeholder="edge/prod/payments"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Rollback instructions
            <input
              className="ui-input"
              value={form.delivery_rollback_ref ?? ""}
              onChange={(event) => setForm({ ...form, delivery_rollback_ref: event.target.value })}
              placeholder="restore previous binding"
            />
          </label>
          <div className="flex flex-wrap gap-2 md:col-span-2">
            <Button type="button" variant="outline" onClick={previewBlastRadius} disabled={previewing}>
              {previewing ? "Loading preview..." : "Preview blast radius"}
            </Button>
            <Button type="submit" disabled={executing}>
              {executing ? "Executing..." : "Execute incident"}
            </Button>
          </div>
        </form>
        {previewError && <ErrorState title="Blast-radius preview unavailable">{previewError}</ErrorState>}
        {executeError && <ErrorState title="Incident execution failed">{executeError}</ErrorState>}
        {latestExecution && (
          <section role="status" aria-labelledby="incident-progress-heading" className="ui-panel p-comfortable">
            <h3 id="incident-progress-heading" className="text-title font-semibold">
              Incident execution recorded
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-3">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Execution</dt>
                <dd className="font-mono text-xs">{latestExecution.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Status</dt>
                <dd>{latestExecution.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Current phase</dt>
                <dd className="break-all font-mono text-xs">{latestExecution.phase}</dd>
              </div>
            </dl>
          </section>
        )}
        {impact && <BlastRadiusPreview impact={impact} />}
      </section>

      <section aria-labelledby="evidence-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="evidence-heading" className="text-title font-semibold">
            Execution evidence
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Each execution is a projected event-sourced evidence pack with revocation, delivery, rollback, and audit-bundle state.
          </p>
        </div>
        {loading && <LoadingState>Loading incident execution evidence...</LoadingState>}
        {loadError && <ErrorState title="Incident evidence unavailable">{loadError}</ErrorState>}
        {!loading && !loadError && <IncidentExecutionTable executions={executions} />}
      </section>

      <section aria-labelledby="fleet-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="fleet-heading" className="text-title font-semibold">
            Example fleet re-issuance plan
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Example planning data for a CA compromise drill. Live fleet batch execution is not available in this console.
          </p>
        </div>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">Example fleet reissuance plan</caption>
            <thead>
              <tr>
                <th scope="col">Batch</th>
                <th scope="col">Affected issuer scope</th>
                <th scope="col">Percent complete</th>
                <th scope="col">Health / resume</th>
                <th scope="col">Failed targets / rollback</th>
              </tr>
            </thead>
            <tbody>
              {fleetStages.map((stage) => (
                <tr key={stage.batch} className="align-top">
                  <td className="font-medium">{stage.batch}</td>
                  <td>{stage.scope}</td>
                  <td>{stage.status}</td>
                  <td>{stage.health}</td>
                  <td>{stage.failed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="incident-help-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="incident-help-heading" className="text-title font-semibold">
            Incident response help
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Keep emergency issuance guidance close by without mixing it into the execution form.
          </p>
        </div>
        <div>
          <Button type="button" variant="outline" onClick={() => setShowBreakGlassHelp(true)}>
            Break-glass help
          </Button>
        </div>
        {showBreakGlassHelp && (
          <div role="dialog" aria-modal="true" aria-labelledby="break-glass-help-heading" className="ui-panel max-w-4xl p-comfortable">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 id="break-glass-help-heading" className="text-title font-semibold">
                  Break-glass help
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  Emergency issuance requires declaration, quorum, offline issue evidence, verification, expiry, reconciliation, and cleanup.
                </p>
              </div>
              <Button type="button" variant="outline" onClick={() => setShowBreakGlassHelp(false)}>
                Close help
              </Button>
            </div>
            <ul className="mt-3 grid gap-2 md:grid-cols-2">
              {breakGlassChecklist.map((item) => (
                <li key={item} className="rounded-md border border-border p-3 text-sm text-muted-foreground">
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </section>
  );
}

function IncidentExecutionTable({ executions }: { executions: IncidentExecution[] }) {
  if (executions.length === 0) {
    return <p className="text-sm text-muted-foreground">No incident executions have been recorded.</p>;
  }
  return (
    <div className="overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[68rem]">
        <caption className="sr-only">Incident execution evidence</caption>
        <thead>
          <tr>
            <th scope="col">Execution</th>
            <th scope="col">Compromised</th>
            <th scope="col">Replacement</th>
            <th scope="col">Status</th>
            <th scope="col">Delivery</th>
            <th scope="col">Failed targets</th>
            <th scope="col">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {executions.map((item) => (
            <tr key={item.id} className="align-top">
              <td className="font-mono text-xs">{item.id}</td>
              <td className="font-mono text-xs">{item.compromised_identity_id}</td>
              <td className="font-mono text-xs">{item.replacement_identity_id ?? "-"}</td>
              <td>
                <p className="font-medium">{item.status}</p>
                <p className="text-xs text-muted-foreground">{item.phase}</p>
              </td>
              <td>
                <p className="font-medium">{item.connector_delivery?.status ?? item.connector_delivery_id ?? "-"}</p>
                <p className="text-xs text-muted-foreground">
                  {item.connector_delivery?.connector ?? ""} {item.connector_delivery?.target ?? ""}
                </p>
              </td>
              <td>{item.failed_targets.length ? item.failed_targets.join(", ") : "none"}</td>
              <td>
                <p className="font-medium">{item.evidence_bundle_format || "unavailable"}</p>
                <p className="max-w-[18rem] truncate font-mono text-xs text-muted-foreground">{item.evidence_bundle || "-"}</p>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BlastRadiusPreview({ impact }: { impact: GraphImpact }) {
  return (
    <section aria-labelledby="incident-blast-heading" className="ui-panel p-comfortable">
      <h3 id="incident-blast-heading" className="text-title font-semibold">
        Blast-radius snapshot
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        Compromise of {impact.node.name || impact.node.id} affects {impact.affected.length} downstream node{impact.affected.length === 1 ? "" : "s"}.
      </p>
      <dl className="mt-3 grid gap-2 md:grid-cols-3">
        {Object.entries(impact.by_kind ?? {}).map(([kind, value]) => (
          <div key={kind} className="rounded-md border border-border p-2">
            <dt className="font-medium">{kind}</dt>
            <dd className="text-sm text-muted-foreground">{displayValue(value)}</dd>
          </div>
        ))}
      </dl>
      <AffectedNodes nodes={impact.affected} />
    </section>
  );
}

function AffectedNodes({ nodes }: { nodes: GraphNode[] }) {
  if (nodes.length === 0) {
    return <p className="mt-3 text-sm text-muted-foreground">No downstream affected nodes were returned.</p>;
  }
  return (
    <ul className="mt-3 grid gap-2 md:grid-cols-2">
      {nodes.map((node) => (
        <li key={node.id} className="rounded-md border border-border p-2">
          <p className="font-medium">{node.name || node.id}</p>
          <p className="font-mono text-xs text-muted-foreground">
            {node.kind} - {node.id}
          </p>
        </li>
      ))}
    </ul>
  );
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (Array.isArray(value)) return String(value.length);
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s.`;
    const body = err.body.trim();
    if (body) {
      try {
        const problem = JSON.parse(body) as { detail?: string; title?: string };
        const message = problem.detail || problem.title;
        if (message) return `${fallback}: ${message}`;
      } catch {
        return `${fallback}: ${body}`;
      }
    }
    return `${fallback}: ${err.message}`;
  }
  return `${fallback}: ${err instanceof Error ? err.message : String(err)}`;
}
