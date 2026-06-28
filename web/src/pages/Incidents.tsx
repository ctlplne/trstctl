import { FormEvent, useEffect, useRef, useState } from "react";
import { Download, Pause, Play, RotateCcw } from "lucide-react";
import {
  api,
  ApiError,
  type FleetReissuanceEvidence,
  type FleetReissuanceRequest,
  type FleetReissuanceRun,
  type GraphImpact,
  type GraphNode,
  type IncidentExecution,
  type IncidentExecutionRequest,
  type ITSMTicket,
  type ServiceNowTicketRequest,
} from "@/lib/api";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { BreakGlassReconcile } from "@/components/breakglass";

const defaultExecution: IncidentExecutionRequest = {
  identity_id: "",
  reason: "private key compromise",
  replacement_name: "",
  connector: "nginx",
  target: "",
  delivery_rollback_ref: "",
};

const defaultServiceNowTicket: ServiceNowTicketRequest = {
  instance_url: "",
  table: "incident",
  token_ref: "servicenow-ticket-token",
  short_description: "",
  description: "",
  category: "security",
  urgency: "2",
  impact: "2",
  correlation_id: "",
};

const defaultFleetRun: FleetReissuanceRequest = {
  issuer_id: "",
  reason: "intermediate CA private key exposure",
  batch_size: 25,
  connector: "nginx",
  target: "",
  rollback_ref: "",
  health_gates: [
    { name: "replacement deployed", status: "passed" },
    { name: "revocation published", status: "passed" },
  ],
  evidence_hint: "",
};

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
  const [fleetForm, setFleetForm] = useState<FleetReissuanceRequest>(defaultFleetRun);
  const [fleetRuns, setFleetRuns] = useState<FleetReissuanceRun[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [executeError, setExecuteError] = useState<string | null>(null);
  const [fleetError, setFleetError] = useState<string | null>(null);
  const [ticketForm, setTicketForm] = useState<ServiceNowTicketRequest>(defaultServiceNowTicket);
  const [ticketError, setTicketError] = useState<string | null>(null);
  const [latestExecution, setLatestExecution] = useState<IncidentExecution | null>(null);
  const [latestFleetRun, setLatestFleetRun] = useState<FleetReissuanceRun | null>(null);
  const [fleetEvidence, setFleetEvidence] = useState<FleetReissuanceEvidence | null>(null);
  const [latestTicket, setLatestTicket] = useState<ITSMTicket | null>(null);
  const [showBreakGlassHelp, setShowBreakGlassHelp] = useState(false);
  const breakGlassCloseRef = useRef<HTMLButtonElement>(null);
  const [loading, setLoading] = useState(true);
  const [previewing, setPreviewing] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [runningFleet, setRunningFleet] = useState(false);
  const [fleetAction, setFleetAction] = useState<string | null>(null);
  const [ticketing, setTicketing] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.all([api.incidentExecutions({ limit: 10 }), api.fleetReissuanceRuns({ limit: 10 })])
      .then(([executionResult, fleetResult]) => {
        if (!active) return;
        setExecutions(executionResult.items ?? []);
        setFleetRuns(fleetResult.items ?? []);
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

  async function queueServiceNowTicket(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ticketForm.instance_url.trim()) {
      setTicketError("ServiceNow instance URL is required.");
      return;
    }
    if (!ticketForm.short_description.trim()) {
      setTicketError("Ticket summary is required.");
      return;
    }
    setTicketing(true);
    setTicketError(null);
    setLatestTicket(null);
    try {
      const result = await api.createServiceNowTicket({
        ...ticketForm,
        instance_url: ticketForm.instance_url.trim(),
        token_ref: ticketForm.token_ref.trim(),
        short_description: ticketForm.short_description.trim(),
        description: ticketForm.description?.trim() ?? "",
        category: ticketForm.category?.trim() ?? "",
        urgency: ticketForm.urgency?.trim() ?? "",
        impact: ticketForm.impact?.trim() ?? "",
        correlation_id: ticketForm.correlation_id?.trim() ?? "",
      });
      setLatestTicket(result);
    } catch (err) {
      setTicketError(apiProblemMessage(err, "Could not queue ServiceNow ticket"));
    } finally {
      setTicketing(false);
    }
  }

  async function startFleetReissuance(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (!fleetForm.issuer_id.trim()) {
      setFleetError("Compromised issuer ID is required.");
      return;
    }
    setRunningFleet(true);
    setFleetError(null);
    setLatestFleetRun(null);
    setFleetEvidence(null);
    try {
      const result = await api.startFleetReissuance({
        ...fleetForm,
        issuer_id: fleetForm.issuer_id.trim(),
        reason: fleetForm.reason?.trim() || "fleet reissuance",
        connector: fleetForm.connector?.trim() || "nginx",
        target: fleetForm.target?.trim() || "unconfigured-target",
        rollback_ref: fleetForm.rollback_ref?.trim() || "restore previous credential binding",
      });
      setFleetRuns((prev) => [result, ...prev.filter((item) => item.id !== result.id)].slice(0, 10));
      setLatestFleetRun(result);
    } catch (err) {
      setFleetError(apiProblemMessage(err, "Could not start fleet reissuance"));
    } finally {
      setRunningFleet(false);
    }
  }

  async function recordFleetAction(kind: "pause" | "resume" | "rollback" | "evidence", run: FleetReissuanceRun) {
    const actionKey = `${kind}:${run.id}`;
    setFleetAction(actionKey);
    setFleetError(null);
    try {
      if (kind === "evidence") {
        const evidence = await api.exportFleetReissuanceEvidence(run.id);
        setFleetEvidence(evidence);
        return;
      }
      const input = kind === "rollback" ? { reason: "operator rollback", rollback_ref: "restore previous credential bindings" } : { reason: `operator ${kind}` };
      const updated =
        kind === "pause"
          ? await api.pauseFleetReissuance(run.id, input)
          : kind === "resume"
            ? await api.resumeFleetReissuance(run.id, input)
            : await api.rollbackFleetReissuance(run.id, input);
      setFleetRuns((prev) => [updated, ...prev.filter((item) => item.id !== updated.id)].slice(0, 10));
      setLatestFleetRun(updated);
      if (kind === "rollback") {
        setFleetEvidence({
          run_id: updated.id,
          evidence_bundle_format: updated.evidence_bundle_format ?? "",
          evidence_bundle: updated.evidence_bundle ?? "",
          rollback_refs: updated.rollback_refs ?? [],
          failed_targets: updated.failed_targets ?? [],
          exported_at: updated.updated_at ?? new Date().toISOString(),
        });
      }
    } catch (err) {
      setFleetError(apiProblemMessage(err, `Could not ${kind} fleet reissuance`));
    } finally {
      setFleetAction(null);
    }
  }

  return (
    <section aria-labelledby="incidents-heading" className="grid gap-6">
      <PageHeader
        titleId="incidents-heading"
        title="Incidents"
        description="Respond to a compromised credential: see what it can reach (blast radius), issue a replacement before revoking, push it out through connectors, roll back failed targets, and capture a tamper-evident audit bundle."
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

      <section aria-labelledby="servicenow-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="servicenow-heading" className="text-title font-semibold">
            ServiceNow ITSM workflow
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Queue a ServiceNow Table API ticket through the same event log and outbox used for credential workflows.
          </p>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={queueServiceNowTicket}>
          <label className="grid gap-1 text-sm font-medium">
            ServiceNow instance
            <input
              className="ui-input"
              value={ticketForm.instance_url}
              onChange={(event) => setTicketForm({ ...ticketForm, instance_url: event.target.value })}
              placeholder="https://example.service-now.com"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Ticket table
            <select
              className="ui-input"
              value={ticketForm.table ?? "incident"}
              onChange={(event) => setTicketForm({ ...ticketForm, table: event.target.value as ServiceNowTicketRequest["table"] })}
            >
              <option value="incident">Incident</option>
              <option value="change_request">Change request</option>
              <option value="sc_task">Service catalog task</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Token reference
            <input
              className="ui-input font-mono"
              value={ticketForm.token_ref}
              onChange={(event) => setTicketForm({ ...ticketForm, token_ref: event.target.value })}
              placeholder="servicenow-ticket-token"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Ticket summary
            <input
              className="ui-input"
              value={ticketForm.short_description}
              onChange={(event) => setTicketForm({ ...ticketForm, short_description: event.target.value })}
              placeholder="Rotate exposed TLS private key"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium md:col-span-2">
            Ticket description
            <textarea
              className="ui-input min-h-24"
              value={ticketForm.description ?? ""}
              onChange={(event) => setTicketForm({ ...ticketForm, description: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Category
            <input className="ui-input" value={ticketForm.category ?? ""} onChange={(event) => setTicketForm({ ...ticketForm, category: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Urgency
            <input className="ui-input" value={ticketForm.urgency ?? ""} onChange={(event) => setTicketForm({ ...ticketForm, urgency: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Impact
            <input className="ui-input" value={ticketForm.impact ?? ""} onChange={(event) => setTicketForm({ ...ticketForm, impact: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Correlation ID
            <input
              className="ui-input"
              value={ticketForm.correlation_id ?? ""}
              onChange={(event) => setTicketForm({ ...ticketForm, correlation_id: event.target.value })}
              placeholder="optional"
            />
          </label>
          <div className="md:col-span-2">
            <Button type="submit" disabled={ticketing}>
              {ticketing ? "Queueing..." : "Queue ServiceNow ticket"}
            </Button>
          </div>
        </form>
        {ticketError && <ErrorState title="ServiceNow ticket failed">{ticketError}</ErrorState>}
        {latestTicket && (
          <section role="status" aria-labelledby="servicenow-queued-heading" className="ui-panel p-comfortable">
            <h3 id="servicenow-queued-heading" className="text-title font-semibold">
              ServiceNow ticket queued
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Ticket request</dt>
                <dd className="font-mono text-xs">{latestTicket.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Outbox</dt>
                <dd className="font-mono text-xs">{latestTicket.outbox_id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Table</dt>
                <dd>{latestTicket.table}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Status</dt>
                <dd>{latestTicket.status}</dd>
              </div>
            </dl>
          </section>
        )}
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

      <BreakGlassReconcile />

      <section aria-labelledby="fleet-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="fleet-heading" className="text-title font-semibold">
            Fleet re-issuance
          </h2>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={startFleetReissuance}>
          <label className="grid gap-1 text-sm font-medium">
            Compromised issuer
            <input
              className="ui-input font-mono"
              value={fleetForm.issuer_id}
              onChange={(event) => setFleetForm({ ...fleetForm, issuer_id: event.target.value })}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Batch size
            <input
              className="ui-input"
              type="number"
              min={1}
              max={100}
              value={fleetForm.batch_size ?? ""}
              onChange={(event) =>
                setFleetForm({ ...fleetForm, batch_size: event.target.value === "" ? undefined : Number(event.target.value) || undefined })
              }
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            What happened
            <input
              className="ui-input"
              value={fleetForm.reason ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, reason: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Delivery method
            <input
              className="ui-input"
              value={fleetForm.connector ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, connector: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Deployment target
            <input
              className="ui-input"
              value={fleetForm.target ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, target: event.target.value })}
              placeholder="edge/prod"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Rollback instructions
            <input
              className="ui-input"
              value={fleetForm.rollback_ref ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, rollback_ref: event.target.value })}
              placeholder="restore previous bindings"
            />
          </label>
          <div className="md:col-span-2">
            <Button type="button" onClick={() => void startFleetReissuance()} disabled={runningFleet}>
              <Play className="h-4 w-4" aria-hidden="true" />
              {runningFleet ? "Starting..." : "Start fleet run"}
            </Button>
          </div>
        </form>
        {fleetError && <ErrorState title="Fleet reissuance failed">{fleetError}</ErrorState>}
        {latestFleetRun && (
          <section role="status" aria-labelledby="fleet-progress-heading" className="ui-panel p-comfortable">
            <h3 id="fleet-progress-heading" className="text-title font-semibold">
              Fleet run recorded
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Run</dt>
                <dd className="font-mono text-xs">{latestFleetRun.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Status</dt>
                <dd>{latestFleetRun.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Batches</dt>
                <dd>{latestFleetRun.batch_count}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Revoked</dt>
                <dd>{latestFleetRun.revoked_identity_ids.length}</dd>
              </div>
            </dl>
          </section>
        )}
        {fleetEvidence && (
          <section role="status" aria-labelledby="fleet-evidence-heading" className="ui-panel p-comfortable">
            <h3 id="fleet-evidence-heading" className="text-title font-semibold">
              Fleet evidence exported
            </h3>
            <p className="mt-2 max-w-full truncate font-mono text-xs text-muted-foreground">{fleetEvidence.evidence_bundle}</p>
            <p className="mt-2 text-sm text-muted-foreground">{fleetEvidence.rollback_refs.join(", ") || "No rollback refs recorded."}</p>
          </section>
        )}
        <FleetReissuanceTable runs={fleetRuns} action={fleetAction} onAction={recordFleetAction} />
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
          <Dialog
            open
            onClose={() => setShowBreakGlassHelp(false)}
            titleId="break-glass-help-heading"
            descriptionId="break-glass-help-description"
            initialFocusRef={breakGlassCloseRef}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            overlayClassName="absolute inset-0 bg-black/55"
            panelClassName="ui-panel relative max-h-[calc(100vh-2rem)] w-full max-w-4xl overflow-y-auto p-comfortable"
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 id="break-glass-help-heading" className="text-title font-semibold">
                  Break-glass help
                </h3>
                <p id="break-glass-help-description" className="mt-1 text-sm text-muted-foreground">
                  Emergency issuance requires declaration, quorum, offline issue evidence, verification, expiry, reconciliation, and cleanup.
                </p>
              </div>
              <Button ref={breakGlassCloseRef} type="button" variant="outline" onClick={() => setShowBreakGlassHelp(false)}>
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
          </Dialog>
        )}
      </section>
    </section>
  );
}

function FleetReissuanceTable({
  runs,
  action,
  onAction,
}: {
  runs: FleetReissuanceRun[];
  action: string | null;
  onAction: (kind: "pause" | "resume" | "rollback" | "evidence", run: FleetReissuanceRun) => void;
}) {
  if (runs.length === 0) {
    return <p className="text-sm text-muted-foreground">No fleet reissuance runs have been recorded.</p>;
  }
  return (
    <div className="overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[76rem]">
        <caption className="sr-only">Fleet reissuance runs</caption>
        <thead>
          <tr>
            <th scope="col">Run</th>
            <th scope="col">Issuer</th>
            <th scope="col">Status</th>
            <th scope="col">Scope</th>
            <th scope="col">Batches</th>
            <th scope="col">Failed targets</th>
            <th scope="col">Evidence</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id} className="align-top">
              <td className="font-mono text-xs">{run.id}</td>
              <td className="font-mono text-xs">{run.issuer_id}</td>
              <td>
                <p className="font-medium">{run.status}</p>
                <p className="text-xs text-muted-foreground">{run.phase}</p>
              </td>
              <td>
                <p>{run.affected_identity_ids.length} affected</p>
                <p className="text-xs text-muted-foreground">{run.revoked_identity_ids.length} revoked</p>
              </td>
              <td>
                <p>{run.batch_count} batches</p>
                <p className="text-xs text-muted-foreground">{run.health_gates.map((gate) => `${gate.name}:${gate.status}`).join(", ")}</p>
              </td>
              <td>{run.failed_targets?.length ? run.failed_targets.join(", ") : "none"}</td>
              <td>
                <p className="font-medium">{run.evidence_bundle_format || "unavailable"}</p>
                <p className="max-w-[14rem] truncate font-mono text-xs text-muted-foreground">{run.evidence_bundle || "-"}</p>
              </td>
              <td>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("pause", run)}
                    disabled={action === `pause:${run.id}`}
                    aria-label={`Pause fleet run ${shortId(run.id)}`}
                  >
                    <Pause className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("resume", run)}
                    disabled={action === `resume:${run.id}`}
                    aria-label={`Resume fleet run ${shortId(run.id)}`}
                  >
                    <Play className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("rollback", run)}
                    disabled={action === `rollback:${run.id}`}
                    aria-label={`Rollback fleet run ${shortId(run.id)}`}
                  >
                    <RotateCcw className="h-4 w-4" aria-hidden="true" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => onAction("evidence", run)}
                    disabled={action === `evidence:${run.id}`}
                    aria-label={`Export fleet run ${shortId(run.id)} evidence`}
                  >
                    <Download className="h-4 w-4" aria-hidden="true" />
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
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
