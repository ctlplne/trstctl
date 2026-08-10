import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Activity, Bell, CheckCircle, Play, RotateCcw, Send } from "lucide-react";
import {
  api,
  type ConnectorCatalogItem,
  type FleetReissuanceEvidence,
  type FleetReissuanceRequest,
  type FleetReissuanceRun,
  type GraphImpact,
  type GraphNode,
  type Identity,
  type IncidentExecution,
  type IncidentExecutionRequest,
  type ITSMTicket,
  type NHIInventoryItem,
  type OwnerRemediationQueue,
  type OwnerRemediationRun,
  type OutboxReconciliationConflictList,
  type ResponseIntegrationDispatch,
  type ResponseIntegrationDispatchRequest,
  type RemediationPlaybook,
  type RemediationPlaybookRun,
  type RemediationPlaybookRunRequest,
  type ServiceNowTicketRequest,
} from "@/lib/api";
// This page renders errors in the fallback-prefixed shape ("Could not execute
// incident: <detail>").
import { apiProblemContext as apiProblemMessage } from "@/lib/apiProblem";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { IdentityPicker } from "@/components/IdentityPicker";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { BreakGlassReconcile } from "@/components/breakglass";
import { useTranslation, type I18nContextValue, translateNow } from "@/i18n/I18nProvider";
import { IncidentSeverityBadge, IncidentStepper } from "./incidents/IncidentsPageParts";
import { FleetReissuanceTable } from "./incidents/FleetReissuanceParts";
import { OutboxRecoveryPanel } from "./incidents/OutboxRecoveryPanel";
import { formatDateTime } from "@/i18n/format";
import { describeStatus, type StatusTone } from "@/lib/statusVocab";

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

type ResponseIntegrationForm = {
  title: string;
  summary: string;
  severity: NonNullable<ResponseIntegrationDispatchRequest["severity"]>;
  correlation_id: string;
  evidence_refs: string;
  splunk_endpoint_url: string;
  splunk_token_ref: string;
  jira_endpoint_url: string;
  jira_project_key: string;
  jira_token_ref: string;
  slack_channel: string;
  servicenow_instance_url: string;
  servicenow_token_ref: string;
};
type IncidentWorkspaceTab = "overview" | "execute" | "remediation" | "integrations" | "fleet";

const incidentWorkspaceTabIDs: readonly IncidentWorkspaceTab[] = ["overview", "execute", "remediation", "integrations", "fleet"];

function incidentWorkspaceTabFromSearchParam(value: string | null, hasIdentityDeepLink: boolean): IncidentWorkspaceTab {
  if (incidentWorkspaceTabIDs.includes(value as IncidentWorkspaceTab)) return value as IncidentWorkspaceTab;
  return hasIdentityDeepLink ? "execute" : "overview";
}

const defaultResponseIntegration: ResponseIntegrationForm = {
  title: "",
  summary: "",
  severity: "critical",
  correlation_id: "",
  evidence_refs: "",
  splunk_endpoint_url: "",
  splunk_token_ref: "splunk-response-token",
  jira_endpoint_url: "",
  jira_project_key: "NHI",
  jira_token_ref: "jira-response-token",
  slack_channel: "security-incidents",
  servicenow_instance_url: "",
  servicenow_token_ref: "servicenow-response-token",
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

const defaultPlaybookRun: RemediationPlaybookRunRequest = {
  target_identity_id: "",
  inventory_id: "",
  reason: "",
  connector: "",
  target: "",
  remove_scopes: [],
  recommended_scopes: [],
  rollback_ref: "",
};

/** readRoster loads picker suggestion data on a best-effort basis (C-P1 /
 * DA-10): intake must keep working when a roster read fails or the api
 * function is absent in a partial test double, so failures resolve to null
 * instead of surfacing. Suggestion data is never load-bearing. */
async function readRoster<T>(load: () => Promise<T>): Promise<T | null> {
  try {
    return (await load()) ?? null;
  } catch {
    return null;
  }
}

const breakGlassChecklist = [
  "emergency declaration names incident ID, commander, reason, and expiry",
  "quorum approval records two operators outside the affected owner team",
  "offline issue uses signer ceremony evidence and a short TTL",
  "verification checks fingerprint, chain, scope, and tenant before deployment",
  "reconciliation imports the offline event stream delta after control-plane recovery",
  "post-incident checklist rotates emergency material and closes temporary access",
];

export function Incidents() {
  const { t } = useTranslation();
  // S-C11: /incidents?identity=<id> preselects the affected identity, so the
  // graph and the certificate detail can hand a compromised credential
  // straight into the response form instead of making the operator copy an id
  // between two pages.
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = incidentWorkspaceTabFromSearchParam(searchParams.get("tab"), searchParams.has("identity"));
  const [form, setForm] = useState<IncidentExecutionRequest>(() => {
    const identityID = searchParams.get("identity");
    return identityID ? { ...defaultExecution, identity_id: identityID } : defaultExecution;
  });
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [executions, setExecutions] = useState<IncidentExecution[]>([]);
  const [fleetForm, setFleetForm] = useState<FleetReissuanceRequest>(defaultFleetRun);
  const [fleetRuns, setFleetRuns] = useState<FleetReissuanceRun[]>([]);
  const [playbookForm, setPlaybookForm] = useState<RemediationPlaybookRunRequest>(defaultPlaybookRun);
  const [responseForm, setResponseForm] = useState<ResponseIntegrationForm>(defaultResponseIntegration);
  const [playbooks, setPlaybooks] = useState<RemediationPlaybook[]>([]);
  const [playbookRuns, setPlaybookRuns] = useState<RemediationPlaybookRun[]>([]);
  const [ownerRemediation, setOwnerRemediation] = useState<OwnerRemediationQueue | null>(null);
  const [removeScopesText, setRemoveScopesText] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [executeError, setExecuteError] = useState<string | null>(null);
  const [fleetError, setFleetError] = useState<string | null>(null);
  const [playbookError, setPlaybookError] = useState<string | null>(null);
  const [ownerRemediationError, setOwnerRemediationError] = useState<string | null>(null);
  const [responseError, setResponseError] = useState<string | null>(null);
  const [ticketForm, setTicketForm] = useState<ServiceNowTicketRequest>(defaultServiceNowTicket);
  const [ticketError, setTicketError] = useState<string | null>(null);
  const [latestExecution, setLatestExecution] = useState<IncidentExecution | null>(null);
  const [latestFleetRun, setLatestFleetRun] = useState<FleetReissuanceRun | null>(null);
  const [fleetEvidence, setFleetEvidence] = useState<FleetReissuanceEvidence | null>(null);
  const [latestPlaybookRun, setLatestPlaybookRun] = useState<RemediationPlaybookRun | null>(null);
  const [latestOwnerRemediationRun, setLatestOwnerRemediationRun] = useState<OwnerRemediationRun | null>(null);
  const [latestResponseDispatch, setLatestResponseDispatch] = useState<ResponseIntegrationDispatch | null>(null);
  const [latestTicket, setLatestTicket] = useState<ITSMTicket | null>(null);
  const [showBreakGlassHelp, setShowBreakGlassHelp] = useState(false);
  const breakGlassCloseRef = useRef<HTMLButtonElement>(null);
  const [loading, setLoading] = useState(true);
  const [previewing, setPreviewing] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [runningFleet, setRunningFleet] = useState(false);
  const [runningPlaybook, setRunningPlaybook] = useState(false);
  const [acceptingOwnerAction, setAcceptingOwnerAction] = useState<string | null>(null);
  const [dispatchingResponse, setDispatchingResponse] = useState(false);
  const [fleetAction, setFleetAction] = useState<string | null>(null);
  const [ticketing, setTicketing] = useState(false);
  const [evidenceRuns, setEvidenceRuns] = useState<RemediationPlaybookRun[] | null>(null);
  const [evidenceRunsCursor, setEvidenceRunsCursor] = useState<string | undefined>(undefined);
  const [evidenceRunsLoadingMore, setEvidenceRunsLoadingMore] = useState(false);
  const [evidenceRunsError, setEvidenceRunsError] = useState<string | null>(null);
  const [evidenceRunDetail, setEvidenceRunDetail] = useState<RemediationPlaybookRun | null>(null);
  const [ownerQueueEvidence, setOwnerQueueEvidence] = useState<OwnerRemediationQueue | null>(null);
  const [outboxRecovery, setOutboxRecovery] = useState<OutboxReconciliationConflictList | null>(null);
  // C-P1 (DA-10): picker rosters — the identities, connector vocabulary, and
  // NHI inventory the rest of the console already loads elsewhere.
  const [identityRoster, setIdentityRoster] = useState<Identity[]>([]);
  const [connectorRoster, setConnectorRoster] = useState<ConnectorCatalogItem[]>([]);
  const [inventoryRoster, setInventoryRoster] = useState<NHIInventoryItem[]>([]);

  useEffect(() => {
    let active = true;
    void readRoster(() => api.identities()).then((items) => {
      if (active && items) setIdentityRoster(items);
    });
    void readRoster(() => api.connectorCatalog()).then((catalog) => {
      if (active && catalog?.items) setConnectorRoster(catalog.items);
    });
    void readRoster(() => api.nhiInventory()).then((inventory) => {
      if (active && inventory?.items) setInventoryRoster(inventory.items);
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    void readRoster(() => api.outboxReconciliationConflicts()).then((conflicts) => {
      if (active && conflicts && Array.isArray(conflicts.items) && typeof conflicts.guidance === "string") {
        setOutboxRecovery(conflicts);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      api.incidentExecutions({ limit: 10 }),
      api.fleetReissuanceRuns({ limit: 10 }),
      api.remediationPlaybooks(),
      api.remediationPlaybookRuns({ limit: 10 }),
      api.ownerRemediationActions(),
    ])
      .then(([executionResult, fleetResult, playbookCatalog, playbookRunResult, ownerQueue]) => {
        if (!active) return;
        setExecutions(executionResult.items ?? []);
        setFleetRuns(fleetResult.items ?? []);
        setPlaybooks(playbookCatalog.items ?? []);
        setPlaybookRuns(playbookRunResult.items ?? []);
        setOwnerRemediation(ownerQueue);
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

  useEffect(() => {
    let active = true;
    Promise.resolve()
      .then(() => api.remediationPlaybookRuns({ limit: 20 }))
      .then((page) => {
        if (!active) return;
        setEvidenceRuns(page.items ?? []);
        setEvidenceRunsCursor(page.next_cursor);
      })
      .catch(() => null);
    Promise.resolve()
      .then(() => api.remediationOwnerActions())
      .then((queue) => {
        if (active) setOwnerQueueEvidence(queue);
      })
      .catch(() => null);
    return () => {
      active = false;
    };
  }, []);

  async function loadMoreEvidenceRuns() {
    if (!evidenceRunsCursor) return;
    setEvidenceRunsLoadingMore(true);
    setEvidenceRunsError(null);
    try {
      const page = await api.remediationPlaybookRuns({ limit: 20, cursor: evidenceRunsCursor });
      setEvidenceRuns((current) => [...(current ?? []), ...(page.items ?? [])]);
      setEvidenceRunsCursor(page.next_cursor);
    } catch (err) {
      setEvidenceRunsError(apiProblemMessage(err, "Could not load more playbook runs"));
    } finally {
      setEvidenceRunsLoadingMore(false);
    }
  }

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

  async function runRightSizePlaybook(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const targetIdentity = playbookForm.target_identity_id?.trim() ?? "";
    const inventoryID = playbookForm.inventory_id?.trim() ?? "";
    if (!targetIdentity && !inventoryID) {
      setPlaybookError(t("incidents.playbooks.requiredTarget"));
      return;
    }
    setRunningPlaybook(true);
    setPlaybookError(null);
    setLatestPlaybookRun(null);
    try {
      const result = await api.runRemediationPlaybook("nhi-right-size", {
        ...playbookForm,
        target_identity_id: targetIdentity,
        inventory_id: inventoryID,
        reason: playbookForm.reason?.trim() || t("incidents.playbooks.defaultReason"),
        connector: playbookForm.connector?.trim() ?? "",
        target: playbookForm.target?.trim() ?? "",
        remove_scopes: splitList(removeScopesText),
        rollback_ref: playbookForm.rollback_ref?.trim() ?? "",
      });
      setPlaybookRuns((prev) => [result, ...prev.filter((item) => item.id !== result.id)].slice(0, 10));
      setLatestPlaybookRun(result);
    } catch (err) {
      setPlaybookError(apiProblemMessage(err, t("incidents.playbooks.loadError")));
    } finally {
      setRunningPlaybook(false);
    }
  }

  async function acceptOwnerRemediationAction(action: OwnerRemediationQueue["items"][number]) {
    setAcceptingOwnerAction(action.id);
    setOwnerRemediationError(null);
    setLatestOwnerRemediationRun(null);
    try {
      const result = await api.acceptOwnerRemediationAction(action.id, {
        reason: action.reason,
        connector: action.connector,
        target: action.target,
        remove_scopes: action.remove_scopes ?? [],
        recommended_scopes: action.recommended_scopes ?? [],
        rollback_ref: action.rollback_ref,
      });
      setLatestOwnerRemediationRun(result);
      setOwnerRemediation((prev) => (prev ? markOwnerActionAccepted(prev, result) : prev));
      setPlaybookRuns((prev) => [result.remediation_run, ...prev.filter((item) => item.id !== result.remediation_run.id)].slice(0, 10));
    } catch (err) {
      setOwnerRemediationError(apiProblemMessage(err, t("incidents.ownerRemediation.loadError")));
    } finally {
      setAcceptingOwnerAction(null);
    }
  }

  async function dispatchResponseIntegrations(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!responseForm.title.trim()) {
      setResponseError(t("incidents.response.titleRequired"));
      return;
    }
    if (!responseForm.splunk_endpoint_url.trim() || !responseForm.jira_endpoint_url.trim() || !responseForm.servicenow_instance_url.trim()) {
      setResponseError(t("incidents.response.providersRequired"));
      return;
    }
    setDispatchingResponse(true);
    setResponseError(null);
    setLatestResponseDispatch(null);
    try {
      const result = await api.dispatchResponseIntegrations({
        title: responseForm.title.trim(),
        summary: responseForm.summary.trim(),
        severity: responseForm.severity,
        correlation_id: responseForm.correlation_id.trim(),
        evidence_refs: splitList(responseForm.evidence_refs),
        destinations: [
          {
            id: "splunk",
            provider: "splunk",
            endpoint_url: responseForm.splunk_endpoint_url.trim(),
            token_ref: responseForm.splunk_token_ref.trim(),
          },
          {
            id: "jira",
            provider: "jira",
            endpoint_url: responseForm.jira_endpoint_url.trim(),
            project_key: responseForm.jira_project_key.trim(),
            issue_type: "Task",
            token_ref: responseForm.jira_token_ref.trim(),
          },
          {
            id: "slack",
            provider: "slack",
            channel: responseForm.slack_channel.trim(),
          },
          {
            id: "servicenow",
            provider: "servicenow",
            instance_url: responseForm.servicenow_instance_url.trim(),
            table: "incident",
            token_ref: responseForm.servicenow_token_ref.trim(),
          },
        ],
      });
      setLatestResponseDispatch(result);
    } catch (err) {
      setResponseError(apiProblemMessage(err, t("incidents.response.loadError")));
    } finally {
      setDispatchingResponse(false);
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
      const input =
        kind === "rollback" ? { reason: "operator rollback", rollback_ref: "restore previous credential bindings" } : { reason: `operator ${kind}` };
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

  function selectTab(next: string) {
    const value = incidentWorkspaceTabFromSearchParam(next, false);
    setSearchParams(
      (current) => {
        const nextParams = new URLSearchParams(current);
        if (value === "overview") {
          nextParams.delete("tab");
        } else {
          nextParams.set("tab", value);
        }
        return nextParams;
      },
      { replace: true },
    );
  }

  return (
    <section aria-labelledby="incidents-heading" className="grid gap-6">
      <PageHeader
        titleId="incidents-heading"
        title={translateNow("source.incidents.bfe8689315")}
        description="Respond to a compromised credential: see what it can reach (blast radius), issue a replacement before revoking, push it out through connectors, roll back failed targets, and capture a tamper-evident audit bundle."
        actions={
          <>
            <Link
              to="/operations"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
            >
              <Activity className="h-4 w-4" aria-hidden="true" />
              {t("nav.item.operations")}
            </Link>
            <Link
              to="/notifications"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
            >
              <Bell className="h-4 w-4" aria-hidden="true" />
              {t("nav.item.notifications")}
            </Link>
          </>
        }
      />

      <PageTabs
        tabs={[
          { id: "overview", label: t("incidents.workspace.tabs.overview") },
          { id: "execute", label: t("incidents.workspace.tabs.execute") },
          { id: "remediation", label: t("incidents.workspace.tabs.remediation") },
          { id: "integrations", label: t("incidents.workspace.tabs.integrations") },
          { id: "fleet", label: t("incidents.workspace.tabs.fleet") },
        ]}
        active={tab}
        onChange={selectTab}
        ariaLabel={t("incidents.workspace.label")}
        idPrefix="incidents"
      />

      <section {...tabPanelProps("incidents", "execute")} className={tab === "execute" ? "grid gap-4 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="execute-heading" className="text-title font-semibold">
            {translateNow("source.credential.compromise.execution.3cfb067780")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.incident.execution.issues.and.deploys.a.re.c00d70d3f5")}</p>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={executeIncident}>
          <label className="grid gap-1 text-sm font-medium" htmlFor="incident-affected-identity">
            {translateNow("source.affected.identity.031ba2eb6f")}
            <IdentityPicker
              id="incident-affected-identity"
              value={form.identity_id}
              onChange={(identityId) => setForm({ ...form, identity_id: identityId })}
              identities={identityRoster}
              placeholder={t("incidents.picker.identityHint")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.what.happened.483bd49023")}
            <input className="ui-input" value={form.reason ?? ""} onChange={(event) => setForm({ ...form, reason: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.replacement.identity.name.503334612e")}
            <input
              className="ui-input"
              value={form.replacement_name ?? ""}
              onChange={(event) => setForm({ ...form, replacement_name: event.target.value })}
              placeholder={translateNow("source.optional.ec91fdd925")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.delivery.method.26b6ab1b68")}
            <input
              className="ui-input"
              value={form.connector ?? ""}
              onChange={(event) => setForm({ ...form, connector: event.target.value })}
              list="incident-delivery-method-options"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.deployment.target.5b274e18ab")}
            <input
              className="ui-input"
              value={form.target ?? ""}
              onChange={(event) => setForm({ ...form, target: event.target.value })}
              placeholder={translateNow("source.edge.prod.payments.178b58c24e")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.rollback.instructions.8fb506160a")}
            <input
              className="ui-input"
              value={form.delivery_rollback_ref ?? ""}
              onChange={(event) => setForm({ ...form, delivery_rollback_ref: event.target.value })}
              placeholder={translateNow("source.restore.previous.binding.3e3a4f657d")}
            />
          </label>
          <div className="flex flex-wrap gap-2 md:col-span-2">
            <Button type="button" variant="outline" onClick={previewBlastRadius} disabled={previewing}>
              {previewing ? translateNow("source.loading.preview.c02130fa90") : translateNow("source.preview.blast.radius.925ac72409")}
            </Button>
            <Button type="submit" disabled={executing}>
              {executing ? translateNow("source.executing.535a363214") : translateNow("source.execute.incident.c74e8b45e9")}
            </Button>
          </div>
        </form>
        {/* Shared delivery-method vocabulary (C-P1): one served connector
            catalog feeds every delivery-method field on this page. */}
        <datalist id="incident-delivery-method-options">
          {connectorRoster.map((item) => (
            <option key={item.name} value={item.name}>
              {translateNow("source.value1.value2.7c639bc99b", { value1: item.kind, value2: item.delivery_mode })}
            </option>
          ))}
        </datalist>
        {previewError && <ErrorState title={translateNow("source.blast.radius.preview.unavailable.00a241de01")}>{previewError}</ErrorState>}
        {executeError && <ErrorState title={translateNow("source.incident.execution.failed.70db66b277")}>{executeError}</ErrorState>}
        {latestExecution && (
          <section role="status" aria-labelledby="incident-progress-heading" className="ui-panel p-comfortable">
            <h3 id="incident-progress-heading" className="text-title font-semibold">
              {translateNow("source.incident.execution.recorded.2ea0b1ce57")}
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-3">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.execution.a45cd4bd09")}</dt>
                <dd className="font-mono text-xs">{latestExecution.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
                <dd>{latestExecution.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.current.phase.44c03cecc0")}</dt>
                <dd className="break-all font-mono text-xs">{latestExecution.phase}</dd>
              </div>
            </dl>
            {/* S-C17: the phase string is precise for a log and unreadable as
                progress; the stepper reads the same record's concrete fields. */}
            <IncidentStepper execution={latestExecution} />
          </section>
        )}
        {impact && <BlastRadiusPreview impact={impact} />}
      </section>

      <section {...tabPanelProps("incidents", "remediation")} className={tab === "remediation" ? "grid gap-4 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="playbooks-heading" className="text-title font-semibold">
            {t("incidents.playbooks.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("incidents.playbooks.description")}</p>
        </div>
        <div className="grid gap-2 md:grid-cols-3">
          {playbooks.map((item) => (
            <div key={item.id} className="rounded-panel border border-border p-3">
              <p className="font-medium">{item.name}</p>
              <p className="mt-1 text-xs text-muted-foreground">{item.external_effect}</p>
            </div>
          ))}
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={runRightSizePlaybook}>
          <label className="grid gap-1 text-sm font-medium" htmlFor="playbook-target-identity">
            {t("incidents.playbooks.targetIdentity")}
            <IdentityPicker
              id="playbook-target-identity"
              value={playbookForm.target_identity_id ?? ""}
              onChange={(identityId) => setPlaybookForm({ ...playbookForm, target_identity_id: identityId })}
              identities={identityRoster}
              placeholder={t("incidents.picker.identityHint")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.playbooks.inventoryId")}
            <input
              className="ui-input"
              value={playbookForm.inventory_id ?? ""}
              onChange={(event) => setPlaybookForm({ ...playbookForm, inventory_id: event.target.value })}
              placeholder={t("incidents.playbooks.inventoryPlaceholder")}
              list="incident-inventory-options"
            />
            {/* label attribute, not text children — this datalist lives inside
                the field's <label> (see IdentityPicker). */}
            <datalist id="incident-inventory-options">
              {inventoryRoster.map((item) => (
                <option key={item.id} value={item.id} label={`${item.display_name} (${item.kind})`} />
              ))}
            </datalist>
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.playbooks.connector")}
            <input
              className="ui-input"
              value={playbookForm.connector ?? ""}
              onChange={(event) => setPlaybookForm({ ...playbookForm, connector: event.target.value })}
              placeholder={t("incidents.playbooks.connectorPlaceholder")}
              list="incident-delivery-method-options"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.playbooks.providerTarget")}
            <input
              className="ui-input"
              value={playbookForm.target ?? ""}
              onChange={(event) => setPlaybookForm({ ...playbookForm, target: event.target.value })}
              placeholder={t("incidents.playbooks.providerTargetPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.playbooks.removeScopes")}
            <input
              className="ui-input"
              value={removeScopesText}
              onChange={(event) => setRemoveScopesText(event.target.value)}
              placeholder={t("incidents.playbooks.removeScopesPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.playbooks.rollbackReference")}
            <input
              className="ui-input"
              value={playbookForm.rollback_ref ?? ""}
              onChange={(event) => setPlaybookForm({ ...playbookForm, rollback_ref: event.target.value })}
              placeholder={t("incidents.playbooks.rollbackPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium md:col-span-2">
            {t("incidents.playbooks.reason")}
            <input
              className="ui-input"
              value={playbookForm.reason ?? ""}
              onChange={(event) => setPlaybookForm({ ...playbookForm, reason: event.target.value })}
            />
          </label>
          <div className="md:col-span-2">
            <Button type="submit" disabled={runningPlaybook}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              {runningPlaybook ? t("incidents.playbooks.running") : t("incidents.playbooks.runRightSize")}
            </Button>
          </div>
        </form>
        {playbookError && <ErrorState title={t("incidents.playbooks.failedTitle")}>{playbookError}</ErrorState>}
        {latestPlaybookRun && (
          <section role="status" aria-labelledby="playbook-progress-heading" className="ui-panel p-comfortable">
            <h3 id="playbook-progress-heading" className="text-title font-semibold">
              {t("incidents.playbooks.recorded")}
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.playbooks.run")}</dt>
                <dd className="font-mono text-xs">{latestPlaybookRun.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.playbooks.playbook")}</dt>
                <dd>{latestPlaybookRun.playbook_id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.playbooks.status")}</dt>
                <dd>{latestPlaybookRun.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.playbooks.externalIntent")}</dt>
                <dd>{latestPlaybookRun.connector_delivery?.destination ?? latestPlaybookRun.connector ?? latestPlaybookRun.status}</dd>
              </div>
            </dl>
          </section>
        )}
      </section>

      <section aria-labelledby="owner-remediation-heading" className={tab === "remediation" ? "grid gap-4 border-y border-border py-4" : "hidden"}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="owner-remediation-heading" className="text-title font-semibold">
              {t("incidents.ownerRemediation.heading")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("incidents.ownerRemediation.description")}</p>
          </div>
          {ownerRemediation && (
            <p className="text-sm text-muted-foreground">
              {t("incidents.ownerRemediation.summary", {
                open: ownerRemediation.summary.open,
                accepted: ownerRemediation.summary.accepted,
              })}
            </p>
          )}
        </div>
        {ownerRemediationError && <ErrorState title={t("incidents.ownerRemediation.failedTitle")}>{ownerRemediationError}</ErrorState>}
        {ownerRemediation == null ? (
          <LoadingState>{t("incidents.ownerRemediation.loading")}</LoadingState>
        ) : ownerRemediation.items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("incidents.ownerRemediation.empty")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <caption className="sr-only">{t("incidents.ownerRemediation.caption")}</caption>
              <thead className="text-xs uppercase text-muted-foreground">
                <tr>
                  <th scope="col" className="py-2 pr-4">
                    {t("incidents.ownerRemediation.identity")}
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    {t("incidents.ownerRemediation.severity")}
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    {t("incidents.ownerRemediation.recommendation")}
                  </th>
                  <th scope="col" className="py-2 pr-4">
                    {t("incidents.ownerRemediation.status")}
                  </th>
                  <th scope="col" className="py-2">
                    {t("incidents.ownerRemediation.action")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {ownerRemediation.items.map((action) => (
                  <tr key={action.id} className="border-t border-border">
                    <td className="py-2 pr-4">
                      <div className="font-medium">{action.display_name}</div>
                      <div className="font-mono text-xs text-muted-foreground">{action.inventory_id}</div>
                    </td>
                    <td className="py-2 pr-4">
                      <IncidentSeverityBadge severity={action.severity} />
                    </td>
                    <td className="max-w-xl py-2 pr-4 text-muted-foreground">{action.recommendation}</td>
                    <td className="py-2 pr-4">{action.status}</td>
                    <td className="py-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={action.status === "accepted" || acceptingOwnerAction === action.id}
                        onClick={() => void acceptOwnerRemediationAction(action)}
                      >
                        <CheckCircle className="h-4 w-4" aria-hidden="true" />
                        {action.status === "accepted"
                          ? t("incidents.ownerRemediation.accepted")
                          : acceptingOwnerAction === action.id
                            ? t("incidents.ownerRemediation.accepting")
                            : t("incidents.ownerRemediation.accept")}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {latestOwnerRemediationRun && (
          <section role="status" aria-labelledby="owner-remediation-recorded-heading" className="ui-panel p-comfortable">
            <h3 id="owner-remediation-recorded-heading" className="text-title font-semibold">
              {t("incidents.ownerRemediation.recorded")}
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.ownerRemediation.run")}</dt>
                <dd className="font-mono text-xs">{latestOwnerRemediationRun.remediation_run.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.ownerRemediation.playbook")}</dt>
                <dd>{latestOwnerRemediationRun.remediation_run.playbook_id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.ownerRemediation.status")}</dt>
                <dd>{latestOwnerRemediationRun.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.ownerRemediation.externalIntent")}</dt>
                <dd>{latestOwnerRemediationRun.remediation_run.connector_delivery?.destination ?? latestOwnerRemediationRun.remediation_run.connector}</dd>
              </div>
            </dl>
          </section>
        )}
      </section>

      <section {...tabPanelProps("incidents", "integrations")} className={tab === "integrations" ? "grid gap-4 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="response-integrations-heading" className="text-title font-semibold">
            {t("incidents.response.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("incidents.response.description")}</p>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={dispatchResponseIntegrations}>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.title")}
            <input
              className="ui-input"
              value={responseForm.title}
              onChange={(event) => setResponseForm({ ...responseForm, title: event.target.value })}
              placeholder={t("incidents.response.titlePlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.severity")}
            <select
              className="ui-input"
              value={responseForm.severity}
              onChange={(event) => setResponseForm({ ...responseForm, severity: event.target.value as ResponseIntegrationForm["severity"] })}
            >
              <option value="critical">{t("incidents.response.severityCritical")}</option>
              <option value="warning">{t("incidents.response.severityWarning")}</option>
              <option value="informational">{t("incidents.response.severityInformational")}</option>
              <option value="low">{t("incidents.response.severityLow")}</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium md:col-span-2">
            {t("incidents.response.summary")}
            <textarea
              className="ui-input min-h-20"
              value={responseForm.summary}
              onChange={(event) => setResponseForm({ ...responseForm, summary: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.correlation")}
            <input
              className="ui-input"
              value={responseForm.correlation_id}
              onChange={(event) => setResponseForm({ ...responseForm, correlation_id: event.target.value })}
              placeholder={t("incidents.response.optionalPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.evidenceRefs")}
            <input
              className="ui-input"
              value={responseForm.evidence_refs}
              onChange={(event) => setResponseForm({ ...responseForm, evidence_refs: event.target.value })}
              placeholder={t("incidents.response.evidencePlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.splunkEndpoint")}
            <input
              className="ui-input"
              value={responseForm.splunk_endpoint_url}
              onChange={(event) => setResponseForm({ ...responseForm, splunk_endpoint_url: event.target.value })}
              placeholder={t("incidents.response.splunkPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.splunkToken")}
            <input
              className="ui-input font-mono"
              value={responseForm.splunk_token_ref}
              onChange={(event) => setResponseForm({ ...responseForm, splunk_token_ref: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.jiraEndpoint")}
            <input
              className="ui-input"
              value={responseForm.jira_endpoint_url}
              onChange={(event) => setResponseForm({ ...responseForm, jira_endpoint_url: event.target.value })}
              placeholder={t("incidents.response.jiraPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.jiraProject")}
            <input
              className="ui-input"
              value={responseForm.jira_project_key}
              onChange={(event) => setResponseForm({ ...responseForm, jira_project_key: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.jiraToken")}
            <input
              className="ui-input font-mono"
              value={responseForm.jira_token_ref}
              onChange={(event) => setResponseForm({ ...responseForm, jira_token_ref: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.slackRoute")}
            <input
              className="ui-input"
              value={responseForm.slack_channel}
              onChange={(event) => setResponseForm({ ...responseForm, slack_channel: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.servicenowInstance")}
            <input
              className="ui-input"
              value={responseForm.servicenow_instance_url}
              onChange={(event) => setResponseForm({ ...responseForm, servicenow_instance_url: event.target.value })}
              placeholder={t("incidents.response.servicenowPlaceholder")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("incidents.response.servicenowToken")}
            <input
              className="ui-input font-mono"
              value={responseForm.servicenow_token_ref}
              onChange={(event) => setResponseForm({ ...responseForm, servicenow_token_ref: event.target.value })}
            />
          </label>
          <div className="md:col-span-2">
            <Button type="submit" disabled={dispatchingResponse}>
              <Send className="h-4 w-4" aria-hidden="true" />
              {dispatchingResponse ? t("incidents.response.dispatching") : t("incidents.response.dispatch")}
            </Button>
          </div>
        </form>
        {responseError && <ErrorState title={t("incidents.response.failedTitle")}>{responseError}</ErrorState>}
        {latestResponseDispatch && (
          <section role="status" aria-labelledby="response-dispatch-queued-heading" className="ui-panel p-comfortable">
            <h3 id="response-dispatch-queued-heading" className="text-title font-semibold">
              {t("incidents.response.queued")}
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-3">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.response.dispatchId")}</dt>
                <dd className="font-mono text-xs">{latestResponseDispatch.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.response.status")}</dt>
                <dd>{latestResponseDispatch.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{t("incidents.response.idempotency")}</dt>
                <dd className="break-all font-mono text-xs">{latestResponseDispatch.idempotency_key}</dd>
              </div>
            </dl>
            <ResponseIntegrationDestinationTable dispatch={latestResponseDispatch} t={t} />
          </section>
        )}
      </section>

      <section aria-labelledby="servicenow-heading" className={tab === "integrations" ? "grid gap-4 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="servicenow-heading" className="text-title font-semibold">
            {translateNow("source.servicenow.itsm.workflow.9ebb1f9288")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.queue.a.servicenow.table.api.ticket.throug.0df778f34b")}</p>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={queueServiceNowTicket}>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.servicenow.instance.0da2a11806")}
            <input
              className="ui-input"
              value={ticketForm.instance_url}
              onChange={(event) => setTicketForm({ ...ticketForm, instance_url: event.target.value })}
              placeholder={translateNow("source.https.example.service.now.com.1d3417de64")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.ticket.table.bfbfbeffa9")}
            <select
              className="ui-input"
              value={ticketForm.table ?? "incident"}
              onChange={(event) => setTicketForm({ ...ticketForm, table: event.target.value as ServiceNowTicketRequest["table"] })}
            >
              <option value="incident">{translateNow("source.incident.36a606d488")}</option>
              <option value="change_request">{translateNow("source.change.request.6946efe81c")}</option>
              <option value="sc_task">{translateNow("source.service.catalog.task.6c47887640")}</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.token.reference.f98f4b9710")}
            <input
              className="ui-input font-mono"
              value={ticketForm.token_ref}
              onChange={(event) => setTicketForm({ ...ticketForm, token_ref: event.target.value })}
              placeholder={translateNow("source.servicenow.ticket.token.77e4d20179")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.ticket.summary.aafe32b23d")}
            <input
              className="ui-input"
              value={ticketForm.short_description}
              onChange={(event) => setTicketForm({ ...ticketForm, short_description: event.target.value })}
              placeholder={translateNow("source.rotate.exposed.tls.private.key.8868cb8fa7")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium md:col-span-2">
            {translateNow("source.ticket.description.a277a242bf")}
            <textarea
              className="ui-input min-h-24"
              value={ticketForm.description ?? ""}
              onChange={(event) => setTicketForm({ ...ticketForm, description: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.category.292c06f004")}
            <input
              className="ui-input"
              value={ticketForm.category ?? ""}
              onChange={(event) => setTicketForm({ ...ticketForm, category: event.target.value })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.urgency.03d37e9a53")}
            <input className="ui-input" value={ticketForm.urgency ?? ""} onChange={(event) => setTicketForm({ ...ticketForm, urgency: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.impact.d1f23f0d13")}
            <input className="ui-input" value={ticketForm.impact ?? ""} onChange={(event) => setTicketForm({ ...ticketForm, impact: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.correlation.id.c267c186e8")}
            <input
              className="ui-input"
              value={ticketForm.correlation_id ?? ""}
              onChange={(event) => setTicketForm({ ...ticketForm, correlation_id: event.target.value })}
              placeholder={translateNow("source.optional.ec91fdd925")}
            />
          </label>
          <div className="md:col-span-2">
            <Button type="submit" disabled={ticketing}>
              {ticketing ? translateNow("source.queueing.d6e3ff1af9") : translateNow("source.queue.servicenow.ticket.f2988e9681")}
            </Button>
          </div>
        </form>
        {ticketError && <ErrorState title={translateNow("source.servicenow.ticket.failed.75f1ff3ff8")}>{ticketError}</ErrorState>}
        {latestTicket && (
          <section role="status" aria-labelledby="servicenow-queued-heading" className="ui-panel p-comfortable">
            <h3 id="servicenow-queued-heading" className="text-title font-semibold">
              {translateNow("source.servicenow.ticket.queued.aaa6fd780e")}
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.ticket.request.17c5294c85")}</dt>
                <dd className="font-mono text-xs">{latestTicket.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.outbox.49668afa92")}</dt>
                <dd className="font-mono text-xs">{latestTicket.outbox_id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.table.16d1c9050a")}</dt>
                <dd>{latestTicket.table}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
                <dd>{latestTicket.status}</dd>
              </div>
            </dl>
          </section>
        )}
      </section>

      <section {...tabPanelProps("incidents", "overview")} className={tab === "overview" ? "ui-panel p-comfortable" : "hidden"}>
        <h2 id="incidents-overview-heading" className="text-title font-semibold">
          {t("incidents.workspace.overviewHeading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          {t("incidents.workspace.overviewSummary", { executions: executions.length, runs: playbookRuns.length })}
        </p>
      </section>
      <section aria-labelledby="evidence-heading" className={tab === "overview" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="evidence-heading" className="text-title font-semibold">
            {translateNow("source.execution.evidence.81ad27c5fa")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.each.execution.or.playbook.run.is.a.projec.9af41ecb88")}</p>
        </div>
        {loading && <LoadingState>{translateNow("source.loading.incident.execution.evidence.83ace6ca73")}</LoadingState>}
        {loadError && <ErrorState title={translateNow("source.incident.evidence.unavailable.248e285efe")}>{loadError}</ErrorState>}
        {!loading && !loadError && (
          <>
            <IncidentExecutionTable executions={executions} />
            <RemediationPlaybookRunTable runs={playbookRuns} t={t} />
          </>
        )}
      </section>

      {tab === "overview" && outboxRecovery && <OutboxRecoveryPanel conflicts={outboxRecovery} />}

      {(evidenceRuns || ownerQueueEvidence) && (
        <section aria-labelledby="remediation-evidence-heading" className={tab === "overview" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
          <div>
            <h2 id="remediation-evidence-heading" className="text-title font-semibold">
              {t("parity.remediationEvidence_5174c6")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("parity.recordedPlaybookRunsWithTheirConnector_bffffe")}</p>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            {evidenceRuns && (
              <div className="grid content-start gap-3">
                <h3 className="text-body font-semibold">{t("parity.playbookRuns_da379d")}</h3>
                {evidenceRunsError && <ErrorState title={t("parity.playbookRunHistoryUnavailable_8452d8")}>{evidenceRunsError}</ErrorState>}
                <DataGrid
                  ariaLabel="Remediation playbook runs"
                  rows={evidenceRuns}
                  columns={evidenceRunColumns}
                  getRowId={(run) => run.id}
                  onRowOpen={(run) => setEvidenceRunDetail(run)}
                  rowActionLabel={() => "Details"}
                  pagination={
                    evidenceRunsCursor ? (
                      <div>
                        <Button type="button" size="sm" variant="outline" disabled={evidenceRunsLoadingMore} onClick={() => void loadMoreEvidenceRuns()}>
                          {evidenceRunsLoadingMore ? translateNow("source.loading.more.runs.89d0b6b736") : translateNow("source.load.more.runs.627fcc156a")}
                        </Button>
                      </div>
                    ) : undefined
                  }
                />
              </div>
            )}
            {ownerQueueEvidence && <OwnerRemediationQueuePanel queue={ownerQueueEvidence} />}
          </div>
        </section>
      )}

      <div className={tab === "fleet" ? undefined : "hidden"}>
        <BreakGlassReconcile />
      </div>

      <section {...tabPanelProps("incidents", "fleet")} className={tab === "fleet" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="fleet-heading" className="text-title font-semibold">
            {translateNow("source.fleet.re.issuance.fa35f7921e")}
          </h2>
        </div>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={startFleetReissuance}>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.compromised.issuer.18ef83eabb")}
            <input
              className="ui-input font-mono"
              value={fleetForm.issuer_id}
              onChange={(event) => setFleetForm({ ...fleetForm, issuer_id: event.target.value })}
              placeholder="00000000-0000-0000-0000-000000000000"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.batch.size.8cfe32a041")}
            <input
              className="ui-input"
              type="number"
              min={1}
              max={100}
              value={fleetForm.batch_size ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, batch_size: event.target.value === "" ? undefined : Number(event.target.value) || undefined })}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.what.happened.483bd49023")}
            <input className="ui-input" value={fleetForm.reason ?? ""} onChange={(event) => setFleetForm({ ...fleetForm, reason: event.target.value })} />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.delivery.method.26b6ab1b68")}
            <input
              className="ui-input"
              value={fleetForm.connector ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, connector: event.target.value })}
              list="incident-delivery-method-options"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.deployment.target.5b274e18ab")}
            <input
              className="ui-input"
              value={fleetForm.target ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, target: event.target.value })}
              placeholder={translateNow("source.edge.prod.79b3e5ef21")}
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {translateNow("source.rollback.instructions.8fb506160a")}
            <input
              className="ui-input"
              value={fleetForm.rollback_ref ?? ""}
              onChange={(event) => setFleetForm({ ...fleetForm, rollback_ref: event.target.value })}
              placeholder={translateNow("source.restore.previous.bindings.ec8f60be98")}
            />
          </label>
          <div className="md:col-span-2">
            <Button type="button" onClick={() => void startFleetReissuance()} disabled={runningFleet}>
              <Play className="h-4 w-4" aria-hidden="true" />
              {runningFleet ? translateNow("source.starting.82b93630a9") : translateNow("source.start.fleet.run.140963492c")}
            </Button>
          </div>
        </form>
        {fleetError && <ErrorState title={translateNow("source.fleet.reissuance.failed.734d656156")}>{fleetError}</ErrorState>}
        {latestFleetRun && (
          <section role="status" aria-labelledby="fleet-progress-heading" className="ui-panel p-comfortable">
            <h3 id="fleet-progress-heading" className="text-title font-semibold">
              {translateNow("source.fleet.run.recorded.ff2d7b78ff")}
            </h3>
            <dl className="mt-3 grid gap-2 md:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.run.00d60e31a4")}</dt>
                <dd className="font-mono text-xs">{latestFleetRun.id}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
                <dd>{latestFleetRun.status}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.batches.56a8df948f")}</dt>
                <dd>{latestFleetRun.batch_count}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-muted-foreground">{translateNow("source.revoked.f6f738d043")}</dt>
                <dd>{latestFleetRun.revoked_identity_ids.length}</dd>
              </div>
            </dl>
          </section>
        )}
        {fleetEvidence && (
          <section role="status" aria-labelledby="fleet-evidence-heading" className="ui-panel p-comfortable">
            <h3 id="fleet-evidence-heading" className="text-title font-semibold">
              {translateNow("source.fleet.evidence.exported.eecc6a3c77")}
            </h3>
            <p className="mt-2 max-w-full truncate font-mono text-xs text-muted-foreground">{fleetEvidence.evidence_bundle}</p>
            <p className="mt-2 text-sm text-muted-foreground">
              {fleetEvidence.rollback_refs.join(", ") || translateNow("source.no.rollback.refs.recorded.0d22293f6b")}
            </p>
          </section>
        )}
        <FleetReissuanceTable runs={fleetRuns} action={fleetAction} onAction={recordFleetAction} />
      </section>

      <section aria-labelledby="incident-help-heading" className={tab === "fleet" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
        <div>
          <h2 id="incident-help-heading" className="text-title font-semibold">
            {translateNow("source.incident.response.help.7245c4b82c")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.keep.emergency.issuance.guidance.close.by.6a05c2d327")}</p>
        </div>
        <div>
          <Button type="button" variant="outline" onClick={() => setShowBreakGlassHelp(true)}>
            {translateNow("source.break.glass.help.9f8fde42af")}
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
                  {translateNow("source.break.glass.help.9f8fde42af")}
                </h3>
                <p id="break-glass-help-description" className="mt-1 text-sm text-muted-foreground">
                  {translateNow("source.emergency.issuance.requires.declaration.qu.24cf522826")}
                </p>
              </div>
              <Button ref={breakGlassCloseRef} type="button" variant="outline" onClick={() => setShowBreakGlassHelp(false)}>
                {translateNow("source.close.help.88f2b69280")}
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

      {evidenceRunDetail && (
        <Dialog
          open
          onClose={() => setEvidenceRunDetail(null)}
          titleId="playbook-run-detail-heading"
          descriptionId="playbook-run-detail-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="playbook-run-detail-heading" className="text-title font-semibold">
              {translateNow("source.playbook.run.value1.48f61c2511", { value1: evidenceRunDetail.id })}
            </h2>
            <p id="playbook-run-detail-description" className="mt-1 text-sm text-muted-foreground">
              {t("parity.eventSourcedRemediationRunEvidenceIncluding_cec725")}
            </p>
          </header>
          <dl className="grid gap-2 p-5 text-sm">
            <IncidentDetailRow term="Run ID" mono>
              {evidenceRunDetail.id}
            </IncidentDetailRow>
            <IncidentDetailRow term="Playbook" mono>
              {evidenceRunDetail.playbook_id}
            </IncidentDetailRow>
            <IncidentDetailRow term="Action">{evidenceRunDetail.action}</IncidentDetailRow>
            <IncidentDetailRow term="Status">
              <StatusBadge value={evidenceRunDetail.status} label={evidenceRunDetail.status} tone={remediationRunTone(evidenceRunDetail.status)} />
            </IncidentDetailRow>
            <IncidentDetailRow term="Phase">{evidenceRunDetail.phase}</IncidentDetailRow>
            <IncidentDetailRow term="Created">
              {formatDateTime(evidenceRunDetail.created_at)}
              {evidenceRunDetail.created_by ? translateNow("source.value1.d610afc356", { value1: evidenceRunDetail.created_by }) : ""}
            </IncidentDetailRow>
            <IncidentDetailRow term="Updated">{formatDateTime(evidenceRunDetail.updated_at)}</IncidentDetailRow>
            <IncidentDetailRow term="Reason">{evidenceRunDetail.reason || "-"}</IncidentDetailRow>
            <IncidentDetailRow term="Target identity" mono>
              {evidenceRunDetail.target_identity_id || "-"}
            </IncidentDetailRow>
            <IncidentDetailRow term="Inventory" mono>
              {evidenceRunDetail.inventory_id || "-"}
            </IncidentDetailRow>
            <IncidentDetailRow term="Connector">{evidenceRunDetail.connector || "-"}</IncidentDetailRow>
            <IncidentDetailRow term="Provider target">{evidenceRunDetail.target || "-"}</IncidentDetailRow>
            <IncidentDetailRow term="Rollback refs">{evidenceRunDetail.rollback_refs.join(", ") || "-"}</IncidentDetailRow>
            <IncidentDetailRow term="Evidence refs" mono>
              {evidenceRunDetail.evidence_refs.join(", ") || "-"}
            </IncidentDetailRow>
            <IncidentDetailRow term="Idempotency key" mono>
              {evidenceRunDetail.idempotency_key || "-"}
            </IncidentDetailRow>
            <IncidentDetailRow term="Outbox ID">{evidenceRunDetail.outbox_id != null ? String(evidenceRunDetail.outbox_id) : "-"}</IncidentDetailRow>
            {Object.keys(evidenceRunDetail.scope_delta ?? {}).length > 0 && (
              <IncidentDetailRow term="Scope delta">
                <pre className="max-h-40 overflow-auto rounded-control border border-border bg-muted/40 p-2 font-mono text-xs">
                  {JSON.stringify(evidenceRunDetail.scope_delta, null, 2)}
                </pre>
              </IncidentDetailRow>
            )}
          </dl>
          {evidenceRunDetail.connector_delivery && (
            <div className="border-t border-border px-5 py-4">
              <h3 className="text-body font-semibold">{translateNow("source.connector.delivery.670c8c3d02")}</h3>
              <dl className="mt-2 grid gap-2 text-sm">
                <IncidentDetailRow term="Delivery ID" mono>
                  {evidenceRunDetail.connector_delivery.id}
                </IncidentDetailRow>
                <IncidentDetailRow term="Status">
                  <StatusBadge
                    value={evidenceRunDetail.connector_delivery.status}
                    label={evidenceRunDetail.connector_delivery.status}
                    tone={connectorDeliveryTone(evidenceRunDetail.connector_delivery.status)}
                  />
                </IncidentDetailRow>
                <IncidentDetailRow term="Connector">{evidenceRunDetail.connector_delivery.connector}</IncidentDetailRow>
                <IncidentDetailRow term="Target">{evidenceRunDetail.connector_delivery.target}</IncidentDetailRow>
                <IncidentDetailRow term="Destination" mono>
                  {evidenceRunDetail.connector_delivery.destination}
                </IncidentDetailRow>
                <IncidentDetailRow term="Attempts">{evidenceRunDetail.connector_delivery.attempts}</IncidentDetailRow>
                <IncidentDetailRow term="Detail">{evidenceRunDetail.connector_delivery.detail || "-"}</IncidentDetailRow>
                <IncidentDetailRow term="Rollback ref" mono>
                  {evidenceRunDetail.connector_delivery.rollback_ref || "-"}
                </IncidentDetailRow>
                <IncidentDetailRow term="Updated">{formatDateTime(evidenceRunDetail.connector_delivery.updated_at)}</IncidentDetailRow>
              </dl>
            </div>
          )}
          <div className="flex justify-end border-t border-border px-5 py-4">
            <Button type="button" variant="outline" onClick={() => setEvidenceRunDetail(null)}>
              {translateNow("source.close.7d9eb7acb1")}
            </Button>
          </div>
        </Dialog>
      )}
    </section>
  );
}

function ResponseIntegrationDestinationTable({ dispatch, t }: { dispatch: ResponseIntegrationDispatch; t: I18nContextValue["t"] }) {
  return (
    <div className="mt-3 overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[54rem]">
        <caption className="sr-only">{t("incidents.response.tableCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("incidents.response.provider")}</th>
            <th scope="col">{t("incidents.response.destination")}</th>
            <th scope="col">{t("incidents.response.status")}</th>
            <th scope="col">{t("incidents.response.outbox")}</th>
            <th scope="col">{t("incidents.response.idempotency")}</th>
          </tr>
        </thead>
        <tbody>
          {dispatch.destinations.map((destination) => (
            <tr key={destination.id} className="align-top">
              <td>{destination.provider}</td>
              <td className="font-mono text-xs">{destination.destination}</td>
              <td>{destination.status}</td>
              <td className="font-mono text-xs">{destination.outbox_id}</td>
              <td className="break-all font-mono text-xs">{destination.idempotency_key}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RemediationPlaybookRunTable({ runs, t }: { runs: RemediationPlaybookRun[]; t: I18nContextValue["t"] }) {
  if (runs.length === 0) {
    return <p className="text-sm text-muted-foreground">{t("incidents.playbooks.noRuns")}</p>;
  }
  return (
    <div className="overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[64rem]">
        <caption className="sr-only">{t("incidents.playbooks.tableCaption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("incidents.playbooks.run")}</th>
            <th scope="col">{t("incidents.playbooks.playbook")}</th>
            <th scope="col">{t("incidents.playbooks.target")}</th>
            <th scope="col">{t("incidents.playbooks.status")}</th>
            <th scope="col">{t("incidents.playbooks.connector")}</th>
            <th scope="col">{t("incidents.playbooks.rollback")}</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((item) => (
            <tr key={item.id} className="align-top">
              <td className="font-mono text-xs">{item.id}</td>
              <td>
                <p className="font-medium">{item.playbook_id}</p>
                <p className="text-xs text-muted-foreground">{item.action}</p>
              </td>
              <td>
                <p className="font-mono text-xs">{item.target_identity_id || item.inventory_id || "-"}</p>
                <p className="text-xs text-muted-foreground">{item.inventory_id}</p>
              </td>
              <td>
                <p className="font-medium">{item.status}</p>
                <p className="text-xs text-muted-foreground">{item.phase}</p>
              </td>
              <td>
                <p className="font-medium">{item.connector_delivery?.destination ?? item.connector ?? "-"}</p>
                <p className="text-xs text-muted-foreground">{item.target}</p>
              </td>
              <td>{item.rollback_refs.length ? item.rollback_refs.join(", ") : t("incidents.playbooks.none")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IncidentExecutionTable({ executions }: { executions: IncidentExecution[] }) {
  if (executions.length === 0) {
    return <p className="text-sm text-muted-foreground">{translateNow("source.no.incident.executions.have.been.recorded.b14b9f6701")}</p>;
  }
  return (
    <div className="overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[68rem]">
        <caption className="sr-only">{translateNow("source.incident.execution.evidence.ed369964a3")}</caption>
        <thead>
          <tr>
            <th scope="col">{translateNow("source.execution.a45cd4bd09")}</th>
            <th scope="col">{translateNow("source.compromised.05ab8ef2cf")}</th>
            <th scope="col">{translateNow("source.replacement.cefd665229")}</th>
            <th scope="col">{translateNow("source.status.920e413c7d")}</th>
            <th scope="col">{translateNow("source.delivery.52bfe584a5")}</th>
            <th scope="col">{translateNow("source.failed.targets.4ffa850540")}</th>
            <th scope="col">{translateNow("source.evidence.03867aea70")}</th>
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
              <td>{item.failed_targets.length ? item.failed_targets.join(", ") : translateNow("source.none.140bedbf9c")}</td>
              <td>
                <p className="font-medium">{item.evidence_bundle_format || translateNow("source.unavailable.ba691ba042")}</p>
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
        {translateNow("source.blast.radius.snapshot.c447c874b9")}
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        {translateNow("source.compromise.of.988dd256bd")} {impact.node.name || impact.node.id} {translateNow("source.affects.e3e4b7e9f8")}{" "}
        {impact.affected.length} {translateNow("source.downstream.node.35861aa3d8")}
        {impact.affected.length === 1 ? "" : "s"}.
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
    return <p className="mt-3 text-sm text-muted-foreground">{translateNow("source.no.downstream.affected.nodes.were.returned.58352b876f")}</p>;
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

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function markOwnerActionAccepted(queue: OwnerRemediationQueue, result: OwnerRemediationRun): OwnerRemediationQueue {
  let changed = false;
  const items = queue.items.map((item) => {
    if (item.id !== result.action.id) return item;
    changed = item.status !== "accepted";
    return result.action;
  });
  return {
    ...queue,
    items,
    summary: {
      ...queue.summary,
      open: changed ? Math.max(0, queue.summary.open - 1) : queue.summary.open,
      accepted: changed ? queue.summary.accepted + 1 : queue.summary.accepted,
    },
  };
}

const evidenceRunColumns: DataGridColumn<RemediationPlaybookRun>[] = [
  { id: "created", header: "Created", cell: (run) => formatDateTime(run.created_at) },
  {
    id: "playbook",
    header: "Playbook",
    cell: (run) => (
      <div className="grid gap-1">
        <span className="font-medium">{run.playbook_id}</span>
        <span className="text-xs text-muted-foreground">{run.action}</span>
      </div>
    ),
  },
  {
    id: "status",
    header: "Status",
    cell: (run) => <StatusBadge value={run.status} label={run.status} tone={remediationRunTone(run.status)} />,
  },
  {
    id: "target",
    header: "Target",
    cell: (run) => (
      <span className="block max-w-[14rem] truncate font-mono text-xs" title={run.target_identity_id || run.inventory_id || run.target || ""}>
        {run.target_identity_id || run.inventory_id || run.target || "-"}
      </span>
    ),
  },
];

function remediationRunTone(status: string | undefined): StatusTone {
  // Served runs may omit status while queued; render them as neutral instead
  // of crashing the page.
  if (!status) return "neutral";
  if (status.includes("fail") || status.includes("error")) return "critical";
  // "rollback_recorded" is an attested intent, not an executed restore, so it
  // must not read as a green outcome (truth-integrity 4).
  if (status.includes("rollback")) return "warning";
  if (status.includes("complete") || status.includes("succeed") || status.includes("recorded") || status.includes("done")) return "success";
  if (status.includes("pending") || status.includes("running") || status.includes("progress") || status.includes("open")) return "warning";
  return "neutral";
}

// Delegated to the shared delivery vocabulary so a receipt cannot render greener
// here than it does on the Connectors page or than the served claim allows
// (internal/servedstatus).
function connectorDeliveryTone(status: NonNullable<RemediationPlaybookRun["connector_delivery"]>["status"]): StatusTone {
  return describeStatus("delivery", status).tone;
}

function OwnerRemediationQueuePanel({ queue }: { queue: OwnerRemediationQueue }) {
  const { t } = useTranslation();
  return (
    <div className="grid content-start gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-body font-semibold">{t("parity.ownerRemediationQueue_610e16")}</h3>
        <StatusBadge value={queue.status ?? "queued"} label={queue.status ?? "queued"} tone={remediationRunTone(queue.status)} />
      </div>
      <p className="text-xs text-muted-foreground">
        {translateNow("source.generated.827ec8d9f9")} {formatDateTime(queue.generated_at)} · {queue.capability}
      </p>
      {(queue.items ?? []).length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("parity.noOwnerRemediationActionsAreQueued_596b9b")}</p>
      ) : (
        <ul className="grid gap-2">
          {(queue.items ?? []).map((item) => (
            <li key={item.id} className="grid gap-1 rounded-panel border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{item.display_name}</span>
                <span className="flex flex-wrap items-center gap-2">
                  <StatusBadge value={item.severity ?? "medium"} label={item.severity ?? "medium"} tone={item.severity ?? "medium"} />
                  <span className="text-xs text-muted-foreground">{item.status}</span>
                </span>
              </div>
              <p className="break-all font-mono text-xs text-muted-foreground">
                {item.inventory_id}
                {item.target_identity_id ? translateNow("source.value1.d610afc356", { value1: item.target_identity_id }) : ""}
              </p>
              <p className="text-muted-foreground">{item.recommendation}</p>
              <p className="text-xs text-muted-foreground">
                {item.playbook_id} · {item.action || item.kind} · {item.source} · {item.connector}
                {item.target ? translateNow("source.value1.87b66be02d", { value1: item.target }) : ""} {translateNow("source.risk.b422944f55")}{" "}
                {item.risk_score} {translateNow("source.owner.6f9e1d3981")} {item.owner_name}
                {item.owner_email ? translateNow("source.value1.1a37d34e22", { value1: item.owner_email }) : ""}
              </p>
              {(item.remove_scopes.length > 0 || item.recommended_scopes.length > 0) && (
                <p className="break-all font-mono text-xs text-muted-foreground">
                  {item.remove_scopes.length > 0 ? translateNow("source.remove.value1.e3301e7b14", { value1: item.remove_scopes.join(", ") }) : ""}
                  {item.remove_scopes.length > 0 && item.recommended_scopes.length > 0 ? " · " : ""}
                  {item.recommended_scopes.length > 0 ? translateNow("source.keep.value1.208d6f9b94", { value1: item.recommended_scopes.join(", ") }) : ""}
                </p>
              )}
              {item.reason && (
                <p className="text-xs text-muted-foreground">
                  {translateNow("source.reason.3425d10869")} {item.reason}
                </p>
              )}
              {item.rollback_ref && (
                <p className="break-all font-mono text-xs text-muted-foreground">
                  {translateNow("source.rollback.c48b9dea6f")} {item.rollback_ref}
                </p>
              )}
              {item.evidence_refs.length > 0 && (
                <p className="break-all font-mono text-xs text-muted-foreground">
                  {translateNow("source.evidence.5da3c91b4d")} {item.evidence_refs.join(", ")}
                </p>
              )}
              {item.remediation_run_id && (
                <p className="break-all font-mono text-xs text-muted-foreground">
                  {translateNow("source.run.ea64488842")} {item.remediation_run_id}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function IncidentDetailRow({ term, children, mono = false }: { term: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr] sm:gap-2">
      <dt className="font-medium text-muted-foreground">{term}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}
