import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { issuanceRequestRecovery, type IssuanceRequestRecovery } from "@/lib/issuanceRequestRecovery";
import { api, ApiError, type IssuanceRequest, type IssuanceRequestList, type TicketIntakeInput, type TicketIntakeSchedule } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { hasPermission } from "@/lib/access";
import { apiProblemMessage } from "@/lib/apiProblem";
import { approvalRequestsQueryKey } from "@/lib/approvalQueue";
import { translateNow } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";

export function readIssuanceRequests(): Promise<IssuanceRequestList> {
  return optionalApiCall<IssuanceRequestList>("issuanceRequests", { items: [], open: 0, guidance: "" });
}

function readTicketIntakeSchedule(system: "servicenow" | "jira"): Promise<TicketIntakeSchedule> {
  return optionalApiCall<TicketIntakeSchedule>(
    "ticketIntakeSchedule",
    {
      configured: false,
      system,
      enabled: false,
      read_count: 0,
      pages_completed: 0,
      coverage_complete: false,
      eligible_count: 0,
      skipped_count: 0,
      guidance: "",
    },
    system,
  );
}

// IssuanceRequestsPanel shows the request queue with its real lifecycle (I3).
//
// Every state is rendered by name rather than folded into open/closed. That is
// the point of the object: a DENIAL is somebody's decision with a reason, an
// EXPIRY is the absence of one, and a requester needs to tell those apart to
// know whether re-asking is reasonable. An "approved" row is still shown as
// outstanding work, because approval is a decision and issuance is an outcome —
// a request approved but never minted would otherwise vanish from every queue.
export interface IssuanceRequestsPanelProps {
  currentPrincipal?: { subject?: string; email?: string; permissions?: string[] } | null;
}

export const issuanceRequestsQueryKey = ["issuance-requests"] as const;

const intakeSystems = ["servicenow", "jira"] as const;
type IntakeSystem = (typeof intakeSystems)[number];
type IntakeDraft = Omit<TicketIntakeInput, "interval_seconds"> & { interval_seconds: string };
type ReviewedIntake = { input: TicketIntakeInput; idempotencyKey: string };

function intakeDraft(system: IntakeSystem, current?: TicketIntakeSchedule): IntakeDraft {
  return {
    system,
    instance_url: current?.instance_url ?? "",
    token_ref: current?.token_ref ?? "",
    sn_table: current?.sn_table ?? "sc_req_item",
    jira_project: current?.jira_project ?? "",
    query: current?.query ?? "",
    subject_field: current?.subject_field ?? "",
    profile_field: current?.profile_field ?? "",
    requester_field: current?.requester_field ?? "",
    justification_field: current?.justification_field ?? "",
    interval_seconds: String(current?.interval_seconds ?? 3600),
    enabled: current?.enabled ?? false,
  };
}

function reviewedIntake(draft: IntakeDraft): TicketIntakeInput | null {
  let endpoint: URL;
  try {
    endpoint = new URL(draft.instance_url.trim());
  } catch {
    return null;
  }
  if (
    endpoint.protocol !== "https:" ||
    !endpoint.hostname ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    !/^secret:\/\/.+/.test(draft.token_ref.trim()) ||
    !/^\d+$/.test(draft.interval_seconds) ||
    Number(draft.interval_seconds) < 300 ||
    !/^[A-Za-z0-9_.-]{1,128}$/.test(draft.subject_field.trim()) ||
    !/^[A-Za-z0-9_.-]{1,128}$/.test(draft.profile_field.trim())
  )
    return null;
  for (const optionalField of [draft.requester_field, draft.justification_field]) {
    if (optionalField?.trim() && !/^[A-Za-z0-9_.-]{1,128}$/.test(optionalField.trim())) return null;
  }
  if (draft.system === "jira" && !/^[A-Z][A-Z0-9_]{0,63}$/.test(draft.jira_project?.trim() ?? "")) return null;
  return {
    system: draft.system,
    instance_url: draft.instance_url.trim().replace(/\/$/, ""),
    token_ref: draft.token_ref.trim(),
    ...(draft.system === "jira" ? { jira_project: draft.jira_project?.trim() } : { sn_table: draft.sn_table }),
    subject_field: draft.subject_field.trim(),
    profile_field: draft.profile_field.trim(),
    ...(draft.query?.trim() ? { query: draft.query.trim() } : {}),
    ...(draft.requester_field?.trim() ? { requester_field: draft.requester_field.trim() } : {}),
    ...(draft.justification_field?.trim() ? { justification_field: draft.justification_field.trim() } : {}),
    interval_seconds: Number(draft.interval_seconds),
    enabled: Boolean(draft.enabled),
  };
}

export function IssuanceRequestsPanel({ currentPrincipal }: IssuanceRequestsPanelProps = {}) {
  const queryClient = useQueryClient();
  const requests = useApiQuery(issuanceRequestsQueryKey, readIssuanceRequests);
  const serviceNowSchedule = useApiQuery(["ticket-intake-schedule", "servicenow"], () => readTicketIntakeSchedule("servicenow"));
  const jiraSchedule = useApiQuery(["ticket-intake-schedule", "jira"], () => readTicketIntakeSchedule("jira"));
  const [busyRequestID, setBusyRequestID] = useState<string | null>(null);
  const [denyRequestID, setDenyRequestID] = useState<string | null>(null);
  const [denyReason, setDenyReason] = useState("");
  const [decisionNotice, setDecisionNotice] = useState<string | null>(null);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [recovery, setRecovery] = useState<Record<string, IssuanceRequestRecovery>>({});
  const canDecideRequests = hasPermission(currentPrincipal, "certs:issue");
  const canRequestCertificates = hasPermission(currentPrincipal, "certs:request");
  const canConfigureIntake = hasPermission(currentPrincipal, "certs:write");
  const canFulfillRequests = canDecideRequests && hasPermission(currentPrincipal, "identities:write");
  const items = requests.data?.items ?? [];
  const schedules = [serviceNowSchedule.data, jiraSchedule.data].filter((schedule): schedule is TicketIntakeSchedule => Boolean(schedule?.configured));
  const [intakeEditor, setIntakeEditor] = useState<IntakeDraft | null>(null);
  const [intakeReview, setIntakeReview] = useState<ReviewedIntake | null>(null);
  const [intakeSaving, setIntakeSaving] = useState(false);
  const [intakeError, setIntakeError] = useState<string | null>(null);
  const [intakeSaved, setIntakeSaved] = useState(false);
  if (items.length === 0 && schedules.length === 0 && !canConfigureIntake) return null;

  function openIntakeEditor(system: IntakeSystem) {
    const current = system === "jira" ? jiraSchedule.data : serviceNowSchedule.data;
    setIntakeEditor(intakeDraft(system, current ?? undefined));
    setIntakeReview(null);
    setIntakeError(null);
    setIntakeSaved(false);
  }

  function reviewIntake(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!intakeEditor) return;
    const input = reviewedIntake(intakeEditor);
    if (!input) {
      setIntakeError(translateNow("ticket.intake.setup.invalid"));
      return;
    }
    setIntakeReview({ input, idempotencyKey: newIdempotencyKey() });
    setIntakeError(null);
  }

  async function saveIntake() {
    if (!intakeReview || intakeSaving) return;
    setIntakeSaving(true);
    setIntakeError(null);
    try {
      const saved = await api.putTicketIntakeSchedule(intakeReview.input, intakeReview.idempotencyKey);
      queryClient.setQueryData(["ticket-intake-schedule", intakeReview.input.system], saved);
      void queryClient.invalidateQueries({ queryKey: ["ticket-intake-schedule", intakeReview.input.system] });
      setIntakeSaved(true);
      setIntakeEditor(null);
      setIntakeReview(null);
    } catch (error) {
      // A lost response must retry the reviewed body with the same key.
      setIntakeError(error instanceof Error ? error.message : String(error));
    } finally {
      setIntakeSaving(false);
    }
  }

  function retainDecision(updated: IssuanceRequest) {
    queryClient.setQueryData<IssuanceRequestList>(issuanceRequestsQueryKey, (current) => {
      if (!current) return current;
      const items = current.items.map((item) => (item.id === updated.id ? updated : item));
      return { ...current, items, open: items.filter((item) => item.status === "requested").length };
    });
  }

  async function approve(item: IssuanceRequest) {
    setBusyRequestID(item.id);
    setDecisionError(null);
    setDecisionNotice(null);
    try {
      retainDecision(await api.approveIssuanceRequest(item.id));
      setDecisionNotice(translateNow("source.issuance.requests.approvalrecorded.i3req00015", { value1: item.subject }));
    } catch (err) {
      setDecisionError(apiProblemMessage(err, translateNow("source.issuance.requests.approvalfailed.i3req00018")));
    } finally {
      setBusyRequestID(null);
    }
  }

  async function deny(event: FormEvent<HTMLFormElement>, item: IssuanceRequest) {
    event.preventDefault();
    setBusyRequestID(item.id);
    setDecisionError(null);
    setDecisionNotice(null);
    try {
      retainDecision(await api.denyIssuanceRequest(item.id, denyReason.trim()));
      setDecisionNotice(translateNow("source.issuance.requests.denialrecorded.i3req00016", { value1: item.subject }));
      setDenyRequestID(null);
      setDenyReason("");
    } catch (err) {
      setDecisionError(apiProblemMessage(err, translateNow("source.issuance.requests.denialfailed.i3req00019")));
    } finally {
      setBusyRequestID(null);
    }
  }

  async function withdraw(item: IssuanceRequest) {
    setBusyRequestID(item.id);
    setDecisionError(null);
    setDecisionNotice(null);
    try {
      retainDecision(await api.cancelIssuanceRequest(item.id));
      setDecisionNotice(translateNow("source.issuance.requests.withdrawalrecorded.i3req00017", { value1: item.subject }));
    } catch (err) {
      setDecisionError(apiProblemMessage(err, translateNow("source.issuance.requests.withdrawalfailed.i3req00020")));
    } finally {
      setBusyRequestID(null);
    }
  }

  async function fulfill(item: IssuanceRequest) {
    setBusyRequestID(item.id);
    setDecisionError(null);
    setDecisionNotice(null);
    try {
      const prepared = await api.prepareIssuanceRequest(item.id);
      if (prepared.identity.status !== "issued") {
        await api.transitionIdentity(
          prepared.identity.id,
          "issued",
          `fulfill approved issuance request ${item.id}`,
          prepared.csr_pem,
          prepared.issue_idempotency_key,
        );
      }

      let completed: IssuanceRequest | null = null;
      let lastError: unknown = null;
      for (let attempt = 0; attempt < 8 && !completed; attempt += 1) {
        try {
          completed = await api.completeIssuanceRequest(item.id);
        } catch (err) {
          lastError = err;
          if (!(err instanceof ApiError) || err.status !== 409 || attempt === 7) throw err;
          await new Promise<void>((resolve) => window.setTimeout(resolve, 350));
        }
      }
      if (!completed) throw lastError ?? new Error("certificate evidence did not arrive");
      retainDecision(completed);
      setRecovery((current) => {
        const next = { ...current };
        delete next[`${item.tenant_id}:${item.id}`];
        return next;
      });
      setDecisionNotice(translateNow("source.issuance.requests.issued.i3req00023", { value1: item.subject }));
    } catch (err) {
      setRecovery((current) => ({ ...current, [`${item.tenant_id}:${item.id}`]: issuanceRequestRecovery(err) }));
      setDecisionError(apiProblemMessage(err, translateNow("source.issuance.requests.issuefailed.i3req00024")));
    } finally {
      setBusyRequestID(null);
      // An attempt can create an approval request or consume its authority.
      // Refresh that independent queue even if the issuance step was refused.
      void queryClient.invalidateQueries({ queryKey: approvalRequestsQueryKey });
    }
  }

  return (
    <Card aria-labelledby="issuance-requests-heading" className="space-y-3 p-comfortable">
      <h2 id="issuance-requests-heading" className="text-title font-semibold">
        {translateNow("source.issuance.requests.heading.i3req00001")}
      </h2>
      {decisionNotice ? (
        <p role="status" className="text-sm text-status-success">
          {decisionNotice}
        </p>
      ) : null}
      {decisionError ? (
        <p role="alert" className="text-sm text-destructive">
          {decisionError}
        </p>
      ) : null}
      {canConfigureIntake && !intakeEditor ? (
        <Button type="button" variant="outline" onClick={() => openIntakeEditor("servicenow")}>
          {translateNow("ticket.intake.setup.configure")}
        </Button>
      ) : null}
      {intakeSaved ? (
        <p role="status" className="text-sm text-success">
          {translateNow("ticket.intake.setup.saved")}
        </p>
      ) : null}
      {canConfigureIntake && intakeEditor && !intakeReview ? (
        <form onSubmit={reviewIntake} className="grid gap-3 rounded-control border border-border p-3 text-sm">
          <p className="text-muted-foreground">{translateNow("ticket.intake.setup.help")}</p>
          <label className="grid gap-1">
            {translateNow("ticket.intake.setup.provider")}
            <select className="ui-input" value={intakeEditor.system} onChange={(event) => openIntakeEditor(event.target.value as IntakeSystem)}>
              {intakeSystems.map((system) => (
                <option value={system} key={system}>
                  {translateNow(system === "jira" ? "ticket.intake.setup.providerJira" : "ticket.intake.setup.providerServiceNow")}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1">
            {translateNow("ticket.intake.setup.url")}
            <input
              className="ui-input"
              type="url"
              value={intakeEditor.instance_url}
              onChange={(event) => setIntakeEditor({ ...intakeEditor, instance_url: event.target.value })}
              required
            />
          </label>
          <label className="grid gap-1">
            {translateNow("cmdb.setup.tokenRef")}
            <input
              className="ui-input"
              value={intakeEditor.token_ref}
              onChange={(event) => setIntakeEditor({ ...intakeEditor, token_ref: event.target.value })}
              autoComplete="off"
              required
            />
          </label>
          {intakeEditor.system === "jira" ? (
            <label className="grid gap-1">
              {translateNow("ticket.intake.setup.project")}
              <input
                className="ui-input"
                value={intakeEditor.jira_project ?? ""}
                onChange={(event) => setIntakeEditor({ ...intakeEditor, jira_project: event.target.value })}
                required
              />
            </label>
          ) : (
            <label className="grid gap-1">
              {translateNow("ticket.intake.setup.table")}
              <select
                className="ui-input"
                value={intakeEditor.sn_table}
                onChange={(event) => setIntakeEditor({ ...intakeEditor, sn_table: event.target.value as TicketIntakeInput["sn_table"] })}
              >
                {["sc_req_item", "sc_request", "change_request", "incident"].map((table) => (
                  <option key={table} value={table}>
                    {table}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="grid gap-1">
            {translateNow("ticket.intake.setup.query")}
            <input
              className="ui-input"
              value={intakeEditor.query ?? ""}
              onChange={(event) => setIntakeEditor({ ...intakeEditor, query: event.target.value })}
            />
          </label>
          {(["subject_field", "profile_field", "requester_field", "justification_field"] as const).map((field) => (
            <label className="grid gap-1" key={field}>
              {translateNow(`ticket.intake.setup.${field}`)}
              <input
                className="ui-input"
                value={intakeEditor[field] ?? ""}
                onChange={(event) => setIntakeEditor({ ...intakeEditor, [field]: event.target.value })}
                required={field === "subject_field" || field === "profile_field"}
              />
            </label>
          ))}
          <label className="grid gap-1">
            {translateNow("cmdb.setup.interval")}
            <input
              className="ui-input"
              type="number"
              min={300}
              step={1}
              value={intakeEditor.interval_seconds}
              onChange={(event) => setIntakeEditor({ ...intakeEditor, interval_seconds: event.target.value })}
              required
            />
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={Boolean(intakeEditor.enabled)}
              onChange={(event) => setIntakeEditor({ ...intakeEditor, enabled: event.target.checked })}
            />
            {translateNow("cmdb.setup.enabled")}
          </label>
          {intakeError ? (
            <p role="alert" className="text-risk-critical">
              {intakeError}
            </p>
          ) : null}
          <div className="flex gap-2">
            <Button type="submit">{translateNow("ticket.intake.setup.review")}</Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setIntakeEditor(null);
                setIntakeError(null);
              }}
            >
              {translateNow("cmdb.setup.cancel")}
            </Button>
          </div>
        </form>
      ) : null}
      {intakeReview ? (
        <section aria-label={translateNow("ticket.intake.setup.reviewed")} className="grid gap-2 rounded-control border border-border p-3 text-sm">
          <p>
            {translateNow("ticket.intake.setup.provider")}: {intakeReview.input.system}
          </p>
          <p>
            {translateNow("ticket.intake.setup.url")}: {intakeReview.input.instance_url}
          </p>
          <p>
            {translateNow("cmdb.setup.tokenRef")}: {intakeReview.input.token_ref}
          </p>
          <p>
            {translateNow(
              "ticket.intake.setup.labelValue",
              intakeReview.input.system === "jira"
                ? { label: translateNow("ticket.intake.setup.project"), value: intakeReview.input.jira_project ?? "" }
                : { label: translateNow("ticket.intake.setup.table"), value: intakeReview.input.sn_table ?? "" },
            )}
          </p>
          <p>
            {translateNow("ticket.intake.setup.subject_field")}: {intakeReview.input.subject_field}
          </p>
          <p>
            {translateNow("ticket.intake.setup.profile_field")}: {intakeReview.input.profile_field}
          </p>
          <p>
            {translateNow("ticket.intake.setup.query")}: {intakeReview.input.query || translateNow("ticket.intake.setup.none")}
          </p>
          <p>
            {translateNow("ticket.intake.setup.requester_field")}: {intakeReview.input.requester_field || translateNow("ticket.intake.setup.none")}
          </p>
          <p>
            {translateNow("ticket.intake.setup.justification_field")}: {intakeReview.input.justification_field || translateNow("ticket.intake.setup.none")}
          </p>
          <p>
            {translateNow("cmdb.setup.interval")}: {intakeReview.input.interval_seconds}
          </p>
          <p>{intakeReview.input.enabled ? translateNow("cmdb.setup.enabledState") : translateNow("cmdb.setup.pausedState")}</p>
          <p>{translateNow("ticket.intake.setup.relayBoundary")}</p>
          {intakeError ? (
            <p role="alert" className="text-risk-critical">
              {intakeError}
            </p>
          ) : null}
          <div className="flex gap-2">
            <Button type="button" disabled={intakeSaving} onClick={() => void saveIntake()}>
              {translateNow("ticket.intake.setup.save")}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={intakeSaving}
              onClick={() => {
                setIntakeReview(null);
                setIntakeError(null);
              }}
            >
              {translateNow("cmdb.setup.editReview")}
            </Button>
          </div>
        </section>
      ) : null}
      {schedules.map((schedule) => (
        <div className="space-y-1" key={schedule.system}>
          <h3 className="text-sm font-semibold">{translateNow("source.vantage.relay.a3vant0003")}</h3>
          <p className="text-caption text-muted-foreground">
            <span className="font-medium">{schedule.system ?? "—"}</span>
            {" · "}
            {translateNow(schedule.enabled ? "protocols.ari.schedulerEnabled" : "protocols.ari.schedulerDisabled")}
            {" · "}
            {translateNow("discovery.monitoring.columnLastRun")}: {schedule.last_run_at?.slice(0, 16).replace("T", " ") ?? "—"}
          </p>
          {schedule.sweep_id ? (
            <div className="rounded-control border border-border bg-muted/30 p-3 text-sm" role="status">
              <p>
                {schedule.expected_count == null
                  ? translateNow("ticket.intake.coverage.unknown.aud470001", {
                      provider: schedule.system ?? "ITSM",
                      read: String(schedule.read_count),
                      pages: String(schedule.pages_completed),
                    })
                  : translateNow("ticket.intake.coverage.known.aud470002", {
                      provider: schedule.system ?? "ITSM",
                      read: String(schedule.read_count),
                      expected: String(schedule.expected_count),
                      pages: String(schedule.pages_completed),
                    })}
              </p>
              {schedule.coverage_complete ? (
                <p className="mt-1 text-success">
                  {translateNow("ticket.intake.coverage.complete.aud470003", {
                    eligible: String(schedule.eligible_count),
                    skipped: String(schedule.skipped_count),
                  })}
                </p>
              ) : (
                <p className="mt-1 text-risk-warning">
                  {translateNow("ticket.intake.coverage.incomplete.aud470004", {
                    cursor: schedule.next_cursor || "start",
                  })}
                </p>
              )}
            </div>
          ) : null}
          {schedule.last_error ? <p className="text-caption text-risk-critical">{schedule.last_error}</p> : null}
          <p className="text-caption text-muted-foreground">{schedule.guidance}</p>
          {canConfigureIntake && !intakeEditor ? (
            <Button type="button" size="sm" variant="outline" onClick={() => openIntakeEditor(schedule.system as IntakeSystem)}>
              {translateNow("ticket.intake.setup.edit")}
            </Button>
          ) : null}
        </div>
      ))}
      {items.length > 0 ? (
        <>
          <p className="text-sm">
            {translateNow("source.issuance.requests.counts.i3req00002", {
              value1: String(requests.data?.open ?? 0),
              value2: String(items.length),
            })}
          </p>
          <ul className="space-y-2 text-sm">
            {items.slice(0, 25).map((item) => {
              const ownRequest = requesterMatchesCurrentPrincipal(item.requester, currentPrincipal);
              const recoveryMode = recovery[`${item.tenant_id}:${item.id}`];
              const canWithdraw = ownRequest && canRequestCertificates && (item.status === "requested" || item.status === "approved");
              return (
                <li key={item.id} className="border-b border-border pb-3 last:border-0">
                  <span className="font-mono text-xs">{item.subject}</span>{" "}
                  <span className="text-caption text-muted-foreground">
                    {item.status === "expired" ? translateNow("source.issuance.requests.expired.i3req00003") : item.status}
                  </span>
                  <span className="mt-1 block text-caption text-muted-foreground">
                    {item.decided_by
                      ? translateNow("source.issuance.requests.decidedby.i3req00004", {
                          value1: item.requester,
                          value2: item.decided_by,
                        })
                      : item.requester}
                  </span>
                  <span className="mt-1 block text-caption text-muted-foreground">
                    {translateNow("request.wizard.issuerLabel")}:{" "}
                    {item.issuer
                      ? translateNow("request.wizard.issuerSummary", { name: item.issuer.name, source: item.issuer.source, id: item.issuer.id })
                      : translateNow("request.wizard.issuerLegacy")}
                  </span>
                  {item.justification ? (
                    <span className="mt-1 block text-caption text-muted-foreground">
                      {translateNow("source.issuance.requests.purpose.i3req00005", { value1: item.justification })}
                    </span>
                  ) : null}
                  {item.decision_reason ? (
                    <span className="mt-1 block text-caption text-muted-foreground">
                      {translateNow("source.issuance.requests.decisionreason.i3req00006", { value1: item.decision_reason })}
                    </span>
                  ) : null}
                  {item.status === "requested" && ownRequest ? (
                    <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.issuance.requests.selfapproval.i3req00007")}</p>
                  ) : null}
                  {item.status === "requested" && !ownRequest && canDecideRequests ? (
                    <div
                      className="mt-2 flex flex-wrap gap-2"
                      aria-label={translateNow("source.issuance.requests.decisiongroup.i3req00008", { value1: item.subject })}
                    >
                      <Button type="button" size="sm" disabled={busyRequestID === item.id} onClick={() => void approve(item)}>
                        {translateNow("source.issuance.requests.approve.i3req00009", { value1: item.subject })}
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={busyRequestID === item.id}
                        onClick={() => {
                          setDenyRequestID(item.id);
                          setDenyReason("");
                        }}
                      >
                        {translateNow("source.issuance.requests.deny.i3req00010", { value1: item.subject })}
                      </Button>
                    </div>
                  ) : null}
                  {item.status === "requested" && !ownRequest && currentPrincipal && !canDecideRequests ? (
                    <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.issuance.requests.readonly.i3req00021")}</p>
                  ) : null}
                  {(item.status === "approved" || item.status === "cancelled") && recoveryMode === "replace" ? (
                    <div className="mt-2 space-y-2">
                      <p className="text-caption text-muted-foreground">{translateNow("request.recovery.replace")}</p>
                      {ownRequest && canRequestCertificates ? (
                        <Link className="text-sm font-medium underline underline-offset-4" to={`/request?from_request=${encodeURIComponent(item.id)}`}>
                          {translateNow("request.recovery.startNew", { subject: item.subject })}
                        </Link>
                      ) : (
                        <p className="text-caption text-muted-foreground">{translateNow("request.recovery.askRequester")}</p>
                      )}
                    </div>
                  ) : item.status === "approved" && canFulfillRequests ? (
                    <div className="mt-2 space-y-2">
                      {recoveryMode ? (
                        <p className="text-caption text-muted-foreground">
                          {translateNow(recoveryMode === "repair" ? "request.recovery.repair" : "request.recovery.safe")}
                        </p>
                      ) : null}
                      <Button type="button" size="sm" disabled={busyRequestID === item.id} onClick={() => void fulfill(item)}>
                        {recoveryMode === "repair"
                          ? translateNow("request.recovery.afterRepair", { subject: item.subject })
                          : recoveryMode === "retry"
                            ? translateNow("request.recovery.retry", { subject: item.subject })
                            : translateNow("source.issuance.requests.issue.i3req00022", { value1: item.subject })}
                      </Button>
                    </div>
                  ) : null}
                  {item.status === "approved" && currentPrincipal && !canFulfillRequests ? (
                    <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.issuance.requests.awaitingissuance.i3req00025")}</p>
                  ) : null}
                  {item.status === "issued" && item.issued_by ? (
                    <p className="mt-2 text-caption text-muted-foreground">
                      {translateNow("source.issuance.requests.issuedevidence.i3req00026", { value1: item.issued_by })}
                    </p>
                  ) : null}
                  {denyRequestID === item.id ? (
                    <form
                      className="mt-2 grid max-w-xl gap-2"
                      aria-label={translateNow("source.issuance.requests.deny.i3req00010", { value1: item.subject })}
                      onSubmit={(event) => void deny(event, item)}
                    >
                      <label className="grid gap-1 text-caption font-medium">
                        {translateNow("source.issuance.requests.denyprompt.i3req00011")}
                        <input
                          className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-sm"
                          value={denyReason}
                          onChange={(event) => setDenyReason(event.target.value)}
                          required
                        />
                      </label>
                      <div className="flex flex-wrap gap-2">
                        <Button type="submit" size="sm" variant="destructive" disabled={busyRequestID === item.id || !denyReason.trim()}>
                          {translateNow("source.issuance.requests.recorddenial.i3req00012")}
                        </Button>
                        <Button type="button" size="sm" variant="ghost" onClick={() => setDenyRequestID(null)}>
                          {translateNow("source.issuance.requests.keepopen.i3req00013")}
                        </Button>
                      </div>
                    </form>
                  ) : null}
                  {canWithdraw ? (
                    <div className="mt-2">
                      <Button type="button" size="sm" variant="outline" disabled={busyRequestID === item.id} onClick={() => void withdraw(item)}>
                        {translateNow("source.issuance.requests.withdraw.i3req00014", { value1: item.subject })}
                      </Button>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
          <p className="text-caption text-muted-foreground">{requests.data?.guidance}</p>
        </>
      ) : null}
    </Card>
  );
}

function requesterMatchesCurrentPrincipal(requester: string, principal?: IssuanceRequestsPanelProps["currentPrincipal"]): boolean {
  const normalizedRequester = requester.trim().toLowerCase();
  if (!normalizedRequester || !principal) return false;
  return [principal.subject, principal.email].some((candidate) => candidate?.trim().toLowerCase() === normalizedRequester);
}
