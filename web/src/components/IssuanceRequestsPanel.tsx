import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { issuanceRequestRecovery, type IssuanceRequestRecovery } from "@/lib/issuanceRequestRecovery";
import { api, ApiError, type IssuanceRequest, type IssuanceRequestList } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { hasPermission } from "@/lib/access";
import { apiProblemMessage } from "@/lib/apiProblem";
import { approvalRequestsQueryKey } from "@/lib/approvalQueue";
import { translateNow } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";
import { TicketIntakeSchedulesPanel } from "@/components/issuance/TicketIntakeSchedulesPanel";
import { Num } from "@/components/typography";

export function readIssuanceRequests(): Promise<IssuanceRequestList> {
  return optionalApiCall<IssuanceRequestList>("issuanceRequests", { items: [], open: 0, guidance: "" });
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

export function IssuanceRequestsPanel({ currentPrincipal }: IssuanceRequestsPanelProps = {}) {
  const queryClient = useQueryClient();
  const requests = useApiQuery(issuanceRequestsQueryKey, readIssuanceRequests);
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
      <TicketIntakeSchedulesPanel canConfigure={canConfigureIntake} />
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
                  <span className="mt-1 block text-caption text-muted-foreground">
                    {translateNow("ticket.intake.named.requestOwner")}:{" "}
                    {item.owner_id ? <Num>{item.owner_id}</Num> : translateNow("ticket.intake.named.unassigned")}
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
