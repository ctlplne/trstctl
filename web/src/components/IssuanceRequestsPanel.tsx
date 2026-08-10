import { type IssuanceRequestList, type TicketIntakeSchedule } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";

function readIssuanceRequests(): Promise<IssuanceRequestList> {
  return optionalApiCall<IssuanceRequestList>("issuanceRequests", { items: [], open: 0, guidance: "" });
}

function readTicketIntakeSchedule(): Promise<TicketIntakeSchedule> {
  return optionalApiCall<TicketIntakeSchedule>("ticketIntakeSchedule", { configured: false, enabled: false, guidance: "" });
}

// IssuanceRequestsPanel shows the request queue with its real lifecycle (I3).
//
// Every state is rendered by name rather than folded into open/closed. That is
// the point of the object: a DENIAL is somebody's decision with a reason, an
// EXPIRY is the absence of one, and a requester needs to tell those apart to
// know whether re-asking is reasonable. An "approved" row is still shown as
// outstanding work, because approval is a decision and issuance is an outcome —
// a request approved but never minted would otherwise vanish from every queue.
export function IssuanceRequestsPanel() {
  const requests = useApiQuery(["issuance-requests"], readIssuanceRequests);
  const schedule = useApiQuery(["ticket-intake-schedule"], readTicketIntakeSchedule);
  const items = requests.data?.items ?? [];
  if (items.length === 0 && !schedule.data?.configured) return null;
  return (
    <section aria-labelledby="issuance-requests-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="issuance-requests-heading" className="text-title font-semibold">
        {translateNow("source.issuance.requests.heading.i3req00001")}
      </h2>
      {schedule.data?.configured ? (
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">{translateNow("source.vantage.relay.a3vant0003")}</h3>
          <p className="text-caption text-muted-foreground">
            <span className="font-medium">{schedule.data.system ?? "—"}</span>
            {" · "}
            {translateNow(schedule.data.enabled ? "protocols.ari.schedulerEnabled" : "protocols.ari.schedulerDisabled")}
            {" · "}
            {translateNow("discovery.monitoring.columnLastRun")}: {schedule.data.last_run_at?.slice(0, 16).replace("T", " ") ?? "—"}
          </p>
          {schedule.data.last_error ? <p className="text-caption text-risk-critical">{schedule.data.last_error}</p> : null}
          <p className="text-caption text-muted-foreground">{schedule.data.guidance}</p>
        </div>
      ) : null}
      {items.length > 0 ? (
        <>
          <p className="text-sm">
            {translateNow("source.issuance.requests.counts.i3req00002", {
              value1: String(requests.data?.open ?? 0),
              value2: String(items.length),
            })}
          </p>
          <ul className="space-y-2 text-sm">
            {items.slice(0, 25).map((item) => (
              <li key={item.id} className="border-b border-border pb-2 last:border-0">
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
                {item.decision_reason ? <span className="mt-1 block text-caption text-muted-foreground">{item.decision_reason}</span> : null}
              </li>
            ))}
          </ul>
          <p className="text-caption text-muted-foreground">{requests.data?.guidance}</p>
        </>
      ) : null}
    </section>
  );
}
