import { useCallback, useEffect, useState } from "react";
import { useCan } from "@/components/rbac";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type AgentJobPosture } from "@/lib/api";

// The agent job ledger, on the Operations page (epic A1).
//
// Once estate-touching work is executed by agents instead of by the control
// plane, "is the fabric moving?" stops being answerable from anywhere else. A
// queue that has stopped draining looks exactly like a quiet estate right up
// until something expires.
//
// The number that matters is the oldest wait, not the depth: depth alone cannot
// tell a busy queue from a stuck one. And an empty panel has three different
// meanings — channel not mounted, no kind enabled, or genuinely drained — so it
// says which rather than showing zeros and letting an operator guess.

type LedgerRead = { kind: "ready"; posture: AgentJobPosture } | { kind: "unavailable" };

async function readPosture(): Promise<LedgerRead> {
  try {
    return { kind: "ready", posture: await api.agentJobPosture() };
  } catch (error) {
    if (error instanceof ApiError && [0, 403, 404, 501, 503].includes(error.status)) return { kind: "unavailable" };
    throw error;
  }
}

function waitLabel(seconds: number | undefined): string {
  if (!seconds) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

export function AgentJobLedgerPanel({ posture: providedPosture }: { posture?: AgentJobPosture | null }) {
  const { t } = useTranslation();
  const canRead = useCan("access:read");
  const [read, setRead] = useState<LedgerRead | null>(null);
  const readsOwnPosture = providedPosture === undefined;

  const refresh = useCallback(() => {
    if (!canRead || !readsOwnPosture) return Promise.resolve();
    return readPosture()
      .then(setRead)
      .catch(() => setRead({ kind: "unavailable" }));
  }, [canRead, readsOwnPosture]);
  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (!canRead) return null;
  const posture = readsOwnPosture ? (read?.kind === "ready" ? read.posture : null) : providedPosture;
  // Read the arrays defensively. The served response always carries them, but a
  // missing field must not take the whole Operations page down — the panel is a
  // health readout, and a health readout that crashes the page it reports on is
  // worse than one that shows nothing.
  const kinds = posture?.claimable_kinds ?? [];
  const queues = posture?.queues ?? [];
  // A3: how much credential material is outside the seal right now. Read
  // defensively for the same reason the arrays are — a health readout that
  // crashes the page it reports on is worse than one that shows nothing.
  const redemptions = posture?.redemptions;
  const receipts = posture?.receipts;

  return (
    <section aria-labelledby="agent-job-ledger-heading" className="grid content-start gap-3 border-t border-border pt-4">
      <div>
        <h2 id="agent-job-ledger-heading" className="text-title font-medium">
          {t("operations.jobs.heading")}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("operations.jobs.description")}</p>
      </div>

      {(readsOwnPosture && read?.kind === "unavailable") || (posture && !posture.served) ? (
        <p className="text-sm text-muted-foreground">{t("operations.jobs.notServed")}</p>
      ) : posture && kinds.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("operations.jobs.noneEnabled")}</p>
      ) : null}

      {posture?.served && redemptions ? (
        <dl className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-caption text-muted-foreground">{t("operations.jobs.redemptions.live")}</dt>
            <dd className={redemptions.live > 0 ? "font-medium text-status-warning" : "font-medium"}>{redemptions.live}</dd>
          </div>
          <div>
            <dt className="text-caption text-muted-foreground">{t("operations.jobs.redemptions.total")}</dt>
            <dd className="font-medium">{redemptions.total}</dd>
          </div>
          <div>
            <dt className="text-caption text-muted-foreground">{t("operations.jobs.redemptions.oldest")}</dt>
            <dd className="font-medium">
              {redemptions.oldest_live_seconds ? waitLabel(redemptions.oldest_live_seconds) : t("operations.jobs.redemptions.none")}
            </dd>
          </div>
          <p className="text-caption text-muted-foreground sm:col-span-3">{t("operations.jobs.redemptions.help")}</p>
        </dl>
      ) : null}

      {posture?.served && receipts ? (
        <dl className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-caption text-muted-foreground">{t("operations.jobs.receipts.verified")}</dt>
            <dd className="font-medium">{receipts.verified}</dd>
          </div>
          <div>
            <dt className="text-caption text-muted-foreground">{t("operations.jobs.receipts.rejected")}</dt>
            {/* A refusal is worth an operator's attention even when the queue
                looks healthy: an agent believes it did work this ledger will
                not record, so that work is neither done nor requeued. */}
            <dd className={receipts.rejected > 0 ? "font-medium text-status-warning" : "font-medium"}>{receipts.rejected}</dd>
          </div>
          <div>
            <dt className="text-caption text-muted-foreground">{t("operations.jobs.receipts.lastRejected")}</dt>
            <dd className="font-medium">
              {receipts.rejected > 0 && receipts.last_rejected_reason ? receipts.last_rejected_reason : t("operations.jobs.receipts.none")}
            </dd>
          </div>
          <p className="text-caption text-muted-foreground sm:col-span-3">{t("operations.jobs.receipts.help")}</p>
        </dl>
      ) : null}

      {queues.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-caption text-muted-foreground">
                <th scope="col" className="py-1 pe-3 font-medium">
                  {t("operations.jobs.kind")}
                </th>
                <th scope="col" className="py-1 pe-3 font-medium">
                  {t("operations.jobs.waiting")}
                </th>
                <th scope="col" className="py-1 pe-3 font-medium">
                  {t("operations.jobs.inFlight")}
                </th>
                <th scope="col" className="py-1 font-medium">
                  {t("operations.jobs.oldest")}
                </th>
              </tr>
            </thead>
            <tbody>
              {queues.map((queue) => (
                <tr key={queue.kind} className="border-t border-border">
                  <td className="py-1 pe-3">
                    <span className="font-mono text-xs">{queue.kind}</span>
                    {!queue.enabled ? <span className="ms-2 text-2xs text-muted-foreground">{t("operations.jobs.disabled")}</span> : null}
                  </td>
                  <td className="py-1 pe-3 font-mono text-xs">{queue.pending}</td>
                  <td className="py-1 pe-3 font-mono text-xs">{queue.claimed}</td>
                  <td className={`py-1 font-mono text-xs${queue.oldest_unclaimed_seconds ? " text-status-warning" : ""}`}>
                    {waitLabel(queue.oldest_unclaimed_seconds)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
