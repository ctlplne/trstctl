import { useEffect, useState } from "react";
import { useCan } from "@/components/rbac";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ADCSPendingRequests, type ExternalCA, type ExternalCAHeldIssue } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

type HeldNotice = { tone: "status" | "alert"; text: string };

/**
 * N1-L1: issuances an AD CS authority holds for a CA manager's approval. Each
 * one is listed with the CA's request id; once a manager approves the request,
 * Resume reads it back from the CA by that id and finishes the issuance.
 */
export function ExternalCAHeldIssuesPanel({ externalCAs }: { externalCAs: ExternalCA[] }) {
  const { t, formatDateTime } = useTranslation();
  const canRead = useCan("certs:read");
  const canResume = useCan("certs:issue");
  const authorities = externalCAs.filter((item) => item.type === "adcs" && item.status === "available");
  const authorityKey = authorities.map((item) => item.id).join("\n");
  const [held, setHeld] = useState<Record<string, ExternalCAHeldIssue[]>>({});
  // N1-L2: each authority's pending requests at the CA, from its relay's
  // latest read; absent for an authority without a relay route.
  const [pending, setPending] = useState<Record<string, ADCSPendingRequests>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<HeldNotice | null>(null);

  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    if (!canRead || authorityKey === "") return;
    let cancelled = false;
    const ids = authorityKey.split("\n");
    void Promise.all([
      Promise.allSettled(ids.map((id) => api.externalCAHeldIssues(id))),
      Promise.allSettled(ids.map((id) => api.adcsPendingRequests(id))),
    ]).then(([heldResults, pendingResults]) => {
      if (cancelled) return;
      const next: Record<string, ExternalCAHeldIssue[]> = {};
      const nextPending: Record<string, ADCSPendingRequests> = {};
      const failures: string[] = [];
      heldResults.forEach((result, index) => {
        if (result.status === "fulfilled") next[ids[index]] = result.value;
        else failures.push(apiProblemMessage(result.reason, translateNow("caHierarchy.heldIssues.loadFailed")));
      });
      pendingResults.forEach((result, index) => {
        if (result.status === "fulfilled") nextPending[ids[index]] = result.value;
        // 409: the authority has no relay route, so there is no list to show.
        else if (!(result.reason instanceof ApiError && result.reason.status === 409)) {
          failures.push(apiProblemMessage(result.reason, translateNow("caHierarchy.heldIssues.loadFailed")));
        }
      });
      setHeld(next);
      setPending(nextPending);
      setError(failures[0] ?? null);
    });
    return () => {
      cancelled = true;
    };
  }, [authorityKey, canRead, reloads]);

  if (!canRead || authorities.length === 0) return null;

  async function resume(authorityID: string, requestID: number) {
    setBusy(`${authorityID}:${requestID}`);
    setNotice(null);
    try {
      const resumed = await api.resumeExternalCAHeldIssue(authorityID, requestID);
      setNotice(
        resumed.status === "issued"
          ? { tone: "status", text: t("caHierarchy.heldIssues.issuedNotice", { requestID, serial: resumed.serial ?? "" }) }
          : { tone: "status", text: t("caHierarchy.heldIssues.deniedNotice", { requestID }) },
      );
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setNotice({ tone: "status", text: t("caHierarchy.heldIssues.stillHeldNotice", { requestID }) });
      } else {
        setNotice({ tone: "alert", text: apiProblemMessage(err, t("caHierarchy.heldIssues.resumeFailed")) });
      }
    } finally {
      setBusy(null);
      setReloads((count) => count + 1);
    }
  }

  function statusText(item: ExternalCAHeldIssue): string {
    if (item.status === "issued") return t("caHierarchy.heldIssues.status.issued", { serial: item.serial ?? "" });
    if (item.status === "denied") return t("caHierarchy.heldIssues.status.denied");
    return t("caHierarchy.heldIssues.status.held");
  }

  return (
    <section aria-labelledby="external-ca-held-heading" className="grid gap-3 border-b border-border py-4">
      <div>
        <h2 id="external-ca-held-heading" className="text-title font-semibold">
          {t("caHierarchy.heldIssues.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.heldIssues.description")}</p>
      </div>
      {error && <ErrorState title={t("caHierarchy.heldIssues.errorTitle")}>{error}</ErrorState>}
      {notice && (
        <p role={notice.tone} className={notice.tone === "alert" ? "text-sm text-destructive" : "text-sm"}>
          {notice.text}
        </p>
      )}
      {authorities.map((authority) => {
        const items = held[authority.id] ?? [];
        const atCA = pending[authority.id];
        return (
          <section key={authority.id} aria-label={authority.name} className="ui-panel p-comfortable text-sm">
            <h3 className="text-sm font-semibold">{authority.name}</h3>
            {items.length === 0 ? (
              <p className="mt-2 text-muted-foreground">{t("caHierarchy.heldIssues.none")}</p>
            ) : (
              <table className="ui-table mt-2">
                <thead>
                  <tr>
                    <th scope="col">{t("caHierarchy.heldIssues.requestID")}</th>
                    <th scope="col">{t("caHierarchy.heldIssues.names")}</th>
                    <th scope="col">{t("caHierarchy.heldIssues.heldSince")}</th>
                    <th scope="col">{t("caHierarchy.heldIssues.state")}</th>
                    <th scope="col">
                      <span className="sr-only">{t("caHierarchy.heldIssues.actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.ca_request_id}>
                      <td className="font-mono">{item.ca_request_id}</td>
                      <td>{item.dns_names.join(", ")}</td>
                      <td>{formatDateTime(item.held_at)}</td>
                      <td>{statusText(item)}</td>
                      <td>
                        {item.status === "held" && canResume ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={busy !== null}
                            aria-label={t("caHierarchy.heldIssues.resumeLabel", { requestID: item.ca_request_id })}
                            onClick={() => void resume(authority.id, item.ca_request_id)}
                          >
                            {t("caHierarchy.heldIssues.resume")}
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {atCA && (
              <div className="mt-4">
                <h4 className="text-sm font-semibold">{t("caHierarchy.heldIssues.pendingHeading")}</h4>
                <p className="text-xs text-muted-foreground">
                  {atCA.read_at
                    ? t("caHierarchy.heldIssues.pendingReadAt", { time: formatDateTime(atCA.read_at) })
                    : t("caHierarchy.heldIssues.pendingNeverRead")}
                </p>
                {atCA.items.length === 0 ? (
                  atCA.read_at ? (
                    <p className="mt-2 text-muted-foreground">{t("caHierarchy.heldIssues.pendingNone")}</p>
                  ) : null
                ) : (
                  <table className="ui-table mt-2">
                    <thead>
                      <tr>
                        <th scope="col">{t("caHierarchy.heldIssues.requestID")}</th>
                        <th scope="col">{t("caHierarchy.heldIssues.template")}</th>
                        <th scope="col">{t("caHierarchy.heldIssues.requestedName")}</th>
                        <th scope="col">{t("caHierarchy.heldIssues.requester")}</th>
                        <th scope="col">{t("caHierarchy.heldIssues.trstctlIssuance")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {atCA.items.map((request) => (
                        <tr key={request.request_id}>
                          <td className="font-mono">{request.request_id}</td>
                          <td>{request.template || "-"}</td>
                          <td>{request.common_name || "-"}</td>
                          <td>{request.requester || "-"}</td>
                          <td>{request.held_issuance ? t("caHierarchy.heldIssues.heldHere") : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {atCA.truncated && <p className="mt-2 text-xs text-muted-foreground">{t("caHierarchy.heldIssues.pendingTruncated")}</p>}
              </div>
            )}
          </section>
        );
      })}
    </section>
  );
}
