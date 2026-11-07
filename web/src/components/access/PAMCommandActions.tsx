import { useState } from "react";
import { Link } from "react-router-dom";
import { DataGrid } from "@/components/DataGrid";
import { CredentialChip } from "@/components/CredentialChip";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type PAMCommandAction } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

/** Public occurrence metadata only. An authorization is not a target receipt. */
export function PAMCommandActions({ sessionID, live = false }: { sessionID: string; live?: boolean }) {
  const { t, formatDate } = useTranslation();
  const [cursor, setCursor] = useState("");
  const page = useApiQuery(["pam-command-actions", sessionID, cursor], ({ signal }) => api.pamCommandActions(sessionID, { cursor, signal }), {
    retry: false,
    ...(live ? { live: { intervalMs: 1000 } } : {}),
  });
  const status = (row: PAMCommandAction) =>
    t(
      (
        {
          blocked: "admin.access.rules.blocked",
          pending: "admin.access.rules.pending",
          authorized: "admin.access.rules.authorized",
          denied: "admin.access.rules.denied",
          expired: "admin.access.rules.expired",
          canceled: "admin.access.rules.canceled",
          alerted: "admin.access.rules.alerted",
          review_deadline_elapsed: "admin.access.rules.elapsed",
        } as const
      )[row.effective_status] ?? "admin.access.rules.unavailable",
    );
  return (
    <section className="grid gap-3">
      <h4 className="text-body font-semibold">{t("admin.access.rules.actions")}</h4>
      <p className="text-caption text-muted-foreground">{t("admin.access.rules.evidenceHelp")}</p>
      <DataGrid<PAMCommandAction>
        ariaLabel={t("admin.access.rules.actions")}
        rows={page.data?.items ?? []}
        getRowId={(r) => r.id}
        state={page.error ? "error" : page.loading ? "loading" : "ready"}
        columns={[
          {
            id: "status",
            header: t("admin.access.rules.decision"),
            cell: (r) => (
              <div>
                <p>{status(r)}</p>
                <p>{r.operations.join(", ")}</p>
                {r.review_expires_at ? (
                  <p>{t("admin.access.rules.deadline", { at: formatDate(r.review_expires_at, undefined, { dateStyle: "short", timeStyle: "medium" }) })}</p>
                ) : null}
              </div>
            ),
          },
          {
            id: "scope",
            header: t("admin.access.rules.occurrence"),
            cell: (r) => (
              <details>
                <summary>{t("admin.access.rules.exactEvidence")}</summary>
                <dl className="break-all text-caption">
                  <dt>{t("admin.access.rules.actionID")}</dt>
                  <dd>
                    <CredentialChip value={r.id} />
                  </dd>
                  <dt>{t("admin.access.rules.ruleIDs")}</dt>
                  <dd>{r.rule_ids.join(", ")}</dd>
                  <dt>{t("admin.access.rules.messageDigest")}</dt>
                  <dd>{r.message_digest}</dd>
                  <dt>{t("admin.access.rules.policyDigest")}</dt>
                  <dd>{r.policy_digest}</dd>
                  <dt>{t("admin.access.rules.sourceEvent")}</dt>
                  <dd>{r.source_event_id}</dd>
                  <dt>{t("admin.access.rules.occurrence")}</dt>
                  <dd>
                    {r.protocol} / {r.phase} / {r.connection_id} / {r.ordinal} / {r.job_id}:{r.attempt}
                  </dd>
                  <dt>{t("admin.access.rules.observed")}</dt>
                  <dd>{formatDate(r.observed_at)}</dd>
                  <dt>{t("admin.access.rules.decisionTime")}</dt>
                  <dd>
                    {formatDate(r.decided_at)} / {r.reason}
                  </dd>
                </dl>
              </details>
            ),
          },
          {
            id: "review",
            header: t("admin.access.rules.review"),
            cell: (r) =>
              r.approval_request_id ? (
                <Link className="underline" target="_blank" rel="noopener noreferrer" to={`/approvals?request=${encodeURIComponent(r.approval_request_id)}`}>
                  {t("admin.access.rules.openReview")}
                </Link>
              ) : (
                t("admin.access.rules.noReview")
              ),
          },
        ]}
      />
      <div className="flex gap-2">
        {cursor ? (
          <Button type="button" variant="outline" onClick={() => setCursor("")}>
            {t("admin.access.rules.newest")}
          </Button>
        ) : null}
        {page.data?.next_cursor ? (
          <Button type="button" variant="outline" disabled={live} onClick={() => setCursor(page.data?.next_cursor ?? "")}>
            {t("admin.access.rules.older")}
          </Button>
        ) : null}
      </div>
    </section>
  );
}
