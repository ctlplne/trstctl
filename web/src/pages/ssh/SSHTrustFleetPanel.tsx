import { useState } from "react";
import { Button } from "@/components/ui/button";
import { DataGrid } from "@/components/DataGrid";
import { Num } from "@/components/typography";
import { api, type SSHTrustFleetRollout } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { apiProblemMessage } from "@/lib/apiProblem";
import { translateNow as t } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";
import { SSHTrustFleetWizard, fleetSkipLabel } from "./SSHTrustFleetWizard";
const states: Record<string, MessageKey> = {
  pending: "sshTrust.fleetChange.pending",
  verified: "sshTrust.fleetChange.verified",
  attention_required: "sshTrust.fleetChange.attention",
  execution_window_expired: "sshTrust.fleetChange.expired",
  queued: "sshTrust.fleetChange.queued",
  skipped: "sshTrust.fleetChange.skipped",
  failed: "sshTrust.fleetChange.failed",
  refused: "sshTrust.fleetChange.refused",
};
const recoveries: Record<string, MessageKey> = {
  verified: "sshTrust.fleetChange.rollbackVerified",
  failed: "sshTrust.fleetChange.rollbackFailed",
  not_available: "sshTrust.fleetChange.rollbackUnavailable",
  not_needed: "sshTrust.fleetChange.rollbackNotNeeded",
};
export function SSHTrustFleetPanel({ publicKey, canConfigure }: { publicKey: string; canConfigure: boolean }) {
  const client = useQueryClient();
  const [cursor, setCursor] = useState("");
  const [planning, setPlanning] = useState(false);
  const [selected, setSelected] = useState("");
  const list = useApiQuery(["ssh-trust-fleet", cursor], () => api.sshTrustFleetRollouts({ limit: 25, ...(cursor ? { cursor } : {}) }), {
    live: { intervalMs: 10000 },
  });
  const detail = useApiQuery(["ssh-trust-fleet-detail", selected], () => api.sshTrustFleetRollout(selected), {
    enabled: !!selected,
    live: { intervalMs: 5000 },
    retry: false,
  });
  const rollout = detail.error ? null : detail.data;
  function started(value: SSHTrustFleetRollout) {
    client.setQueryData(["ssh-trust-fleet-detail", value.id], value);
    void client.invalidateQueries({ queryKey: ["ssh-trust-fleet"] });
    setSelected(value.id);
    setPlanning(false);
  }
  return (
    <section className="space-y-3" aria-label={t("sshTrust.fleetChange.heading")}>
      <h2 className="text-title font-semibold">{t("sshTrust.fleetChange.heading")}</h2>
      <p className="text-sm text-muted-foreground">{t("sshTrust.fleetChange.description")}</p>
      {planning ? (
        <SSHTrustFleetWizard publicKey={publicKey} onCancel={() => setPlanning(false)} onStarted={started} />
      ) : canConfigure ? (
        <Button type="button" onClick={() => setPlanning(true)}>
          {t("sshTrust.fleetChange.plan")}
        </Button>
      ) : (
        <p>{t("sshTrust.fleetChange.readOnly")}</p>
      )}
      <DataGrid
        ariaLabel={t("sshTrust.fleetChange.list")}
        rows={list.error ? [] : (list.data?.items ?? [])}
        getRowId={(row) => row.id}
        state={list.loading ? "loading" : list.error ? "error" : list.data?.items.length ? "ready" : "empty"}
        stateMessage={list.error ? apiProblemMessage(list.errorValue, t("sshTrust.fleetChange.listFailed")) : t("sshTrust.fleetChange.empty")}
        columns={[
          {
            id: "name",
            header: t("sshTrust.fleetChange.name"),
            cell: (row) => (
              <Button type="button" variant="ghost" aria-label={t("sshTrust.fleetChange.inspect", { name: row.plan.name })} onClick={() => setSelected(row.id)}>
                {row.plan.name}
              </Button>
            ),
          },
          { id: "state", header: t("sshTrust.fleetChange.state"), cell: (row) => t(states[row.state]) },
          { id: "created", header: t("sshTrust.fleetChange.checked"), cell: (row) => formatDateTime(row.updated_at) },
        ]}
        pagination={
          <div className="flex gap-2">
            {cursor ? (
              <Button variant="outline" onClick={() => setCursor("")}>
                {t("sshTrust.fleetChange.first")}
              </Button>
            ) : null}
            {list.data?.next_cursor ? (
              <Button variant="outline" onClick={() => setCursor(list.data!.next_cursor!)}>
                {t("sshTrust.fleetChange.more")}
              </Button>
            ) : null}
          </div>
        }
      />
      {selected ? (
        <section className="space-y-2" aria-label={t("sshTrust.fleetChange.detail")}>
          <Button type="button" variant="outline" loading={detail.fetching} onClick={detail.refetch}>
            {t("sshTrust.fleetChange.refresh")}
          </Button>
          {detail.error ? <p role="alert">{apiProblemMessage(detail.errorValue, t("sshTrust.fleetChange.detailFailed"))}</p> : null}
          {rollout ? (
            <>
              <p>{t(states[rollout.state])}</p>
              <p>
                <Num>{rollout.plan_digest}</Num>
              </p>
              <p>{t("sshTrust.fleetChange.receiptLimit")}</p>
              <DataGrid
                ariaLabel={t("sshTrust.fleetChange.detail")}
                rows={rollout.hosts}
                getRowId={(host) => host.agent_id}
                columns={[
                  { id: "host", header: t("sshTrust.fleetChange.host"), cell: (host) => <Num>{host.agent_id}</Num> },
                  {
                    id: "state",
                    header: t("sshTrust.fleetChange.state"),
                    cell: (host) => (host.state === "skipped" ? fleetSkipLabel(host.skip_reason) : t(states[host.state])),
                  },
                  { id: "result", header: t("sshTrust.fleetChange.reasonCode"), cell: (host) => <Num>{host.receipt?.reason_code ?? ""}</Num> },
                  {
                    id: "rollback",
                    header: t("sshTrust.fleetChange.rollback"),
                    cell: (host) => (host.receipt ? t(recoveries[host.receipt.rollback]) : t("sshTrust.fleetChange.noReceipt")),
                  },
                  {
                    id: "checked",
                    header: t("sshTrust.fleetChange.checked"),
                    cell: (host) => (host.checked_at ? formatDateTime(host.checked_at) : t("sshTrust.fleetChange.noReceipt")),
                  },
                ]}
              />
            </>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
