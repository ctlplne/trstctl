import { useSearchParams, Link } from "react-router-dom";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { CredentialChip } from "@/components/CredentialChip";
import { WorkloadIdentityHandoff } from "@/components/WorkloadIdentityHandoff";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { api, type BrokerAgentIdentityHistory, type BrokerHistoryQuery } from "@/lib/api";
import { useCapabilityExecution } from "@/lib/capabilities";
import { useApiQuery } from "@/lib/query";
import { BrokerFact } from "./BrokerPlanReview";

const stateLabels: Record<BrokerAgentIdentityHistory["state"], MessageKey> = {
  valid: "broker.state.valid",
  not_yet_valid: "broker.state.notYetValid",
  expired: "broker.state.expired",
  revoked: "broker.state.revoked",
  superseded: "broker.state.superseded",
  unknown: "broker.state.unknown",
};
const freshnessLabels: Record<BrokerAgentIdentityHistory["projection_state"], MessageKey> = {
  current: "broker.freshness.current",
  catching_up: "broker.freshness.catchingUp",
  blocked: "broker.freshness.blocked",
  unknown: "broker.freshness.unknown",
};
function knownState(state: string): state is BrokerAgentIdentityHistory["state"] {
  return Object.prototype.hasOwnProperty.call(stateLabels, state);
}

export function BrokerIdentityHistory({ scope }: { scope: string }) {
  const { t, formatDateTime } = useTranslation();
  const [params, setParams] = useSearchParams();
  const listAction = useCapabilityExecution("F61", "listBrokerAgentIdentities");
  const detailAction = useCapabilityExecution("F61", "getBrokerAgentIdentity");
  const selectedID = params.get("broker_id") ?? "";
  const state = params.get("broker_state") ?? "";
  const invalidState = Boolean(state && !knownState(state));
  const filters: BrokerHistoryQuery = {
    limit: 20,
    cursor: params.get("broker_cursor") ?? "",
    q: params.get("broker_q") ?? "",
    method: params.get("broker_method") ?? "",
    ...(knownState(state) ? { state } : {}),
  };
  const list = useApiQuery(["broker-history", scope, filters], ({ signal }) => api.brokerAgentIdentities(filters, signal), {
    enabled: listAction.runnable && !invalidState,
    retry: false,
    live: { intervalMs: 15000 },
  });
  const detail = useApiQuery(["broker-detail", scope, selectedID], ({ signal }) => api.brokerAgentIdentity(selectedID, signal), {
    enabled: Boolean(selectedID) && detailAction.runnable,
    retry: false,
    live: { intervalMs: 15000 },
  });
  function setParam(key: string, value: string) {
    setParams((previous) => {
      const next = new URLSearchParams(previous);
      if (value) next.set(key, value);
      else next.delete(key);
      if (["broker_q", "broker_state", "broker_method"].includes(key)) next.delete("broker_cursor");
      return next;
    });
  }
  const columns: DataGridColumn<BrokerAgentIdentityHistory>[] = [
    {
      id: "agent",
      header: t("source.agent.11b39c9377"),
      cell: (row) => (row.metadata_state === "recorded" && row.issuance ? row.issuance.agent_id : t("broker.metadataUnavailable")),
    },
    { id: "subject", header: t("source.subject.6897128384"), cell: (row) => <span className="block max-w-xs break-words">{row.certificate_subject}</span> },
    { id: "state", header: t("broker.history.state"), cell: (row) => <BrokerState row={row} /> },
    {
      id: "expires",
      header: t("source.expires.f6725f3af0"),
      cell: (row) =>
        row.not_after ? (
          <time dateTime={row.not_after} title={row.not_after}>
            {formatDateTime(row.not_after)}
          </time>
        ) : (
          t("broker.metadataUnavailable")
        ),
    },
  ];
  const row = detailAction.runnable && !detail.error ? detail.data : null;
  return (
    <section aria-labelledby="broker-history-heading" className="grid gap-3">
      <div>
        <h3 id="broker-history-heading" className="font-semibold">
          {t("broker.history.title")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("broker.history.scope")}</p>
      </div>
      <CapabilityActionNotice action={listAction} />
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label={t("broker.history.search")}>
          {(control) => <Input {...control} maxLength={200} value={filters.q} onChange={(event) => setParam("broker_q", event.target.value)} />}
        </Field>
        <Field label={t("broker.history.state")} error={invalidState ? t("broker.history.invalidFilter") : undefined}>
          {(control) => (
            <Select {...control} value={state} onChange={(event) => setParam("broker_state", event.target.value)}>
              <option value="">{t("broker.history.allStates")}</option>
              {invalidState ? <option value={state}>{t("broker.history.invalidFilter")}</option> : null}
              {Object.entries(stateLabels).map(([value, key]) => (
                <option key={value} value={value}>
                  {t(key)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("source.broker.method.86e0708911")} description={t("broker.history.methodHelp")}>
          {(control) => <Input {...control} maxLength={128} value={filters.method} onChange={(event) => setParam("broker_method", event.target.value)} />}
        </Field>
      </div>
      {listAction.runnable && !list.error && !invalidState && list.data ? (
        <p className="text-caption text-muted-foreground">
          {t("broker.history.asOf", { at: formatDateTime(list.data.generated_at) })}{" "}
          {t(freshnessLabels[list.data.projection_state] ?? "broker.freshness.unknown")}
        </p>
      ) : null}
      <DataGrid
        ariaLabel={t("source.ai.agent.broker.identities.6ec86399a3")}
        rows={listAction.runnable && !invalidState ? (list.data?.items ?? []) : []}
        columns={columns}
        getRowId={(item) => item.certificate_id}
        state={
          !listAction.runnable
            ? listAction.state === "denied"
              ? "permission-denied"
              : "unavailable"
            : invalidState || list.error
              ? "error"
              : list.loading
                ? "loading"
                : list.data?.items.length
                  ? "ready"
                  : "empty"
        }
        stateTitle={invalidState ? t("broker.history.invalidFilter") : list.error ? t("broker.history.failed") : t("broker.history.empty")}
        stateMessage={list.error ? t("broker.history.readFailure") : t("broker.history.scope")}
        onRowOpen={detailAction.runnable ? (item) => setParam("broker_id", item.certificate_id) : undefined}
        rowActionLabel={() => t("broker.openRecord")}
        pagination={
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" disabled={!listAction.runnable || list.fetching || invalidState} onClick={list.refetch}>
              {t("broker.history.refresh")}
            </Button>
            {filters.cursor ? (
              <Button type="button" variant="outline" onClick={() => setParam("broker_cursor", "")}>
                {t("broker.history.newest")}
              </Button>
            ) : null}
            {list.data?.next_cursor && !list.error ? (
              <Button
                type="button"
                variant="outline"
                disabled={list.fetching || !listAction.runnable}
                onClick={() => setParam("broker_cursor", list.data?.next_cursor ?? "")}
              >
                {t("broker.history.older")}
              </Button>
            ) : null}
          </div>
        }
      />
      <DetailDrawer
        open={Boolean(selectedID)}
        title={t("broker.record.title")}
        description={t("broker.record.description")}
        onClose={() => setParam("broker_id", "")}
        actions={
          <>
            <Link
              to={`/certificates?tab=crlct&certificate_id=${encodeURIComponent(row?.certificate_id ?? selectedID)}`}
              className={buttonVariants({ variant: "outline" })}
            >
              {t("broker.openRevocation")}
            </Link>
            <Link to="/audit?feature=F61" className={buttonVariants({ variant: "outline" })}>
              {t("workloads.attested.openAudit")}
            </Link>
          </>
        }
      >
        <CapabilityActionNotice action={detailAction} />
        {detailAction.runnable && detail.loading ? <LoadingState>{t("broker.record.loading")}</LoadingState> : null}
        {detailAction.runnable && detail.error ? (
          <ErrorState title={t("broker.history.failed")}>
            <p>{t("broker.history.readFailure")}</p>
            <Button type="button" variant="outline" onClick={detail.refetch}>
              {t("broker.history.refresh")}
            </Button>
          </ErrorState>
        ) : null}
        {row ? (
          <div className="grid gap-4">
            <BrokerState row={row} />
            <p className="text-sm">{row.state_reason}</p>
            <p className="text-caption text-muted-foreground">
              {t("broker.history.asOf", { at: formatDateTime(row.generated_at) })} {t(freshnessLabels[row.projection_state] ?? "broker.freshness.unknown")}
            </p>
            <dl className="grid gap-3 sm:grid-cols-2">
              <BrokerFact label={t("source.subject.6897128384")}>{row.certificate_subject}</BrokerFact>
              <BrokerFact label={t("source.expires.f6725f3af0")}>
                {row.not_after ? (
                  <time dateTime={row.not_after} title={row.not_after}>
                    {formatDateTime(row.not_after)}
                  </time>
                ) : (
                  t("broker.metadataUnavailable")
                )}
              </BrokerFact>
              <BrokerFact label={t("broker.validFrom")}>
                {row.not_before ? (
                  <time dateTime={row.not_before} title={row.not_before}>
                    {formatDateTime(row.not_before)}
                  </time>
                ) : (
                  t("broker.metadataUnavailable")
                )}
              </BrokerFact>
            </dl>
            {row.metadata_state === "recorded" && row.issuance ? (
              <>
                <h3 className="text-sm font-semibold">{t("broker.originalFacts")}</h3>
                <dl className="grid gap-3 sm:grid-cols-2">
                  <BrokerFact label={t("source.agent.id.510bce732d")}>{row.issuance.agent_id}</BrokerFact>
                  <BrokerFact label={t("source.broker.method.86e0708911")}>{row.issuance.method}</BrokerFact>
                  <BrokerFact label={t("source.broker.scopes.60ad7540e2")}>{row.issuance.scopes.join(", ")}</BrokerFact>
                  <BrokerFact label={t("workloads.ephemeral.effectiveTTL")}>
                    {t("workloads.ephemeral.seconds", { count: row.issuance.effective_ttl_seconds })}
                  </BrokerFact>
                </dl>
              </>
            ) : (
              <p className="border-s-2 border-status-warning ps-3 text-sm">{t("broker.metadataMissingBody")}</p>
            )}
            <WorkloadIdentityHandoff key={row.certificate_id} spiffeID={row.spiffe_id} />
            <details>
              <summary className="cursor-pointer text-sm font-medium">{t("workloads.attested.exactEvidence")}</summary>
              <dl className="mt-3 grid gap-3">
                <BrokerFact label={t("broker.certificateID")}>
                  <CredentialChip value={row.certificate_id} label={t("broker.certificateID")} />
                </BrokerFact>
                <BrokerFact label={t("broker.fingerprint")}>
                  <CredentialChip value={row.fingerprint} label={t("broker.fingerprint")} />
                </BrokerFact>
                {row.issuance ? (
                  <>
                    <BrokerFact label={t("broker.originalOwner")}>
                      <CredentialChip value={row.issuance.owner_id} label={t("broker.originalOwner")} />
                    </BrokerFact>
                    <BrokerFact label={t("broker.taskDigest")}>
                      {row.issuance.task_envelope_digest ? (
                        <CredentialChip value={row.issuance.task_envelope_digest} label={t("broker.taskDigest")} />
                      ) : (
                        t("broker.noTask")
                      )}
                    </BrokerFact>
                  </>
                ) : null}
                <BrokerFact label={t("broker.currentOwner")}>
                  {row.current_owner_id ? <CredentialChip value={row.current_owner_id} label={t("broker.currentOwner")} /> : t("broker.metadataUnavailable")}
                </BrokerFact>
              </dl>
            </details>
            <p className="text-sm text-muted-foreground">{t("broker.scopesHelp")}</p>
          </div>
        ) : null}
      </DetailDrawer>
    </section>
  );
}

function BrokerState({ row }: { row: BrokerAgentIdentityHistory }) {
  const { t } = useTranslation();
  const state = knownState(row.state) ? row.state : "unknown";
  return <StatusBadge value={state} label={t(stateLabels[state])} tone={state === "revoked" || state === "expired" ? "critical" : "neutral"} />;
}
