import { useState } from "react";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type OperationLedgerItem } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { OperationActionRunner } from "./OperationActionRunner";

const stateCopy = {
  reviewed: "operations.state.reviewed",
  awaiting_approval: "operations.state.awaitingApproval",
  queued: "operations.state.queued",
  executing: "operations.state.executing",
  delivered: "operations.state.delivered",
  verified: "operations.state.verified",
  failed: "operations.state.failed",
  uncertain: "operations.state.uncertain",
  recovered: "operations.state.recovered",
} as const;

const sourceCopy = {
  certificate_rotation: "operations.ledger.source.certificate_rotation",
  connector_delivery: "operations.ledger.source.connector_delivery",
  secret_rotation: "operations.ledger.source.secret_rotation",
  approval: "operations.ledger.source.approval",
} as const;

const stepCopy = {
  request: "operations.ledger.step.request",
  authority: "operations.ledger.step.authority",
  external_action: "operations.ledger.step.external_action",
  receipt: "operations.ledger.step.receipt",
  observation: "operations.ledger.step.observation",
  revocation: "operations.ledger.step.revocation",
} as const;

const linkCopy = {
  done: "operations.ledger.link.done",
  pending: "operations.ledger.link.pending",
  failed: "operations.ledger.link.failed",
  uncertain: "operations.ledger.link.uncertain",
  not_observed: "operations.ledger.link.not_observed",
} as const;

const actionCopy = { retry: "operations.ledger.action.retry", rollback: "operations.ledger.action.rollback" } as const;

/** The operations ledger (A245): every rotation, delivery, secret rotation and
 * approval in one normalized state, each with its causal chain and the retry
 * and rollback that apply to exactly it. */
export function OperationsLedgerPanel() {
  const { t, formatDateTime } = useTranslation();
  const [state, setState] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const result = useApiQuery(["operation-ledger", state], () => api.operationLedger({ limit: 50, state: state || undefined }), {
    retry: false,
    live: { intervalMs: 15_000 },
  });
  const items = result.data?.items ?? [];
  return (
    <section aria-labelledby="operations-ledger-heading" className="ui-panel grid gap-3 p-comfortable">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="operations-ledger-heading" className="text-title font-semibold">
            {t("operations.ledger.title")}
          </h2>
          <p className="max-w-3xl text-sm text-muted-foreground">{t("operations.ledger.help")}</p>
        </div>
        <Field label={t("operations.ledger.filter")}>
          {(field) => (
            <Select {...field} value={state} onChange={(event) => setState(event.target.value)}>
              <option value="">{t("operations.ledger.allStates")}</option>
              {(Object.keys(stateCopy) as (keyof typeof stateCopy)[]).map((value) => (
                <option key={value} value={value}>
                  {t(stateCopy[value])}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      {result.error ? (
        <div className="grid gap-2">
          <ErrorState title={t("operations.ledger.failed")}>{result.error}</ErrorState>
          <Button onClick={result.refetch}>{t("operations.ledger.retry")}</Button>
        </div>
      ) : !result.data ? (
        <LoadingState>{t("operations.ledger.loading")}</LoadingState>
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("operations.ledger.empty")}</p>
      ) : (
        <ul className="grid gap-2">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge vocabulary="operation" value={item.state} />
                <span className="font-medium">{item.subject.name || item.subject.id}</span>
                <span className="text-muted-foreground">{t(sourceCopy[item.source])}</span>
                <span className="text-xs text-muted-foreground">{t("operations.ledger.updated", { at: formatDateTime(item.updated_at) })}</span>
                <Button size="sm" variant="outline" className="ms-auto" onClick={() => setOpen(open === item.id ? null : item.id)}>
                  {t(open === item.id ? "operations.ledger.hide" : "operations.ledger.details")}
                </Button>
              </div>
              <p className="mt-1 text-muted-foreground">{item.state_reason}</p>
              {open === item.id && <OperationDetail item={item} />}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function OperationDetail({ item }: { item: OperationLedgerItem }) {
  const { t, formatDateTime } = useTranslation();
  const detail = useApiQuery(["operation-ledger-item", item.id], () => api.operationLedgerItem(item.id), { retry: false });
  if (detail.error) return <ErrorState title={t("operations.ledger.detailFailed")}>{detail.error}</ErrorState>;
  if (!detail.data) return <LoadingState>{t("operations.ledger.loading")}</LoadingState>;
  return (
    <div className="mt-2 grid gap-2 border-t border-border pt-2">
      <h3 className="font-medium">{t("operations.ledger.chain")}</h3>
      <ol className="grid list-decimal gap-1 ps-5">
        {(detail.data.chain ?? []).map((link, index) => (
          <li key={`${link.step}-${index}`}>
            <span className="font-medium">{t(stepCopy[link.step])}</span> · {t(linkCopy[link.state])} · {link.detail}
            {link.at && <span className="text-xs text-muted-foreground"> · {formatDateTime(link.at)}</span>}
          </li>
        ))}
      </ol>
      {(detail.data.actions ?? []).length > 0 && (
        <>
          <h3 className="font-medium">{t("operations.ledger.actions")}</h3>
          <ul className="grid gap-1">
            {(detail.data.actions ?? []).map((action) => (
              <li key={action.action}>
                <span className="font-medium">{t(actionCopy[action.action])}</span>:{" "}
                {action.available
                  ? t("operations.ledger.actionAvailable", { scope: action.scope })
                  : t("operations.ledger.actionUnavailable", { scope: action.scope, reason: action.reason ?? "" })}
                <OperationActionRunner action={action} label={t(actionCopy[action.action])} onDone={detail.refetch} />
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
