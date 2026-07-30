import { useMemo } from "react";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { useCan } from "@/components/rbac";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEARIPosture } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

type ARIPostureItem = ACMEARIPosture["items"][number];
type ARIPostureRead = { kind: "ready"; posture: ACMEARIPosture } | { kind: "permission-denied" } | { kind: "unavailable" };

async function readARIPosture(): Promise<ARIPostureRead> {
  try {
    let cursor: string | undefined;
    let posture: ACMEARIPosture | undefined;
    const seenCursors = new Set<string>();
    do {
      const page = await api.acmeARIPosture({ limit: 100, cursor });
      if (!posture) {
        posture = {
          ...page,
          items: [...page.items],
          summary: { ...page.summary },
        };
      } else {
        posture.items.push(...page.items);
        posture.summary.affected_certificates += page.summary.affected_certificates;
        posture.summary.published += page.summary.published;
        posture.summary.scheduler_pending += page.summary.scheduler_pending;
        posture.summary.scheduler_consumed += page.summary.scheduler_consumed;
        posture.summary.scheduler_failed += page.summary.scheduler_failed;
      }
      cursor = page.next_cursor;
      if (cursor) {
        if (seenCursors.has(cursor)) throw new Error("ARI posture returned a repeated cursor");
        seenCursors.add(cursor);
      }
    } while (cursor);
    if (!posture) throw new Error("ARI posture returned no page");
    delete posture.next_cursor;
    return { kind: "ready", posture };
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return { kind: "permission-denied" };
    if (error instanceof ApiError && [0, 404, 501, 503].includes(error.status)) return { kind: "unavailable" };
    throw error;
  }
}

export function ARIPosturePanel() {
  const { formatDateTime, t } = useTranslation();
  const canRead = useCan("lifecycle:read");
  const available = typeof api.acmeARIPosture === "function";
  const query = useApiQuery(["acme", "ari", "posture"], readARIPosture, { enabled: canRead && available });
  const posture = query.data?.kind === "ready" ? query.data.posture : null;
  const rows = posture?.items ?? [];

  const columns = useMemo<Array<DataGridColumn<ARIPostureItem>>>(
    () => [
      {
        id: "certificate",
        header: t("protocols.ari.certificate"),
        cell: (item) => (
          <span className="grid gap-1">
            <span className="font-medium">{item.identity_name || item.certificate_id}</span>
            <span className="break-all font-mono text-xs text-muted-foreground">{item.certificate_id}</span>
            <StatusBadge vocabulary="certificate" value={item.certificate_status} />
          </span>
        ),
      },
      {
        id: "publication",
        header: t("protocols.ari.publication"),
        cell: (item) => <PublicationBadge status={item.publication_status} />,
      },
      {
        id: "window",
        header: t("protocols.ari.suggestedWindow"),
        cell: (item) =>
          item.suggested_window ? (
            <span>
              {t("protocols.ari.windowRange", {
                start: formatDateTime(item.suggested_window.start),
                end: formatDateTime(item.suggested_window.end),
              })}
            </span>
          ) : (
            <span className="text-muted-foreground">{t("protocols.ari.noWindow")}</span>
          ),
      },
      {
        id: "scheduler",
        header: t("protocols.ari.scheduler"),
        cell: (item) => (
          <span className="grid gap-1">
            <SchedulerBadge consumed={item.scheduler_consumed} status={item.scheduler_status} />
            <span className="text-xs text-muted-foreground">{schedulerSourceLabel(item.scheduler_source, t)}</span>
            {item.consumed_at ? (
              <span className="text-xs text-muted-foreground">{t("protocols.ari.consumedAt", { at: formatDateTime(item.consumed_at) })}</span>
            ) : null}
            {item.rotation_run_id ? (
              <span className="break-all font-mono text-xs text-muted-foreground">{t("protocols.ari.rotationRun", { id: item.rotation_run_id })}</span>
            ) : null}
          </span>
        ),
      },
    ],
    [formatDateTime, t],
  );

  let state: DataGridState = "ready";
  let stateTitle: string | undefined;
  let stateMessage: string | undefined;
  if (!canRead || query.data?.kind === "permission-denied") {
    state = "permission-denied";
    stateMessage = t("protocols.ari.permissionDenied");
  } else if (!available || query.data?.kind === "unavailable" || posture?.served === false) {
    state = "unavailable";
    stateTitle = t("protocols.ari.unavailableTitle");
    stateMessage = t("protocols.ari.unavailableBody");
  } else if (query.loading) {
    state = "loading";
    stateMessage = t("protocols.ari.loading");
  } else if (query.error || !posture) {
    state = "error";
    stateTitle = t("protocols.ari.loadFailed");
    stateMessage = t("protocols.ari.loadFailedBody");
  } else if (rows.length === 0) {
    state = "empty";
    stateTitle = t("protocols.ari.emptyTitle");
    stateMessage = t("protocols.ari.emptyBody");
  }

  return (
    <section aria-labelledby="acme-ari-heading" className="grid gap-3">
      <div>
        <h2 id="acme-ari-heading" className="text-title font-semibold">
          {t("protocols.ari.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("protocols.ari.description")}</p>
      </div>

      {posture ? (
        <dl className="grid gap-3 sm:grid-cols-2">
          <div className="ui-panel p-3 text-sm">
            <dt className="font-medium">{t("protocols.ari.publication")}</dt>
            <dd className="mt-2 grid justify-items-start gap-1">
              <StatusBadge
                value={posture.publication_status}
                label={posture.publication_status === "served" ? t("protocols.ari.publicationServed") : t("protocols.ari.publicationNotServed")}
                tone={posture.publication_status === "served" ? "success" : "warning"}
              />
              {posture.publication_endpoint ? <code className="break-all text-xs text-muted-foreground">{posture.publication_endpoint}</code> : null}
            </dd>
          </div>
          <div className="ui-panel p-3 text-sm">
            <dt className="font-medium">{t("protocols.ari.scheduler")}</dt>
            <dd className="mt-2">
              <StatusBadge
                value={posture.scheduler_status}
                label={posture.scheduler_status === "enabled" ? t("protocols.ari.schedulerEnabled") : t("protocols.ari.schedulerDisabled")}
                tone={posture.scheduler_status === "enabled" ? "success" : "warning"}
              />
            </dd>
          </div>
        </dl>
      ) : null}

      <DataGrid
        ariaLabel={t("protocols.ari.listLabel")}
        rows={rows}
        columns={columns}
        getRowId={(item) => item.certificate_id}
        state={state}
        stateTitle={stateTitle}
        stateMessage={stateMessage}
        virtualization={false}
      />
    </section>
  );
}

function PublicationBadge({ status }: { status: ARIPostureItem["publication_status"] }) {
  const { t } = useTranslation();
  const labels = {
    published: t("protocols.ari.published"),
    not_published: t("protocols.ari.notPublished"),
    identifier_unavailable: t("protocols.ari.identifierUnavailable"),
  } as const;
  return <StatusBadge value={status} label={labels[status]} tone={status === "published" ? "success" : "warning"} />;
}

function SchedulerBadge({ consumed, status }: { consumed: boolean; status: ARIPostureItem["scheduler_status"] }) {
  const { t } = useTranslation();
  if (status === "failed") return <StatusBadge value={status} label={t("protocols.ari.failed")} tone="critical" />;
  if (status === "running") return <StatusBadge value={status} label={t("protocols.ari.running")} tone="observe" />;
  if (consumed) return <StatusBadge value="consumed" label={t("protocols.ari.consumed")} tone="success" />;
  const labels = {
    pending: t("protocols.ari.pending"),
    running: t("protocols.ari.running"),
    succeeded: t("protocols.ari.succeeded"),
    failed: t("protocols.ari.failed"),
    not_applicable: t("protocols.ari.notApplicable"),
  } as const;
  const tones = {
    pending: "warning",
    succeeded: "success",
    not_applicable: "neutral",
  } as const;
  return <StatusBadge value={status} label={labels[status]} tone={tones[status]} />;
}

function schedulerSourceLabel(source: ARIPostureItem["scheduler_source"], t: ReturnType<typeof useTranslation>["t"]): string {
  const labels = {
    ari: t("protocols.ari.sourceARI"),
    fixed_threshold: t("protocols.ari.sourceFixedThreshold"),
    manual: t("protocols.ari.sourceManual"),
    none: t("protocols.ari.sourceNone"),
    unknown_scheduler: t("protocols.ari.sourceUnknown"),
  } as const;
  return labels[source];
}
