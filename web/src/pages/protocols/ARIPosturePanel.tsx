import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { useCan } from "@/components/rbac";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEARIPosture } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

type ARIPostureItem = ACMEARIPosture["items"][number];
type ARIPostureRead = { kind: "ready"; posture: ACMEARIPosture } | { kind: "permission-denied" } | { kind: "unavailable" };

const windowLabelKeys = {
  served_acme: "protocols.ari.publication",
  upstream_ca: "protocols.ari.windowUpstream",
  local_estimate: "protocols.ari.windowEstimated",
  none: "protocols.ari.noWindow",
} as const;
const fetchLabelKeys = {
  not_requested: "protocols.ari.upstreamNotRequested",
  queued: "protocols.ari.pending",
  ready: "protocols.ari.succeeded",
  error: "protocols.ari.upstreamFailed",
  unavailable: "protocols.ari.upstreamNoARI",
} as const;
const schedulerLabels = {
  pending: "protocols.ari.pending",
  running: "protocols.ari.running",
  succeeded: "protocols.ari.succeeded",
  failed: "protocols.ari.failed",
  not_applicable: "protocols.ari.notApplicable",
  consumed: "protocols.ari.consumed",
} as const;
const schedulerTones = {
  pending: "warning",
  running: "observe",
  succeeded: "success",
  failed: "critical",
  not_applicable: "neutral",
  consumed: "success",
} as const;
const schedulerSourceKeys = {
  ari: "protocols.ari.sourceARI",
  fixed_threshold: "protocols.ari.sourceFixedThreshold",
  manual: "protocols.ari.sourceManual",
  none: "protocols.ari.sourceNone",
  unknown_scheduler: "protocols.ari.sourceUnknown",
} as const;

async function readARIPosture(): Promise<ARIPostureRead> {
  try {
    const posture = await api.acmeARIPosture({ limit: 100, cursor: undefined });
    let cursor = posture.next_cursor;
    const seenCursors = new Set<string>();
    while (cursor) {
      if (seenCursors.has(cursor)) throw new Error("ARI cursor repeated");
      seenCursors.add(cursor);
      const page = await api.acmeARIPosture({ limit: 100, cursor });
      posture.items.push(...page.items);
      cursor = page.next_cursor;
    }
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
  const query = useApiQuery(["acme", "ari", "posture"], readARIPosture, { enabled: canRead });
  const posture = query.data?.kind === "ready" ? query.data.posture : null;
  const rows = posture?.items ?? [];

  const columns: Array<DataGridColumn<ARIPostureItem>> = [
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
      cell: (item) => (
        <StatusBadge
          value={item.publication_status}
          label={publicationLabel(item.publication_status, t)}
          tone={item.publication_status === "published" ? "success" : "warning"}
        />
      ),
    },
    {
      id: "window",
      header: t("protocols.ari.suggestedWindow"),
      cell: (item) => (
        <span className="grid gap-1">
          <span className="font-medium">{windowSourceLabel(item.window_source, t)}</span>
          {item.suggested_window ? (
            <span>
              {t("protocols.ari.windowRange", {
                start: formatDateTime(item.suggested_window.start),
                end: formatDateTime(item.suggested_window.end),
              })}
            </span>
          ) : item.window_source !== "none" ? (
            <span className="text-muted-foreground">{t("protocols.ari.noWindow")}</span>
          ) : null}
          {item.upstream_status && item.upstream_status !== "ready" ? (
            <span className="text-xs text-muted-foreground">{upstreamStatusLabel(item.upstream_status, t)}</span>
          ) : null}
          {item.upstream_next_poll_at ? (
            <span className="text-xs text-muted-foreground">{t("protocols.ari.nextPollAt", { at: formatDateTime(item.upstream_next_poll_at) })}</span>
          ) : null}
        </span>
      ),
    },
    {
      id: "scheduler",
      header: t("protocols.ari.scheduler"),
      cell: (item) => (
        <span className="grid gap-1">
          {schedulerBadge(item.scheduler_consumed, item.scheduler_status, t)}
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
  ];

  let state: DataGridState = "ready";
  let stateTitle: string | undefined;
  let stateMessage: string | undefined;
  if (!canRead || query.data?.kind === "permission-denied") {
    state = "permission-denied";
    stateMessage = t("protocols.ari.permissionDenied");
  } else if (query.data?.kind === "unavailable" || posture?.served === false) {
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
      <h2 id="acme-ari-heading" className="text-title font-semibold">
        {t("protocols.ari.heading")}
      </h2>

      {posture ? (
        <p className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted-foreground">
          <span>
            {t("protocols.ari.publication")}:{" "}
            <strong>{posture.publication_status === "served" ? t("protocols.ari.publicationServed") : t("protocols.ari.publicationNotServed")}</strong>
          </span>
          <span>
            {t("protocols.ari.scheduler")}:{" "}
            <strong>{posture.scheduler_status === "enabled" ? t("protocols.ari.schedulerEnabled") : t("protocols.ari.schedulerDisabled")}</strong>
          </span>
        </p>
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

function publicationLabel(status: ARIPostureItem["publication_status"], t: ReturnType<typeof useTranslation>["t"]): string {
  if (status === "published") return t("protocols.ari.published");
  if (status === "not_published") return t("protocols.ari.notPublished");
  return t("protocols.ari.identifierUnavailable");
}

function schedulerBadge(consumed: boolean, status: ARIPostureItem["scheduler_status"], t: ReturnType<typeof useTranslation>["t"]) {
  const value = status === "failed" || status === "running" ? status : consumed ? "consumed" : status;
  return <StatusBadge value={value} label={t(schedulerLabels[value])} tone={schedulerTones[value]} />;
}

function schedulerSourceLabel(source: ARIPostureItem["scheduler_source"], t: ReturnType<typeof useTranslation>["t"]): string {
  return t(schedulerSourceKeys[source]);
}

function windowSourceLabel(source: ARIPostureItem["window_source"], t: ReturnType<typeof useTranslation>["t"]): string {
  return t(windowLabelKeys[source] ?? windowLabelKeys.none);
}

function upstreamStatusLabel(status: NonNullable<ARIPostureItem["upstream_status"]>, t: ReturnType<typeof useTranslation>["t"]): string {
  return t(fetchLabelKeys[status]);
}
