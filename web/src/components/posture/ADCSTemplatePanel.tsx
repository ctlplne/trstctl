import { useMemo } from "react";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { StatusBadge } from "@/components/StatusBadge";
import { api, type ADCSInventorySource, type ADCSTemplate } from "@/lib/api";
import { formatDateTime } from "@/i18n/format";
import { translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { useApiQuery } from "@/lib/query";

/**
 * AD CS certificate template posture (epic F1).
 *
 * The source cards answer whether an in-domain reader is pending, running,
 * successful, or failed. The grid answers what it read, including the
 * canonical Windows SIDs granted certificate-enrollment rights. Raw directory
 * descriptors and bind credentials never cross this surface.
 */
export function ADCSTemplatePanel() {
  const query = useApiQuery(["posture", "adcs"], api.adcsPosture, { live: { intervalMs: 10_000 } });
  const posture = query.data;
  const templates = posture?.templates ?? [];
  const sources = posture?.sources ?? [];

  const columns = useMemo<Array<DataGridColumn<ADCSTemplate>>>(
    () => [
      {
        id: "template",
        header: translateNow("source.adcs.col.template.f1adcs0010"),
        cell: (template) => (
          <span className="grid gap-1">
            <span className="font-mono text-xs font-semibold">{template.template}</span>
            {template.display_name ? <span className="text-xs text-muted-foreground">{template.display_name}</span> : null}
          </span>
        ),
      },
      {
        id: "risk",
        header: translateNow("source.adcs.col.risk.f1adcs0011"),
        cell: (template) => <StatusBadge value={template.worst_severity || "none"} vocabulary="risk" />,
      },
      {
        id: "principals",
        header: translateNow("source.principal.afc19f1734"),
        cell: (template) => (
          <span className={`break-all text-xs ${(template.enrollment_principals ?? []).length ? "font-mono" : "text-muted-foreground"}`}>
            {(template.enrollment_principals ?? []).join(", ") || translateNow("source.none.dc937b5989")}
          </span>
        ),
      },
      {
        id: "published",
        header: translateNow("source.adcs.col.published.f1adcs0012"),
        cell: (template) =>
          (template.published_by ?? []).length === 0 ? (
            <span className="text-xs text-muted-foreground">{translateNow("source.adcs.unpublished.f1adcs0014")}</span>
          ) : (
            <span className="text-xs">{(template.published_by ?? []).join(", ")}</span>
          ),
      },
      {
        id: "findings",
        header: translateNow("source.adcs.col.findings.f1adcs0013"),
        cell: (template) =>
          (template.findings ?? []).length === 0 ? (
            <span className="text-xs text-muted-foreground">{translateNow("source.adcs.clean.f1adcs0015")}</span>
          ) : (
            <ul className="grid gap-2">
              {(template.findings ?? []).map((finding) => (
                <li key={finding.id}>
                  <span className="font-mono text-xs">{finding.id}</span>
                  <span className="block text-xs">{finding.summary}</span>
                  <span className="block text-xs text-muted-foreground">
                    {translateNow("source.adcs.remediation.f1adcs0016")} {finding.remediation}
                  </span>
                  {(finding.evidence ?? []).length > 0 ? (
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {translateNow("source.adcs.evidence.f3adcs0001")}{" "}
                      {(finding.evidence ?? []).map((ref) => `${ref.attribute} = ${ref.observed}`).join(" · ")}
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
          ),
      },
    ],
    [],
  );

  let gridState: DataGridState = "ready";
  if (query.loading) gridState = "loading";
  else if (query.error) gridState = "error";
  else if (templates.length === 0) gridState = "empty";

  return (
    <div className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="adcs-heading" className="text-title font-semibold">
          {translateNow("source.adcs.heading.f1adcs0001")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.adcs.description.f1adcs0002")}</p>
      </div>

      {!query.loading && !query.error && sources.length > 0 ? <ADCSSourceLifecycle sources={sources} /> : null}

      {!query.loading && !query.error && posture?.observed ? (
        <dl className="grid gap-2 rounded-panel border border-border bg-card p-3 text-sm shadow-elevation1 sm:grid-cols-3">
          <div>
            <dt className="text-caption text-muted-foreground">{translateNow("source.adcs.critical.f1adcs0007")}</dt>
            <dd className={posture.critical > 0 ? "font-medium text-status-critical" : "font-medium"}>{posture.critical}</dd>
          </div>
          <div>
            <dt className="text-caption text-muted-foreground">{translateNow("source.adcs.high.f1adcs0008")}</dt>
            <dd className={posture.high > 0 ? "font-medium text-status-warning" : "font-medium"}>{posture.high}</dd>
          </div>
          <div>
            <dt className="text-caption text-muted-foreground">{translateNow("source.adcs.templates.f1adcs0009")}</dt>
            <dd className="font-medium">{templates.length}</dd>
          </div>
        </dl>
      ) : null}

      <DataGrid
        ariaLabel={translateNow("source.adcs.heading.f1adcs0001")}
        rows={templates}
        columns={columns}
        getRowId={(template) => `${template.domain}/${template.template}`}
        state={gridState}
        stateTitle={query.error ? translateNow("source.adcs.error.f1adcs0004") : translateNow("source.adcs.unobserved.title.f1adcs0005")}
        stateMessage={query.error ?? translateNow("source.adcs.unobserved.body.f1adcs0006")}
        virtualization={false}
      />

      {templates[0]?.observed_at ? (
        <p className="text-xs text-muted-foreground">
          {translateNow("source.adcs.observed.f1adcs0017")} {formatDateTime(templates[0].observed_at)}
          {templates[0].observed_by ? (
            <>
              {" · "}
              {translateNow("source.adcs.observedby.f1adcs0022")} <span className="font-mono">{templates[0].observed_by}</span>
            </>
          ) : null}
        </p>
      ) : null}

      {posture?.guidance ? <p className="text-xs text-status-warning">{posture.guidance}</p> : null}
    </div>
  );
}

function ADCSSourceLifecycle({ sources }: { sources: ADCSInventorySource[] }) {
  return (
    <ul aria-label={translateNow("discovery.tabs.sources")} className="grid gap-2 md:grid-cols-2">
      {sources.map((source) => (
        <li key={source.source_id} className="grid gap-2 rounded-panel border border-border bg-card p-3 shadow-elevation1">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <span className="text-sm font-medium">{source.name}</span>
            <StatusBadge
              value={source.last_run_status}
              vocabulary="lifecycle"
              label={translateNow(`protocols.ari.${source.last_run_status}` as MessageKey)}
              tone={
                source.last_run_status === "failed"
                  ? "critical"
                  : source.last_run_status === "succeeded"
                    ? "success"
                    : source.last_run_status === "running"
                      ? "observe"
                      : "neutral"
              }
            />
          </div>
          {source.last_run_created_at ? <time className="text-xs text-muted-foreground">{formatDateTime(source.last_run_created_at)}</time> : null}
          {source.last_run_error ? <p className="text-xs text-status-critical">{source.last_run_error}</p> : null}
        </li>
      ))}
    </ul>
  );
}
