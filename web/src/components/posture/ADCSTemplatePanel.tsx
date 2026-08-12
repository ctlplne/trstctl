import { useMemo } from "react";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { StatusBadge } from "@/components/StatusBadge";
import { api, type ADCSEnrollmentService, type ADCSInventorySource, type ADCSTemplate } from "@/lib/api";
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
  const driftQuery = useApiQuery(["posture", "adcs", "drift"], api.adcsDrift, { live: { intervalMs: 10_000 } });
  const posture = query.data;
  const templates = posture?.templates ?? [];
  const sources = posture?.sources ?? [];
  const services = posture?.enrollment_services ?? [];

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

      {!query.loading && !query.error ? <ADCSEnrollmentServices services={services} /> : null}

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

      <ADCSDriftHistory items={driftQuery.data?.items ?? []} loading={driftQuery.loading} error={driftQuery.error} />

      {posture?.guidance ? <p className="text-xs text-status-warning">{posture.guidance}</p> : null}
    </div>
  );
}

function ADCSEnrollmentServices({ services }: { services: ADCSEnrollmentService[] }) {
  return (
    <section aria-labelledby="adcs-services-heading" className="grid gap-2 border-t border-border pt-4">
      <div>
        <h3 id="adcs-services-heading" className="text-sm font-semibold">
          {translateNow("source.adcs.services.heading.aud370003")}
        </h3>
        <p className="text-xs text-muted-foreground">{translateNow("source.adcs.services.help.aud370004")}</p>
      </div>
      {services.length === 0 ? <p className="text-sm text-muted-foreground">{translateNow("source.adcs.services.empty.aud370005")}</p> : null}
      <ul className="grid gap-2">
        {services.map((service) => (
          <li key={`${service.domain}/${service.service}`} className="grid gap-3 rounded-panel border border-border bg-card p-3 shadow-elevation1">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <span>
                <span className="block font-mono text-xs font-semibold">{service.service}</span>
                {service.dns_name ? <span className="block font-mono text-xs text-muted-foreground">{service.dns_name}</span> : null}
              </span>
              <StatusBadge value={service.worst_severity || "none"} vocabulary="risk" />
            </div>
            <dl className="grid gap-2 text-xs sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">{translateNow("source.adcs.restrictions.aud370006")}</dt>
                <dd>
                  <span className="font-mono">{service.agent_restriction_state}</span> · {service.agent_restriction_source}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{translateNow("source.adcs.ces.aud370007")}</dt>
                <dd className="break-all font-mono">{service.enrollment_web_services.join(", ") || translateNow("source.none.dc937b5989")}</dd>
              </div>
            </dl>
            <ul className="grid gap-1">
              {service.endpoints.map((endpoint) => (
                <li key={`${endpoint.kind}/${endpoint.url}`} className="grid gap-1 border-l-2 border-status-info pl-2 text-xs">
                  <span className="font-medium">
                    {endpoint.kind} · <span className="font-mono">{endpoint.state}</span>
                    {endpoint.http_status ? (
                      <>
                        {" · "}
                        {translateNow("source.adcs.http.aud370019")} {endpoint.http_status}
                      </>
                    ) : null}
                  </span>
                  <span className="break-all font-mono text-muted-foreground">{endpoint.url}</span>
                  <span className="text-muted-foreground">
                    {translateNow("source.adcs.tls.aud370008")}:{" "}
                    {endpoint.tls_verified ? translateNow("source.adcs.verified.aud370009") : translateNow("source.adcs.unverified.aud370010")} ·{" "}
                    {translateNow("source.adcs.epa.aud370011")}: {endpoint.extended_protection}
                  </span>
                </li>
              ))}
            </ul>
            <ADCSFindingList findings={service.findings} />
            <p className="text-xs text-muted-foreground">
              {formatDateTime(service.observed_at)} · {translateNow("source.adcs.observedby.f1adcs0022")}{" "}
              <span className="font-mono">{service.observed_by}</span>
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}

function ADCSFindingList({ findings }: { findings: ADCSEnrollmentService["findings"] }) {
  if (findings.length === 0) return <p className="text-xs text-muted-foreground">{translateNow("source.adcs.clean.f1adcs0015")}</p>;
  return (
    <ul className="grid gap-2">
      {findings.map((finding) => (
        <li key={finding.id} className="text-xs">
          <span className="font-mono">{finding.id}</span>
          <span className="block">{finding.summary}</span>
          <span className="block text-muted-foreground">
            {translateNow("source.adcs.remediation.f1adcs0016")} {finding.remediation}
          </span>
          {finding.evidence && finding.evidence.length > 0 ? (
            <span className="block text-muted-foreground">
              {translateNow("source.adcs.evidence.f3adcs0001")} {finding.evidence.map((ref) => `${ref.attribute} = ${ref.observed}`).join(" · ")}
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function ADCSDriftHistory({ items, loading, error }: { items: Awaited<ReturnType<typeof api.adcsDrift>>["items"]; loading: boolean; error: string | null }) {
  return (
    <section aria-labelledby="adcs-drift-heading" className="grid gap-2 border-t border-border pt-4">
      <div>
        <h3 id="adcs-drift-heading" className="text-sm font-semibold">
          {translateNow("source.adcs.drift.heading.aud360001")}
        </h3>
        <p className="text-xs text-muted-foreground">{translateNow("source.adcs.drift.description.aud360002")}</p>
      </div>
      {loading ? <p className="text-sm text-muted-foreground">{translateNow("source.adcs.drift.loading.aud360003")}</p> : null}
      {error ? <p className="text-sm text-status-critical">{translateNow("source.adcs.drift.error.aud360004")}</p> : null}
      {!loading && !error && items.length === 0 ? <p className="text-sm text-muted-foreground">{translateNow("source.adcs.drift.empty.aud360005")}</p> : null}
      {items.length > 0 ? (
        <ol className="grid gap-2">
          {items.map((item) => (
            <li key={item.id} className="grid gap-2 rounded-panel border border-border bg-card p-3 shadow-elevation1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold">{item.domain}</span>
                <StatusBadge
                  value={item.direction}
                  vocabulary="lifecycle"
                  tone={item.direction === "worse" ? "critical" : item.direction === "better" ? "success" : "neutral"}
                />
              </div>
              <ul className="grid gap-2">
                {item.changes.map((change, index) => (
                  <li key={`${item.id}/${change.template}/${change.attribute ?? index}`} className="grid gap-1 border-l-2 border-status-warning pl-2 text-xs">
                    <span className="font-medium">{change.template}</span>
                    <span>{change.change}</span>
                    {change.before || change.after ? (
                      <dl className="grid gap-1 text-muted-foreground sm:grid-cols-2">
                        <div>
                          <dt>{translateNow("source.adcs.drift.before.aud360006")}</dt>
                          <dd className="break-all font-mono">{change.before || translateNow("source.none.dc937b5989")}</dd>
                        </div>
                        <div>
                          <dt>{translateNow("source.adcs.drift.after.aud360007")}</dt>
                          <dd className="break-all font-mono">{change.after || translateNow("source.none.dc937b5989")}</dd>
                        </div>
                      </dl>
                    ) : null}
                  </li>
                ))}
                {item.lifecycle.map((change) => (
                  <li
                    key={`${item.id}/${change.template}/${change.lifecycle}`}
                    className="flex flex-wrap items-center gap-2 border-l-2 border-status-info pl-2 text-xs"
                  >
                    <span className="font-medium">{change.template}</span>
                    <StatusBadge
                      value={change.lifecycle}
                      vocabulary="lifecycle"
                      tone={change.now_dangerous ? "critical" : change.was_dangerous ? "success" : "info"}
                    />
                    {change.was_dangerous ? (
                      <StatusBadge value="high" vocabulary="risk" label={translateNow("source.adcs.drift.dangerousBefore.aud360008")} />
                    ) : null}
                    {change.now_dangerous ? (
                      <StatusBadge value="critical" vocabulary="risk" label={translateNow("source.adcs.drift.dangerousNow.aud360009")} />
                    ) : null}
                  </li>
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">
                {formatDateTime(item.observed_at)} · {translateNow("source.adcs.observedby.f1adcs0022")} <span className="font-mono">{item.observed_by}</span>
              </p>
              <p className="text-xs text-muted-foreground">
                {translateNow("source.source.0e570ca6fa")} <span className="font-mono">{item.source_id}</span> · {translateNow("source.run.00d60e31a4")}{" "}
                <span className="font-mono">{item.run_id}</span>
              </p>
            </li>
          ))}
        </ol>
      ) : null}
    </section>
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
