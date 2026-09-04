import { ScrollableTableRegion } from "@/components/ScrollableTableRegion";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import type { ComplianceInventoryReport, ComplianceReportSchedule, NHIComplianceReport } from "@/lib/api";

const reportTypeMessageKeys: Record<string, MessageKey> = {
  inventory_snapshot: "policy.reportType.inventorySnapshot",
  framework_evidence_pack: "policy.reportType.frameworkEvidencePack",
  cbom_posture: "policy.reportType.cbomPosture",
  audit_summary: "policy.reportType.auditSummary",
  nhi_compliance_mapping: "policy.reportType.nhiComplianceMapping",
};

export function ComplianceInventoryReportPanel({
  report,
  schedules,
  scheduleAction,
  onToggleSchedule,
}: {
  report: ComplianceInventoryReport;
  schedules: ComplianceReportSchedule[];
  scheduleAction: string | null;
  onToggleSchedule: (schedule: ComplianceReportSchedule) => void;
}) {
  const { formatDate, t } = useTranslation();
  const rows = schedules.length > 0 ? schedules : report.schedules;

  return (
    <section aria-labelledby="compliance-inventory-report-heading" className="ui-panel min-w-0 p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="compliance-inventory-report-heading" className="text-title font-semibold">
            {t("policy.reporting.heading")}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {t("policy.reporting.generated", { capability: report.capability, date: formatDate(report.generated_at) })}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{t("policy.reporting.auditExport")}</span>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t("policy.reporting.inventoryRows")} value={String(report.summary.inventory_rows)} />
        <Metric label={t("policy.reporting.certificates")} value={String(report.summary.certificates)} />
        <Metric label={t("policy.reporting.cryptoAssets")} value={String(report.summary.crypto_assets)} />
        <Metric label={t("policy.reporting.discoverySchedules")} value={String(report.summary.discovery_schedules)} />
        <Metric label={t("policy.reporting.frameworks")} value={String(report.summary.frameworks_supported)} />
        <Metric label={t("policy.reporting.reportTypes")} value={String(report.summary.report_types_supported)} />
        <Metric label={t("policy.reporting.schedules")} value={String(report.summary.report_schedules)} />
        <Metric label={t("policy.reporting.enabledSchedules")} value={String(report.summary.enabled_report_schedules)} />
      </dl>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.reporting.reportTypeList")} items={report.report_types.map((reportType) => reportTypeLabel(reportType, t))} />
        <EvidenceList title={t("policy.reporting.routeList")} items={report.routes} />
      </div>

      {rows.length > 0 ? (
        <ScrollableTableRegion className="mt-4" label={t("policy.reporting.tableCaption")}>
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">{t("policy.reporting.tableCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.reporting.schedule")}</th>
                <th scope="col">{t("policy.reporting.framework")}</th>
                <th scope="col">{t("policy.reporting.type")}</th>
                <th scope="col">{t("policy.reporting.cadence")}</th>
                <th scope="col">{t("policy.reporting.nextRun")}</th>
                <th scope="col">{t("policy.reporting.recovery")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((schedule) => (
                <tr key={schedule.id}>
                  <td>
                    <p className="font-medium">{schedule.name}</p>
                    {schedule.recipient_ref && <p className="mt-1 font-mono text-xs text-muted-foreground">{schedule.recipient_ref}</p>}
                  </td>
                  <td>{schedule.framework}</td>
                  <td>{reportTypeLabel(schedule.report_type, t)}</td>
                  <td>{Math.round(schedule.interval_seconds / 86400)}d</td>
                  <td>{formatDate(schedule.next_run_at)}</td>
                  <td>
                    <Button type="button" variant="outline" onClick={() => onToggleSchedule(schedule)} disabled={scheduleAction !== null}>
                      {scheduleAction === `${schedule.enabled ? "pause" : "resume"}:${schedule.id}`
                        ? schedule.enabled
                          ? t("policy.reporting.pausing")
                          : t("policy.reporting.resuming")
                        : schedule.enabled
                          ? t("policy.reporting.pause")
                          : t("policy.reporting.resume")}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollableTableRegion>
      ) : (
        <p className="mt-4 rounded-md border border-border p-3 text-muted-foreground">{t("policy.reporting.empty")}</p>
      )}
    </section>
  );
}

export function NHIComplianceReportPanel({ report }: { report: NHIComplianceReport }) {
  const { formatDate, t } = useTranslation();
  const controlRows = report.controls.slice(0, 8);

  return (
    <section aria-labelledby="nhi-compliance-report-heading" className="ui-panel min-w-0 p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="nhi-compliance-report-heading" className="text-title font-semibold">
            {t("policy.nhiCompliance.heading")}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {t("policy.nhiCompliance.generated", {
              capability: report.capability,
              date: formatDate(report.generated_at),
              state: report.audit_ready ? t("policy.nhiCompliance.auditReady") : t("policy.nhiCompliance.draft"),
            })}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{report.format}</span>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t("policy.nhiCompliance.nhiRows")} value={String(report.summary.total_nhis)} />
        <Metric label={t("policy.nhiCompliance.frameworks")} value={String(report.summary.frameworks_supported)} />
        <Metric label={t("policy.nhiCompliance.mappedControls")} value={String(report.summary.controls_mapped)} />
        <Metric label={t("policy.nhiCompliance.overprivileged")} value={String(report.summary.overprivileged_findings)} />
        <Metric label={t("policy.nhiCompliance.staleFindings")} value={String(report.summary.stale_findings)} />
        <Metric label={t("policy.nhiCompliance.staticCredentials")} value={String(report.summary.static_credential_findings)} />
        <Metric label={t("policy.nhiCompliance.evidenceRefs")} value={String(report.summary.audit_evidence_refs)} />
        <Metric label={t("policy.nhiCompliance.attestations")} value={String(report.summary.operator_attestation_needed)} />
      </dl>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.nhiCompliance.frameworkList")} items={report.frameworks.map((framework) => `${framework.name} ${framework.version}`)} />
        <EvidenceList title={t("policy.nhiCompliance.evidenceRoutes")} items={report.routes} />
      </div>

      {controlRows.length > 0 && (
        <ScrollableTableRegion className="mt-4" label={t("policy.nhiCompliance.tableCaption")}>
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">{t("policy.nhiCompliance.tableCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.nhiCompliance.frameworkColumn")}</th>
                <th scope="col">{t("policy.nhiCompliance.controlColumn")}</th>
                <th scope="col">{t("policy.nhiCompliance.statusColumn")}</th>
                <th scope="col">{t("policy.nhiCompliance.evidenceColumn")}</th>
              </tr>
            </thead>
            <tbody>
              {controlRows.map((control) => (
                <tr key={`${control.framework}:${control.control_id}`} className="align-top">
                  <td>{control.framework}</td>
                  <td>
                    <p className="font-medium">{control.title}</p>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">{control.control_id}</p>
                  </td>
                  <td>
                    <p>{control.status}</p>
                    <p className="mt-1 text-xs text-muted-foreground">{t("policy.nhiCompliance.mappedSignals", { count: control.finding_count })}</p>
                  </td>
                  <td>{control.evidence_refs.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollableTableRegion>
      )}

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.reporting.reportTypeList")} items={report.report_types.map((reportType) => reportTypeLabel(reportType, t))} />
        <EvidenceList title={t("policy.nhiCompliance.residualAttestations")} items={report.residuals} />
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className="text-base font-semibold">{value}</dd>
    </div>
  );
}

function EvidenceList({ items, title }: { items: string[]; title: string }) {
  return (
    <div role="group" aria-label={title} className="rounded-md border border-border p-3">
      <p className="font-medium">{title}</p>
      {items.length > 0 ? (
        <ul className="mt-2 grid gap-1 text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-muted-foreground">{translateNow("source.no.labels.in.this.pack.afb9ef5039")}</p>
      )}
    </div>
  );
}

function reportTypeLabel(value: string, t: (key: MessageKey) => string): string {
  const key = reportTypeMessageKeys[value];
  return key ? t(key) : value;
}
