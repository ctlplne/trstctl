import { CredentialChip } from "@/components/CredentialChip";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { StatusBadge } from "@/components/StatusBadge";
import { Num } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { KubernetesCSRSupport, KubernetesTrustBundleDistribution } from "@/lib/api";
import type { KubernetesPostureObject } from "@/lib/api-types.gen";

type Report = KubernetesCSRSupport | KubernetesTrustBundleDistribution;

// A 200 response alone does not mean the controller finished its last pass.
// Older servers can omit summary, so absence stays pending rather than green.
export function kubernetesControllerBadgeValue(report: Report | null, readFailed = false): string {
  if (readFailed) return "failed";
  const summary = report?.summary;
  if (!summary || summary.controllers === 0) return "pending";
  if (summary.failed > 0) return "failed";
  if (summary.stale_controllers > 0 || summary.complete_controllers < summary.controllers) return "pending";
  return "active";
}

export function KubernetesControllerState({
  kind,
  report,
  loading,
  onRefresh,
}: {
  kind: "csr" | "trust-bundle";
  report: Report | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  const { t, formatDateTime } = useTranslation();
  const summary = report?.summary;
  const objects = report?.objects ?? [];
  const lastSync =
    report?.last_sync ??
    report?.controllers
      ?.map((item) => item.last_sync)
      .sort()
      .at(-1);
  const reasonLabel = (reason: string) => {
    if (reason === "issuer_binding_mismatch") return t("workloads.kubernetesLive.issuerBindingMismatch");
    if (reason === "invalid_signer_name") return t("workloads.kubernetesLive.invalidSignerName");
    return reason;
  };
  const label = kind === "csr" ? t("workloads.kubernetesCSR.heading") : t("workloads.trustBundles.heading");
  const columns: Array<DataGridColumn<KubernetesPostureObject>> = [
    {
      id: "object",
      header: t("workloads.kubernetesLive.object"),
      cell: (row) => (
        <span className="font-mono text-xs">
          {row.namespace ? t("workloads.kubernetesLive.qualifiedObject", { namespace: row.namespace, name: row.name }) : row.name}
        </span>
      ),
    },
    { id: "state", header: t("workloads.kubernetesLive.state"), cell: (row) => <StatusBadge value={row.state} /> },
    { id: "reason", header: t("workloads.kubernetesLive.reason"), cell: (row) => <span title={row.reason}>{reasonLabel(row.reason)}</span> },
    {
      id: "hash",
      header: t("workloads.kubernetesLive.publicHash"),
      cell: (row) => (row.public_hash ? <CredentialChip value={row.public_hash} label={t("workloads.kubernetesLive.publicHash")} /> : "—"),
    },
  ];

  return (
    <div className="grid gap-3" aria-label={t("workloads.kubernetesLive.evidenceFor", { name: label })}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">{t("workloads.kubernetesLive.heading")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {summary
              ? t("workloads.kubernetesLive.reportedControllers", {
                  complete: String(summary.complete_controllers),
                  total: String(summary.controllers),
                })
              : t("workloads.kubernetesLive.noReport")}
          </p>
          {lastSync && <p className="mt-1 text-xs text-muted-foreground">{t("workloads.kubernetesLive.lastSync", { time: formatDateTime(lastSync) })}</p>}
        </div>
        <Button type="button" variant="outline" size="sm" onClick={onRefresh} disabled={loading}>
          {t("workloads.kubernetesLive.refresh")}
        </Button>
      </div>
      {summary && (
        <div className="grid gap-3 sm:grid-cols-4" aria-label={t("workloads.kubernetesLive.counts")}>
          <p className="text-sm">
            {t("workloads.kubernetesLive.ready")}: <Num>{summary.ready}</Num>
          </p>
          <p className="text-sm">
            {t("workloads.kubernetesLive.pending")}: <Num>{summary.pending}</Num>
          </p>
          <p className="text-sm">
            {t("workloads.kubernetesLive.failed")}: <Num>{summary.failed}</Num>
          </p>
          <p className="text-sm">
            {t("workloads.kubernetesLive.stale")}: <Num>{summary.stale_controllers}</Num>
          </p>
        </div>
      )}
      <DataGrid
        ariaLabel={t("workloads.kubernetesLive.objectsFor", { name: label })}
        rows={objects}
        columns={columns}
        getRowId={(row) => `${row.cluster_id}:${row.uid}`}
        state={loading && !report ? "loading" : !summary ? "unavailable" : objects.length === 0 ? "empty" : "ready"}
        stateTitle={!summary ? t("workloads.kubernetesLive.noReport") : t("workloads.kubernetesLive.noObjects")}
        stateMessage={!summary ? t("workloads.kubernetesLive.noReportDetail") : t("workloads.kubernetesLive.noObjectsDetail")}
      />
    </div>
  );
}
