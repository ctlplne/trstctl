import { CredentialChip } from "@/components/CredentialChip";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { useTranslation } from "@/i18n/I18nProvider";
import type { CBOMAsset, PQCMigrationFindingProgress, PQCMigrationProgress } from "@/lib/api";

const statusKeys = {
  queued: "posture.pqcMigration.queuedStatus",
  issued: "posture.pqcMigration.issuedStatus",
  applied: "posture.pqcMigration.appliedStatus",
  failed: "posture.pqcMigration.failedStatus",
  rolled_back: "posture.pqcMigration.rolledBackStatus",
  rollback_failed: "posture.pqcMigration.rollbackFailedStatus",
  rollback_unverified: "posture.pqcMigration.rollbackUnverifiedStatus",
} as const;

export function PQCMigrationProgressDetails({ progress, assets, loading = false }: { progress: PQCMigrationProgress; assets: CBOMAsset[]; loading?: boolean }) {
  const { t } = useTranslation();
  const columns: DataGridColumn<PQCMigrationFindingProgress>[] = [
    {
      id: "asset",
      header: t("posture.pqcMigration.assetColumn"),
      cell: (row) =>
        assets.find((asset) => asset.id === row.asset_id)?.location || (
          <CredentialChip value={row.asset_id} label={t("posture.pqcMigration.assetIdentifier")} />
        ),
    },
    {
      id: "outcome",
      header: t("posture.pqcMigration.statusColumn"),
      cell: (row) => {
        const key = Object.prototype.hasOwnProperty.call(statusKeys, row.status) ? statusKeys[row.status as keyof typeof statusKeys] : undefined;
        return (
          <div className="grid gap-1">
            <span>{key ? t(key) : t("posture.pqcMigration.unknownStatus", { status: row.status })}</span>
            {row.failure ? <span className="text-sm text-destructive">{row.failure}</span> : null}
          </div>
        );
      },
    },
    {
      id: "target",
      header: t("posture.pqcMigration.targetColumn"),
      cell: (row) =>
        row.target_id ? <CredentialChip value={row.target_id} label={t("posture.pqcMigration.targetIdentifier")} /> : t("posture.pqcMigration.targetUnbound"),
    },
    {
      id: "evidence",
      header: t("posture.pqcMigration.evidenceColumn"),
      cell: (row) => (
        <div className="grid gap-1">
          {row.certificate_fingerprint ? (
            <CredentialChip value={row.certificate_fingerprint} label={t("posture.pqcMigration.certificateFingerprint")} />
          ) : (
            <span>{t("posture.pqcMigration.certificateUnreported")}</span>
          )}
          {row.target_algorithm ? <span>{t("posture.pqcMigration.requestedAlgorithm", { algorithm: row.target_algorithm })}</span> : null}
          {row.effective_algorithm ? <span>{t("posture.pqcMigration.effectiveAlgorithm", { algorithm: row.effective_algorithm })}</span> : null}
        </div>
      ),
    },
  ];

  return (
    <div className="grid gap-3">
      <p className="text-sm">{t("posture.pqcMigration.totalFindings", { count: String(progress.total) })}</p>
      <p className="text-sm">
        {t("posture.pqcMigration.progressSummary", {
          applied: String(progress.applied),
          queued: String(progress.queued),
          failed: String(progress.failed),
          rolledBack: String(progress.rolled_back),
        })}
      </p>
      {progress.issued === undefined || progress.rollback_unverified === undefined ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("posture.pqcMigration.countsUnavailable")}
        </p>
      ) : null}
      {typeof progress.issued === "number" && progress.issued > 0 ? (
        <p role="status" className="text-sm">
          {t("posture.pqcMigration.issuedSummary", { count: String(progress.issued) })}
        </p>
      ) : null}
      {typeof progress.rollback_unverified === "number" && progress.rollback_unverified > 0 ? (
        <p role="status" className="text-sm">
          {t("posture.pqcMigration.rollbackUnverifiedSummary", { count: String(progress.rollback_unverified) })}
        </p>
      ) : null}
      <DataGrid
        ariaLabel={t("posture.pqcMigration.findingsLabel")}
        rows={progress.findings ?? []}
        columns={columns}
        getRowId={(row) => row.asset_id}
        state={loading ? "loading" : !Array.isArray(progress.findings) ? "unavailable" : undefined}
      />
    </div>
  );
}
