// SPDX-License-Identifier: BUSL-1.1

import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type UpgradePreflight } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import type { StatusTone } from "@/lib/statusVocab";

const rollbackCopy = {
  none: "platform.upgrade.rollback.none",
  rerun: "platform.upgrade.rollback.rerun",
  redeploy_previous_binary: "platform.upgrade.rollback.redeploy",
  restore_backup: "platform.upgrade.rollback.restore",
} as const;

// A246-L1: the upgrade preflight, read against this deployment's database with
// the running build's migrations: what an upgrade would apply, what would stop
// it, and how it is rolled back. The same verdict a pipeline reads from
// `trstctl --upgrade-preflight --upgrade-preflight-format json`.
export function UpgradePreflightPanel() {
  const { t } = useTranslation();
  const result = useApiQuery(["upgrade-preflight"], () => api.upgradePreflight(), { retry: false });
  return (
    <section className="ui-panel grid gap-3 p-comfortable" aria-labelledby="upgrade-preflight-heading">
      <div>
        <h2 id="upgrade-preflight-heading" className="text-title font-semibold">
          {t("platform.upgrade.title")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("platform.upgrade.description")}</p>
      </div>
      {result.error ? (
        <ErrorState title={t("platform.upgrade.failed")}>{result.error}</ErrorState>
      ) : !result.data ? (
        <LoadingState>{t("platform.upgrade.loading")}</LoadingState>
      ) : (
        <UpgradePreflightVerdict verdict={result.data} />
      )}
    </section>
  );
}

function UpgradePreflightVerdict({ verdict }: { verdict: UpgradePreflight }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge
          value={verdict.ready ? "ready" : "not_ready"}
          tone={(verdict.ready ? "success" : "danger") as StatusTone}
          label={t(verdict.ready ? "platform.upgrade.ready" : "platform.upgrade.notReady")}
        />
        <span>
          {t("platform.upgrade.versions", {
            schema: String(verdict.schema_version),
            build: String(verdict.binary_version),
            count: String(verdict.pending.length),
          })}
        </span>
      </div>
      {verdict.pending.length > 0 ? (
        <ul className="grid gap-1" aria-label={t("platform.upgrade.pending")}>
          {verdict.pending.map((migration) => (
            <li key={migration.version} className="font-mono text-xs">
              {migration.name}
              {migration.destructive ? <span className="ms-2 font-sans text-destructive">{t("platform.upgrade.destructive")}</span> : null}
              {!migration.transactional ? <span className="ms-2 font-sans text-muted-foreground">{t("platform.upgrade.outsideTransaction")}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
      {verdict.blockers.length > 0 ? (
        <div>
          <h3 className="font-medium">{t("platform.upgrade.blockers")}</h3>
          <ul className="grid gap-1">
            {verdict.blockers.map((finding) => (
              <li key={finding.code}>
                <span className="font-mono text-xs">{finding.code}</span>: {finding.detail}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {verdict.warnings.length > 0 ? (
        <div>
          <h3 className="font-medium">{t("platform.upgrade.warnings")}</h3>
          <ul className="grid gap-1">
            {verdict.warnings.map((finding) => (
              <li key={finding.code}>
                <span className="font-mono text-xs">{finding.code}</span>: {finding.detail}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <p>
        <span className="font-medium">{t(rollbackCopy[verdict.rollback.method])}</span> {verdict.rollback.detail}
      </p>
      <p className="text-muted-foreground">
        {verdict.backup.fresh && verdict.backup.taken_at
          ? t("platform.upgrade.backupFresh", { at: verdict.backup.taken_at })
          : verdict.backup.detail || t("platform.upgrade.backupStale")}
      </p>
    </div>
  );
}
