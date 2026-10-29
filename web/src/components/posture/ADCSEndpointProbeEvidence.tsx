import type { ADCSEnrollmentService } from "@/lib/api";
import { CredentialChip } from "@/components/CredentialChip";
import { Num } from "@/components/typography";
import { useTranslation } from "@/i18n/I18nProvider";

export function ADCSEndpointProbeCoverage({ coverage }: { coverage: ADCSEnrollmentService["endpoint_probe"] }) {
  const { t } = useTranslation();
  if (!coverage) return null;
  return (
    <section className="grid gap-2 border-s-2 border-status-info ps-3 text-xs">
      <h4 className="font-medium">{t("source.adcs.probe.heading")}</h4>
      <p className={coverage.complete ? "text-muted-foreground" : "text-status-warning"}>
        {t(coverage.complete ? "source.adcs.probe.complete" : "source.adcs.probe.partial")}
      </p>
      {coverage.state === "not_in_page" ? <p>{t("source.adcs.probe.notInPage")}</p> : null}
      {coverage.reason ? (
        <p className="text-status-warning">
          {t(coverage.reason === "invalid_directory_hostname" ? "source.adcs.probe.invalidHost" : "source.adcs.probe.scopeIssue")}
        </p>
      ) : null}
      <dl className="grid gap-2 sm:grid-cols-2">
        <div>
          <dt>{t("source.adcs.probe.planTargets")}</dt>
          <dd>
            <Num>{coverage.total_targets}</Num>
          </dd>
        </div>
        <div>
          <dt>{t("source.adcs.probe.serviceTargets")}</dt>
          <dd>
            <Num>{coverage.targets_on_page}</Num>
          </dd>
        </div>
        <div>
          <dt>{t("source.adcs.probe.offset")}</dt>
          <dd>
            <Num>{coverage.offset}</Num>
          </dd>
        </div>
        <div>
          <dt>{t("source.adcs.probe.next")}</dt>
          <dd>
            <Num>{coverage.next_offset}</Num>
          </dd>
        </div>
      </dl>
      <p className="text-muted-foreground">{t("source.adcs.probe.recover")}</p>
      <details>
        <summary className="cursor-pointer font-medium">{t("source.adcs.probe.planDigest")}</summary>
        <CredentialChip value={coverage.plan_digest} label={t("source.adcs.probe.planDigest")} fullValue />
      </details>
      <p className="text-muted-foreground">{t("source.adcs.probe.limits")}</p>
    </section>
  );
}

export function ADCSEndpointProbeOrigin({ endpoint }: { endpoint: ADCSEnrollmentService["endpoints"][number] }) {
  const { t } = useTranslation();
  return (
    <>
      {endpoint.source ? (
        <span>
          {t(
            endpoint.source === "ldap_dns"
              ? "source.adcs.probe.sourceLDAP"
              : endpoint.source === "configured_and_ldap_dns"
                ? "source.adcs.probe.sourceBoth"
                : "source.adcs.probe.sourceConfigured",
          )}
        </span>
      ) : null}
      {endpoint.state === "not_checked" ? <span className="text-status-warning">{t("source.adcs.probe.notChecked")}</span> : null}
    </>
  );
}
