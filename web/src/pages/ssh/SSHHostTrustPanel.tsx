import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";
import type { SSHHostTrust, SSHHostTrustView } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

type Judgment = { labelKey: MessageKey; tone: StatusTone };

const unreadable: Judgment = { labelKey: "sshTrust.hostTrust.unreadable", tone: "critical" };

const userCA: Record<string, Judgment> = {
  tenant_ca: { labelKey: "sshTrust.hostTrust.userCATenant", tone: "success" },
  tenant_ca_and_other: { labelKey: "sshTrust.hostTrust.userCATenantAndOther", tone: "warning" },
  other_ca: { labelKey: "sshTrust.hostTrust.userCAOther", tone: "warning" },
  none: { labelKey: "sshTrust.hostTrust.userCANone", tone: "neutral" },
};

const hostCertificate: Record<string, Judgment> = {
  tenant_ca: { labelKey: "sshTrust.hostTrust.hostCertTenant", tone: "success" },
  expiring: { labelKey: "sshTrust.hostTrust.hostCertExpiring", tone: "warning" },
  expired: { labelKey: "sshTrust.hostTrust.hostCertExpired", tone: "critical" },
  not_yet_valid: { labelKey: "sshTrust.hostTrust.hostCertNotYetValid", tone: "warning" },
  other_ca: { labelKey: "sshTrust.hostTrust.hostCertOther", tone: "warning" },
  unverified: { labelKey: "sshTrust.hostTrust.hostCertUnverified", tone: "critical" },
  not_host: { labelKey: "sshTrust.hostTrust.hostCertNotHost", tone: "critical" },
  none: { labelKey: "sshTrust.hostTrust.hostCertNone", tone: "neutral" },
};

const revocationList: Record<string, Judgment> = {
  served: { labelKey: "sshTrust.hostTrust.krlCurrent", tone: "success" },
  not_served: { labelKey: "sshTrust.hostTrust.krlOther", tone: "warning" },
  key_list: { labelKey: "sshTrust.hostTrust.krlKeyList", tone: "warning" },
  missing: { labelKey: "sshTrust.hostTrust.krlMissing", tone: "critical" },
  none: { labelKey: "sshTrust.hostTrust.krlNone", tone: "warning" },
};

const standingKeys: Record<string, Judgment> = {
  off: { labelKey: "sshTrust.hostTrust.standingOff", tone: "success" },
  on: { labelKey: "sshTrust.hostTrust.standingOn", tone: "warning" },
};

function Judged({ table, value }: { table: Record<string, Judgment>; value: string }) {
  const { t } = useTranslation();
  const judgment = table[value] ?? unreadable;
  return <StatusBadge value={value} tone={judgment.tone} label={t(judgment.labelKey)} />;
}

function HostCertificateDetail({ host }: { host: SSHHostTrust }) {
  const { t } = useTranslation();
  const best = host.host_certificates.find((c) => c.judgment === host.host_certificate);
  if (!best) return null;
  return (
    <span className="block text-xs text-muted-foreground">
      {t("sshTrust.hostTrust.hostCertDetail", {
        keyId: best.key_id ?? "",
        principals: (best.principals ?? []).join(", "),
        until: best.valid_before === "forever" ? t("sshTrust.hostTrust.forever") : best.valid_before ? formatDateTime(best.valid_before) : "",
      })}
    </span>
  );
}

// SSHHostTrustPanel shows whether each reporting host is under this tenant's
// SSH CA (A115): the CAs its sshd trusts for user certificates, the host
// certificate it presents, the revocation list it enforces, and whether
// standing authorized_keys still log in, read from its sshd configuration.
export function SSHHostTrustPanel({ view }: { view: SSHHostTrustView }) {
  const { t } = useTranslation();
  if (!view?.summary) return null;
  const hosts = view.hosts ?? [];
  const summary = view.summary;
  return (
    <section aria-labelledby="ssh-host-trust-heading" className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="ssh-host-trust-heading" className="text-title font-semibold">
          {t("sshTrust.hostTrust.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.hostTrust.description")}</p>
      </div>
      {!summary.tenant_ca_configured ? <p className="text-sm text-muted-foreground">{t("sshTrust.hostTrust.noTenantCA")}</p> : null}
      <p className="text-sm font-medium text-foreground">
        {t("sshTrust.hostTrust.summary", {
          hosts: summary.hosts,
          tenant: summary.trusts_tenant_ca,
          other: summary.trusts_other_ca_only,
          none: summary.no_user_ca,
          hostCert: summary.tenant_host_certificate,
          krl: summary.enforces_served_krl,
          standing: summary.standing_keys_on,
        })}
      </p>
      {hosts.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("sshTrust.hostTrust.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="ui-table" aria-label={t("sshTrust.hostTrust.tableLabel")}>
            <thead>
              <tr>
                <th scope="col">{t("sshTrust.hostTrust.host")}</th>
                <th scope="col">{t("sshTrust.hostTrust.userCA")}</th>
                <th scope="col">{t("sshTrust.hostTrust.hostCertificate")}</th>
                <th scope="col">{t("sshTrust.hostTrust.revocationList")}</th>
                <th scope="col">{t("sshTrust.hostTrust.standingKeys")}</th>
                <th scope="col">{t("sshTrust.hostTrust.lastReport")}</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => (
                <tr key={`${host.agent_id}:${host.source_id ?? ""}:${host.target_address ?? ""}:${host.sshd_config}`}>
                  <td>
                    <span className="block font-mono text-xs">{host.target_address || host.agent}</span>
                    {host.collection_mode === "agentless" ? (
                      <span className="block text-xs text-muted-foreground">{t("sshTrust.hostTrust.agentlessProvenance", { relay: host.agent })}</span>
                    ) : null}
                    <span className="block font-mono text-xs text-muted-foreground">{host.sshd_config}</span>
                    {host.match_blocks > 0 ? (
                      <span className="block text-xs text-muted-foreground">{t("sshTrust.hostTrust.matchBlocks", { count: host.match_blocks })}</span>
                    ) : null}
                  </td>
                  <td>
                    <Judged table={userCA} value={host.user_ca} />
                  </td>
                  <td>
                    <Judged table={hostCertificate} value={host.host_certificate} />
                    <HostCertificateDetail host={host} />
                  </td>
                  <td>
                    <Judged table={revocationList} value={host.revocation_list} />
                    {host.krl_version !== undefined && host.krl_version !== null ? (
                      <span className="block font-mono text-xs text-muted-foreground">{t("sshTrust.hostTrust.krlVersion", { version: host.krl_version })}</span>
                    ) : null}
                  </td>
                  <td>
                    <Judged table={standingKeys} value={host.standing_keys} />
                  </td>
                  <td>{formatDateTime(host.last_observed)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
