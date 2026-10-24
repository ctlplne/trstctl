import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";
import type { SSHKRLFleet, SSHKRLHost } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

const hostStates: Record<string, { labelKey: MessageKey; tone: StatusTone }> = {
  current: { labelKey: "sshTrust.krlFleet.stateCurrent", tone: "success" },
  behind: { labelKey: "sshTrust.krlFleet.stateBehind", tone: "warning" },
  refusing: { labelKey: "sshTrust.krlFleet.stateRefusing", tone: "critical" },
  failing: { labelKey: "sshTrust.krlFleet.stateFailing", tone: "critical" },
  stale: { labelKey: "sshTrust.krlFleet.stateStale", tone: "neutral" },
};

function shortDigest(digest: string): string {
  return digest ? `${digest.slice(0, 12)}…` : "";
}

function HostDetail({ host }: { host: SSHKRLHost }) {
  const { t } = useTranslation();
  switch (host.state) {
    case "refusing":
      return host.dropped ? (
        <>
          {t("sshTrust.krlFleet.dropsDetail", {
            serials: host.dropped.serials,
            keyIds: host.dropped.key_ids,
            keys: host.dropped.keys + host.dropped.key_hashes,
          })}
        </>
      ) : (
        <>{t("sshTrust.krlFleet.notNewerDetail", { version: host.fetched_version ?? 0 })}</>
      );
    case "failing":
      return <>{t(host.outcome === "fetch_failed" ? "sshTrust.krlFleet.fetchFailedDetail" : "sshTrust.krlFleet.applyFailedDetail")}</>;
    case "stale":
      return <>{t("sshTrust.krlFleet.staleDetail", { reported: formatDateTime(host.reported_at) })}</>;
    case "behind":
      return <>{t("sshTrust.krlFleet.behindDetail")}</>;
    default:
      return null;
  }
}

// SSHKRLFleetPanel shows which hosts enforce the served KRL (A109), from the
// signed receipts enrolled host agents report on their heartbeats.
export function SSHKRLFleetPanel({ fleet }: { fleet: SSHKRLFleet }) {
  const { t } = useTranslation();
  // An older control plane or a partial payload has no served list to compare
  // against; show nothing rather than an invented comparison.
  if (!fleet?.served || !fleet.summary) return null;
  const hosts = fleet.hosts ?? [];
  return (
    <section aria-labelledby="ssh-krl-fleet-heading" className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="ssh-krl-fleet-heading" className="text-title font-semibold">
          {t("sshTrust.krlFleet.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.krlFleet.description")}</p>
      </div>
      <p className="text-sm font-medium text-foreground">
        {t("sshTrust.krlFleet.summary", {
          version: fleet.served.krl_version,
          digest: shortDigest(fleet.served.sha256),
          hosts: fleet.summary.hosts,
          current: fleet.summary.current,
          behind: fleet.summary.behind,
          refusing: fleet.summary.refusing,
          failing: fleet.summary.failing,
          stale: fleet.summary.stale,
        })}
      </p>
      {hosts.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("sshTrust.krlFleet.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="ui-table" aria-label={t("sshTrust.krlFleet.tableLabel")}>
            <thead>
              <tr>
                <th scope="col">{t("sshTrust.krlFleet.host")}</th>
                <th scope="col">{t("sshTrust.krlFleet.state")}</th>
                <th scope="col">{t("sshTrust.krlFleet.installed")}</th>
                <th scope="col">{t("sshTrust.krlFleet.lastCheck")}</th>
                <th scope="col">{t("sshTrust.krlFleet.detail")}</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => {
                const state = hostStates[host.state] ?? hostStates.stale;
                return (
                  <tr key={host.agent_id}>
                    <td className="font-mono text-xs">{host.agent}</td>
                    <td>
                      <StatusBadge value={host.state} tone={state.tone} label={t(state.labelKey)} />
                    </td>
                    <td className="font-mono text-xs">
                      {t("sshTrust.krlFleet.installedValue", { version: host.installed_version, digest: shortDigest(host.installed_sha256) })}
                    </td>
                    <td>{formatDateTime(host.checked_at)}</td>
                    <td className="text-sm">
                      <HostDetail host={host} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {fleet.summary.refusing > 0 ? <p className="text-sm text-muted-foreground">{t("sshTrust.krlFleet.refusingHint")}</p> : null}
    </section>
  );
}
