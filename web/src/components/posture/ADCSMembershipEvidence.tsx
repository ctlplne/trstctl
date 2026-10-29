import type { ADCSTemplate } from "@/lib/api";
import { CredentialChip } from "@/components/CredentialChip";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

export function ADCSMembershipEvidence({ evidence }: { evidence: ADCSTemplate["enrollment_membership"] }) {
  const { t } = useTranslation();
  if (!evidence) return <span className="text-xs text-muted-foreground">{t("source.adcs.membership.disabled")}</span>;
  return (
    <div className="grid max-w-xl gap-2 text-xs">
      <span className={evidence.state === "complete" ? "text-foreground" : "text-status-warning"}>
        {t(evidence.state === "complete" ? "source.adcs.membership.complete" : "source.adcs.membership.incomplete")}
      </span>
      <span className="break-all font-mono text-muted-foreground">
        {evidence.domain_dn} · {formatDateTime(evidence.observed_at)}
      </span>
      {evidence.state !== "complete" ? (
        <>
          <p>{t("source.adcs.membership.recover")}</p>
          {evidence.budget_exceeded ? <p>{t("source.adcs.membership.budget")}</p> : null}
          <ul>
            {(evidence.trustees ?? [])
              .filter((trustee) => trustee.state !== "complete")
              .map((trustee) => (
                <li key={trustee.sid} className="break-all font-mono">
                  {trustee.sid} · {trustee.state}
                </li>
              ))}
          </ul>
        </>
      ) : null}
      <details>
        <summary className="cursor-pointer font-medium">{t("source.adcs.membership.members", { count: String(evidence.members?.length ?? 0) })}</summary>
        <ul className="mt-2 grid gap-3">
          {(evidence.members ?? []).map((member) => (
            <li key={member.sid} className="grid gap-1 border-s-2 border-border ps-2">
              <span className="break-all font-mono">{member.dn}</span>
              <CredentialChip value={member.sid} label={t("source.adcs.membership.sid")} fullValue />
              <span className="break-all font-mono">{(member.path ?? []).join(" → ")}</span>
              {(member.via_trustees ?? []).map((sid) => (
                <CredentialChip key={sid} value={sid} label={t("source.adcs.membership.trustee")} fullValue />
              ))}
            </li>
          ))}
        </ul>
      </details>
      <p className="text-muted-foreground">{t("source.adcs.membership.limits")}</p>
    </div>
  );
}
