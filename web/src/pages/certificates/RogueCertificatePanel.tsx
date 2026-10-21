import { useState } from "react";
import { AlertTriangle, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatNumber as formatNumberPolicy } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";
import { api, type RogueCertificatePosture } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";

// The rogue-certificate panel of the Certificates page (A43 takedown lives
// here). Split out of Certificates.tsx by workflow so the served-file budget
// keeps the page readable.

export function formatCount(value: number): string {
  return formatNumberPolicy(value);
}

export function HealthStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border px-3 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
    </div>
  );
}

type RogueCertificateFinding = RogueCertificatePosture["findings"][number];

function rogueModelLabel(model: string, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  switch (model) {
    case "host_purge":
      return t("certificates.rogue.model.host_purge");
    case "appliance_takedown":
      return t("certificates.rogue.model.appliance_takedown");
    default:
      return t("certificates.rogue.model.none");
  }
}

function roguePolicyLabel(finding: RogueCertificateFinding, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  return finding.policy_status === "rogue" ? t("certificates.rogue.policyRogue") : t("certificates.rogue.policyNonCompliant");
}

function rogueTypeLabel(type: string, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  const keys: Partial<Record<string, MessageKey>> = {
    ct_unexpected_issuance: "certificates.rogue.typeCTUnexpected",
    not_in_inventory: "certificates.rogue.typeNotInInventory",
    weak_key_algorithm: "certificates.rogue.typeWeakKey",
    lifetime_exceeds_policy: "certificates.rogue.typeLifetime",
    expired_active_certificate: "certificates.rogue.typeExpiredActive",
    owner_missing: "certificates.rogue.typeOwnerMissing",
    issuer_missing: "certificates.rogue.typeIssuerMissing",
  };
  if (type.startsWith("customer_policy:")) {
    return t("certificates.rogue.typeCustomerPolicy", { rule: type.slice("customer_policy:".length) });
  }
  const key = keys[type];
  return key ? t(key) : type.replaceAll("_", " ");
}

function severityClass(severity: RogueCertificateFinding["severity"]): string {
  switch (severity) {
    case "critical":
      return "border-destructive/40 bg-destructive/10 text-destructive";
    case "high":
      return "border-status-warning/50 bg-status-warning/10 text-status-warning";
    case "medium":
      return "border-primary/30 bg-primary/10 text-primary";
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

export function RogueCertificatePanel({ posture }: { posture: RogueCertificatePosture }) {
  const { t } = useTranslation();
  const findings = posture.findings.slice(0, 6);
  const highOrCritical = posture.summary.critical + posture.summary.high;
  // A43: queue removal of a delivered rogue leaf from one target. The reason
  // is recorded on the receipt; the receipt status is the only claim shown.
  const [takedownReason, setTakedownReason] = useState("");
  const [takedownBusy, setTakedownBusy] = useState<string | null>(null);
  const [takedownResult, setTakedownResult] = useState<string | null>(null);
  const takedown = async (fingerprint: string, targetId: string, targetName: string) => {
    if (!fingerprint || !takedownReason.trim() || takedownBusy) return;
    setTakedownBusy(targetId);
    try {
      const receipt = await api.takedownRogueCertificate({ fingerprint, target_id: targetId, reason: takedownReason.trim() }, newIdempotencyKey());
      setTakedownResult(t("certificates.rogue.takedownQueued", { target: targetName, status: receipt.status }));
    } catch (error) {
      setTakedownResult(error instanceof Error ? error.message : String(error));
    } finally {
      setTakedownBusy(null);
    }
  };
  return (
    <section aria-labelledby="rogue-certificates-heading" className="border-y border-border py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 id="rogue-certificates-heading" className="text-base font-semibold">
            {t("certificates.rogue.heading")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("certificates.rogue.description")}</p>
        </div>
        <span
          className={`inline-flex min-h-8 items-center gap-2 rounded-md border px-2.5 text-sm font-medium ${highOrCritical > 0 ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-status-success/40 bg-status-success/10 text-status-success"}`}
        >
          {highOrCritical > 0 ? <AlertTriangle className="h-4 w-4" aria-hidden="true" /> : <ShieldCheck className="h-4 w-4" aria-hidden="true" />}
          {t("certificates.rogue.findingBadge", { count: formatCount(posture.summary.findings) })}
        </span>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <HealthStat label={t("certificates.rogue.metricRogue")} value={posture.summary.rogue} />
        <HealthStat label={t("certificates.rogue.metricNonCompliant")} value={posture.summary.non_compliant} />
        <HealthStat label={t("certificates.rogue.metricCT")} value={posture.summary.ct_unexpected} />
        <HealthStat label={t("certificates.rogue.metricHigh")} value={highOrCritical} />
      </div>
      {findings.length > 0 && (
        <label className="mt-3 grid gap-1 text-sm">
          <span className="text-muted-foreground">{t("certificates.rogue.takedownReason")}</span>
          <input
            className="min-h-9 rounded-md border border-border bg-background px-2"
            value={takedownReason}
            onChange={(event) => setTakedownReason(event.target.value)}
          />
        </label>
      )}
      {takedownResult && <output className="mt-2 block font-mono text-xs text-muted-foreground">{takedownResult}</output>}
      {findings.length === 0 ? (
        <p className="mt-4 rounded-md border border-border px-3 py-2 text-sm text-muted-foreground">{t("certificates.rogue.empty")}</p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <caption className="sr-only">{t("certificates.rogue.caption")}</caption>
            <thead className="border-b border-border text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="py-2 pr-4 font-medium">
                  {t("certificates.rogue.columnSubject")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.rogue.columnStatus")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.rogue.columnSeverity")}
                </th>
                <th scope="col" className="px-4 py-2 font-medium">
                  {t("certificates.rogue.columnEvidence")}
                </th>
                <th scope="col" className="pl-4 py-2 font-medium">
                  {t("certificates.rogue.columnRecommendation")}
                </th>
                <th scope="col" className="pl-4 pb-2 font-medium">
                  {t("certificates.rogue.columnInstalledOn")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="py-2 pr-4 align-top">
                    <span className="block max-w-[18rem] truncate font-medium">{finding.subject}</span>
                    <span className="block max-w-[18rem] truncate text-xs text-muted-foreground">
                      {finding.dns_names?.slice(0, 2).join(", ") || finding.source}
                    </span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className="block font-medium">{roguePolicyLabel(finding, t)}</span>
                    <span className="block max-w-[16rem] text-xs text-muted-foreground">
                      {finding.finding_types.map((type) => rogueTypeLabel(type, t)).join(", ")}
                    </span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className={`inline-flex min-h-7 items-center rounded-md border px-2 text-xs font-medium ${severityClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {t("certificates.rogue.riskScore", { score: formatCount(finding.risk_score) })}
                    </span>
                  </td>
                  <td className="px-4 py-2 align-top">
                    <span className="block max-w-[16rem] break-all font-mono text-xs text-muted-foreground">
                      {finding.evidence_refs.slice(0, 2).join(", ")}
                    </span>
                  </td>
                  <td className="pl-4 py-2 align-top">
                    <span className="block max-w-[24rem] text-sm">{finding.recommendation}</span>
                  </td>
                  <td className="pl-4 py-2 align-top">
                    {finding.installed_on?.length ? (
                      <ul className="grid gap-1 text-xs">
                        {finding.installed_on.map((target) => (
                          <li key={target.target_id} className="flex flex-wrap items-center gap-2">
                            <span className="font-medium">{target.target_name}</span>
                            <span className="text-muted-foreground">{rogueModelLabel(target.model, t)}</span>
                            {target.model !== "none" && (
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                disabled={!takedownReason.trim() || Boolean(takedownBusy)}
                                onClick={() => void takedown(finding.fingerprint ?? "", target.target_id, target.target_name)}
                              >
                                {t("certificates.rogue.takedown")}
                              </Button>
                            )}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span className="text-xs text-muted-foreground">{t("certificates.rogue.installedNone")}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
