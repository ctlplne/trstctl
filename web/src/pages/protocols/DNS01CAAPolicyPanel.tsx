import { CheckCircle2, CircleHelp, ShieldAlert, TriangleAlert } from "lucide-react";
import { useTranslation } from "@/i18n/I18nProvider";
import type { ACMEDNS01CAAPolicyEvidence } from "@/lib/api";

type CAAStateCopy = {
  title: string;
  help: string;
  tone: "success" | "warning" | "critical" | "neutral";
};

/** Makes F72's server-enforced CAA decision legible without hiding the DNS
 * evidence. Human guidance stays primary; exact public records remain close by. */
export function DNS01CAAPolicyPanel({ policy }: { policy: ACMEDNS01CAAPolicyEvidence }) {
  const { t } = useTranslation();
  const state: Record<ACMEDNS01CAAPolicyEvidence["status"], CAAStateCopy> = {
    not_configured: {
      title: t("protocols.dns01.caa.notConfiguredTitle"),
      help: t("protocols.dns01.caa.notConfiguredHelp"),
      tone: "warning",
    },
    unrestricted: {
      title: t("protocols.dns01.caa.unrestrictedTitle"),
      help: t("protocols.dns01.caa.unrestrictedHelp"),
      tone: "warning",
    },
    allowed: {
      title: t("protocols.dns01.caa.allowedTitle"),
      help: t("protocols.dns01.caa.allowedHelp"),
      tone: "success",
    },
    denied: {
      title: t("protocols.dns01.caa.deniedTitle"),
      help: t("protocols.dns01.caa.deniedHelp"),
      tone: "critical",
    },
    lookup_failed: {
      title: t("protocols.dns01.caa.lookupFailedTitle"),
      help: t("protocols.dns01.caa.lookupFailedHelp"),
      tone: "critical",
    },
  };
  const selected = state[policy.status];
  const frame =
    selected.tone === "success"
      ? "border-status-success/35 bg-status-success/5"
      : selected.tone === "critical"
        ? "border-destructive/35 bg-destructive/5"
        : selected.tone === "warning"
          ? "border-status-warning/35 bg-status-warning/5"
          : "border-border bg-muted/20";

  return (
    <section aria-label={t("protocols.dns01.caa.label")} className={`grid gap-4 rounded-control border p-4 ${frame}`}>
      <div className="flex items-start gap-3">
        <CAAStateIcon tone={selected.tone} />
        <div className="min-w-0">
          <h3 className="font-semibold">{selected.title}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{selected.help}</p>
          <p className="mt-2 text-caption font-medium text-muted-foreground">{t("protocols.dns01.caa.liveSource")}</p>
        </div>
      </div>

      <dl className="grid gap-3 text-sm sm:grid-cols-3">
        <CAAFact label={t("protocols.dns01.caa.configuredIssuer")} value={policy.configured_issuer || "—"} mono />
        <CAAFact
          label={t("protocols.dns01.caa.governingName")}
          value={policy.governing_name || t("protocols.dns01.caa.noGoverningName")}
          mono={Boolean(policy.governing_name)}
        />
        <CAAFact
          label={t("protocols.dns01.caa.requestType")}
          value={policy.wildcard ? t("protocols.dns01.caa.wildcardRequest") : t("protocols.dns01.caa.standardRequest")}
        />
      </dl>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="min-w-0">
          <h4 className="text-sm font-semibold">{t("protocols.dns01.caa.currentRecords")}</h4>
          {policy.records.length === 0 ? (
            <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.caa.noCurrentRecords")}</p>
          ) : (
            <ul className="mt-2 grid gap-1.5">
              {policy.records.map((record, index) => (
                <li
                  key={`${record.flag}-${record.tag}-${record.value}-${index}`}
                  className="break-all rounded-control border border-border bg-background px-2 py-1.5 font-mono text-xs"
                >
                  {record.flag} {record.tag} &quot;{record.value}&quot;
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="min-w-0">
          <h4 className="text-sm font-semibold">{t("protocols.dns01.caa.allowedIssuers")}</h4>
          {policy.allowed_issuers.length === 0 ? (
            <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.caa.noAllowedIssuers")}</p>
          ) : (
            <ul className="mt-2 flex flex-wrap gap-2">
              {policy.allowed_issuers.map((issuer) => (
                <li key={issuer} className="break-all rounded-control border border-border bg-background px-2 py-1 font-mono text-xs">
                  {issuer}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {policy.recommended_records.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold">{t("protocols.dns01.caa.recommendedChange")}</h4>
          <ul className="mt-2 grid gap-1.5">
            {policy.recommended_records.map((record) => (
              <li key={record} className="break-all rounded-control border border-border bg-background px-3 py-2 font-mono text-xs">
                {record}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <h4 className="text-sm font-semibold">{t("protocols.dns01.caa.nextSteps")}</h4>
        <ol className="mt-2 grid list-decimal gap-1 ps-5 text-sm text-muted-foreground">
          {policy.recovery_steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </div>

      {policy.fail_closed && <p className="border-s-2 border-border ps-3 text-caption text-muted-foreground">{t("protocols.dns01.caa.failClosed")}</p>}
    </section>
  );
}

function CAAStateIcon({ tone }: { tone: CAAStateCopy["tone"] }) {
  if (tone === "success") return <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />;
  if (tone === "critical") return <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />;
  if (tone === "warning") return <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />;
  return <CircleHelp className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" aria-hidden="true" />;
}

function CAAFact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className={`mt-0.5 break-words ${mono ? "font-mono text-xs" : "font-medium"}`}>{value}</dd>
    </div>
  );
}
