import { useState } from "react";
import { CapabilityActionNotice, capabilityExecutionReason } from "@/components/CapabilityTruth";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type TSAQualification } from "@/lib/api";
import { useCapabilityExecution } from "@/lib/capabilities";

const previewChecks = [
  { id: "mount", titleKey: "protocols.tsaCheck.mountPreview" as const, detailKey: "protocols.tsaCheck.mountPreviewDetail" as const },
  {
    id: "certificate",
    titleKey: "protocols.tsaCheck.certificatePreview" as const,
    detailKey: "protocols.tsaCheck.certificatePreviewDetail" as const,
  },
  { id: "signer", titleKey: "protocols.tsaCheck.signerPreview" as const, detailKey: "protocols.tsaCheck.signerPreviewDetail" as const },
  { id: "audit", titleKey: "protocols.tsaCheck.auditPreview" as const, detailKey: "protocols.tsaCheck.auditPreviewDetail" as const },
];

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isTSAQualification(value: unknown): value is TSAQualification {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Partial<TSAQualification>;
  return (
    typeof result.checked_at === "string" &&
    typeof result.ready === "boolean" &&
    result.effect_free === true &&
    typeof result.endpoint === "string" &&
    typeof result.policy_oid === "string" &&
    Array.isArray(result.checks) &&
    result.checks.every(
      (check) =>
        typeof check === "object" &&
        check !== null &&
        typeof check.id === "string" &&
        typeof check.label === "string" &&
        typeof check.passed === "boolean" &&
        typeof check.detail === "string" &&
        (check.recovery === undefined || typeof check.recovery === "string"),
    ) &&
    isStringArray(result.preview_writes) &&
    isStringArray(result.preview_external_effects) &&
    isStringArray(result.preview_signer_calls) &&
    isStringArray(result.proof) &&
    isStringArray(result.blockers)
  );
}

export function TSAOperatorPanel() {
  const { t } = useTranslation();
  const qualification = useCapabilityExecution("F51", "qualifyTSA");
  const [result, setResult] = useState<TSAQualification | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const disabledReason = capabilityExecutionReason(qualification, t);

  async function runCheck() {
    if (!qualification.runnable) return;
    setRunning(true);
    setError(null);
    try {
      const next = await api.tsaQualification();
      if (!isTSAQualification(next)) throw new Error(t("protocols.tsaCheck.invalidResult"));
      setResult(next);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : t("protocols.tsaCheck.failedBody"));
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card id="tsa-operator-panel" role="region" aria-labelledby="tsa-operator-heading" aria-label={t("protocols.tsaCheck.region")} className="min-w-0 scroll-mt-24">
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 max-w-3xl">
          <CardTitle id="tsa-operator-heading">{t("protocols.tsaCheck.heading")}</CardTitle>
          <p className="mt-1 text-body text-muted-foreground">{t("protocols.tsaCheck.description")}</p>
        </div>
        {result ? (
          <StatusBadge
            value={result.ready ? "ready" : "blocked"}
            label={result.ready ? t("protocols.tsaCheck.ready") : t("protocols.tsaCheck.blocked")}
            tone={result.ready ? "success" : "warning"}
          />
        ) : null}
      </CardHeader>

      <CardContent className="grid min-w-0 gap-5">
        <div className="grid gap-3 border-y border-border py-4">
          <div>
            <p className="text-sm font-semibold">{t("protocols.tsaCheck.previewHeading")}</p>
            <p className="mt-1 text-caption text-muted-foreground">{t("protocols.tsaCheck.safePreview")}</p>
          </div>
          <ol className="grid gap-2 md:grid-cols-2">
            {previewChecks.map((check, index) => (
              <li key={check.id} className="grid min-w-0 grid-cols-[1.5rem_minmax(0,1fr)] gap-1 border-s-2 border-border ps-3">
                <span className="text-caption font-medium text-muted-foreground" aria-hidden="true">
                  {index + 1}
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{t(check.titleKey)}</p>
                  <p className="mt-1 text-caption text-muted-foreground">{t(check.detailKey)}</p>
                </div>
              </li>
            ))}
          </ol>
        </div>

        <CapabilityActionNotice action={qualification} />
        {error ? <ErrorState title={t("protocols.tsaCheck.failedTitle")}>{error}</ErrorState> : null}

        {result ? (
          <div role="status" aria-live="polite" className="grid gap-4">
            <dl className="grid gap-3 sm:grid-cols-2">
              <RuntimeFact label={t("protocols.tsaCheck.endpoint")} value={result.endpoint} />
              <RuntimeFact label={t("protocols.tsaCheck.policy")} value={result.policy_oid} mono />
            </dl>

            <ul className="grid gap-2" aria-label={t("protocols.tsaCheck.resultsLabel")}>
              {result.checks.map((check) => (
                <li key={check.id} className="grid min-w-0 gap-2 border-s-2 border-border ps-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{check.label}</p>
                    <p className="mt-1 text-caption text-muted-foreground">{check.detail}</p>
                    {!check.passed && check.recovery ? <p className="mt-1 text-sm text-status-warning">{check.recovery}</p> : null}
                  </div>
                  <StatusBadge
                    value={check.passed ? "passed" : "failed"}
                    label={check.passed ? t("protocols.tsaCheck.passed") : t("protocols.tsaCheck.failed")}
                    tone={check.passed ? "success" : "critical"}
                  />
                </li>
              ))}
            </ul>

            <div className="rounded-control border border-status-success/30 bg-status-success/5 px-3 py-2 text-caption text-muted-foreground">
              {t("protocols.tsaCheck.effectProof")}
            </div>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-3">
          <Button
            type="button"
            disabled={running || !qualification.runnable || typeof api.tsaQualification !== "function"}
            title={!qualification.runnable ? disabledReason : undefined}
            onClick={() => void runCheck()}
          >
            {running ? t("protocols.tsaCheck.running") : result ? t("protocols.tsaCheck.runAgain") : t("protocols.tsaCheck.run")}
          </Button>
          <p className="max-w-3xl text-caption text-muted-foreground">{t("protocols.tsaCheck.clientBoundary")}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function RuntimeFact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="ui-panel p-3">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className={`mt-1 break-all text-sm font-medium${mono ? " font-mono" : ""}`}>{value}</dd>
    </div>
  );
}
