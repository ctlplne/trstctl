import { useState } from "react";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CMPQualification, type EnrollmentDiagnostic } from "@/lib/api";

const previewChecks = [
  { id: "mount", titleKey: "protocols.cmpCheck.mountPreview" as const, detailKey: "protocols.cmpCheck.mountPreviewDetail" as const },
  { id: "trust", titleKey: "protocols.cmpCheck.trustPreview" as const, detailKey: "protocols.cmpCheck.trustPreviewDetail" as const },
  { id: "issue", titleKey: "protocols.cmpCheck.issuePreview" as const, detailKey: "protocols.cmpCheck.issuePreviewDetail" as const },
  { id: "capacity", titleKey: "protocols.cmpCheck.capacityPreview" as const, detailKey: "protocols.cmpCheck.capacityPreviewDetail" as const },
];

function isCMPQualification(value: unknown): value is CMPQualification {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Partial<CMPQualification>;
  return (
    typeof result.checked_at === "string" &&
    typeof result.ready === "boolean" &&
    result.effect_free === true &&
    typeof result.endpoint === "string" &&
    typeof result.profile === "string" &&
    (result.binding_mode === "subject-bound" || result.binding_mode === "registration-authority") &&
    typeof result.client_trust_anchor_count === "number" &&
    Array.isArray(result.checks) &&
    result.checks.every(
      (check) =>
        typeof check === "object" &&
        check !== null &&
        typeof check.id === "string" &&
        typeof check.label === "string" &&
        typeof check.passed === "boolean" &&
        typeof check.detail === "string",
    ) &&
    Array.isArray(result.preview_writes) &&
    Array.isArray(result.preview_external_effects) &&
    Array.isArray(result.preview_signer_calls) &&
    Array.isArray(result.proof) &&
    Array.isArray(result.blockers)
  );
}

export function CMPOperatorPanel({ diagnostics }: { diagnostics: EnrollmentDiagnostic[] }) {
  const { formatDateTime, t } = useTranslation();
  const [result, setResult] = useState<CMPQualification | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cmpDiagnostics = diagnostics.filter((item) => item.protocol.toLowerCase() === "cmp").slice(0, 5);

  async function runCheck() {
    setRunning(true);
    setError(null);
    try {
      const next = await api.cmpQualification();
      if (!isCMPQualification(next)) throw new Error(t("protocols.cmpCheck.invalidResult"));
      setResult(next);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : t("protocols.cmpCheck.failedBody"));
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card role="region" aria-labelledby="cmp-operator-heading" aria-label={t("protocols.cmpCheck.region")} className="min-w-0">
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 max-w-3xl">
          <CardTitle id="cmp-operator-heading">{t("protocols.cmpCheck.heading")}</CardTitle>
          <p className="mt-1 text-body text-muted-foreground">{t("protocols.cmpCheck.description")}</p>
        </div>
        {result ? (
          <StatusBadge
            value={result.ready ? "ready" : "blocked"}
            label={result.ready ? t("protocols.cmpCheck.ready") : t("protocols.cmpCheck.blocked")}
            tone={result.ready ? "success" : "warning"}
          />
        ) : null}
      </CardHeader>

      <CardContent className="grid min-w-0 gap-5">
        <div className="grid gap-3 border-y border-border py-4">
          <div>
            <p className="text-sm font-semibold">{t("protocols.cmpCheck.previewHeading")}</p>
            <p className="mt-1 text-caption text-muted-foreground">{t("protocols.cmpCheck.safePreview")}</p>
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

        {error ? <ErrorState title={t("protocols.cmpCheck.failedTitle")}>{error}</ErrorState> : null}

        {result ? (
          <div role="status" aria-live="polite" className="grid gap-4">
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <RuntimeFact label={t("protocols.cmpCheck.endpoint")} value={result.endpoint} />
              <RuntimeFact label={t("protocols.cmpCheck.profile")} value={result.profile} />
              <RuntimeFact label={t("protocols.cmpCheck.binding")} value={bindingLabel(result.binding_mode, t)} />
              <RuntimeFact label={t("protocols.cmpCheck.anchors")} value={t("protocols.cmpCheck.anchorCount", { count: result.client_trust_anchor_count })} />
            </dl>

            <ul className="grid gap-2" aria-label={t("protocols.cmpCheck.resultsLabel")}>
              {result.checks.map((check) => (
                <li key={check.id} className="grid min-w-0 gap-2 border-s-2 border-border ps-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{check.label}</p>
                    <p className="mt-1 text-caption text-muted-foreground">{check.detail}</p>
                    {!check.passed && check.recovery ? <p className="mt-1 text-sm text-status-warning">{check.recovery}</p> : null}
                  </div>
                  <StatusBadge
                    value={check.passed ? "passed" : "failed"}
                    label={check.passed ? t("protocols.cmpCheck.passed") : t("protocols.cmpCheck.failed")}
                    tone={check.passed ? "success" : "critical"}
                  />
                </li>
              ))}
            </ul>

            <div className="rounded-control border border-status-success/30 bg-status-success/5 px-3 py-2 text-caption text-muted-foreground">
              {t("protocols.cmpCheck.effectProof")}
            </div>
          </div>
        ) : null}

        <div className="grid gap-3 border-t border-border pt-4">
          <div>
            <p className="text-sm font-semibold">{t("protocols.cmpCheck.receiptsHeading")}</p>
            <p className="mt-1 text-caption text-muted-foreground">{t("protocols.cmpCheck.receiptsDescription")}</p>
          </div>
          {cmpDiagnostics.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("protocols.cmpCheck.noReceipts")}</p>
          ) : (
            <ul className="grid gap-2" aria-label={t("protocols.cmpCheck.receiptsLabel")}>
              {cmpDiagnostics.map((receipt) => (
                <li key={receipt.id} className="ui-panel grid gap-1 p-3 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-medium">{receipt.summary}</span>
                    <span className="text-caption text-muted-foreground">{formatDateTime(receipt.observed_at)}</span>
                  </div>
                  {receipt.operation_ref ? <code className="break-all text-xs text-muted-foreground">{receipt.operation_ref}</code> : null}
                  <p className="text-caption text-muted-foreground">
                    {receipt.actionable && receipt.remediation ? receipt.remediation : t("protocols.cmpCheck.unknownRecovery")}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="button" disabled={running || typeof api.cmpQualification !== "function"} onClick={() => void runCheck()}>
            {running ? t("protocols.cmpCheck.running") : result ? t("protocols.cmpCheck.runAgain") : t("protocols.cmpCheck.run")}
          </Button>
          <p className="max-w-3xl text-caption text-muted-foreground">{t("protocols.cmpCheck.clientBoundary")}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function RuntimeFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="ui-panel p-3">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all text-sm font-medium">{value}</dd>
    </div>
  );
}

function bindingLabel(mode: CMPQualification["binding_mode"], t: ReturnType<typeof useTranslation>["t"]): string {
  return mode === "registration-authority" ? t("protocols.cmpCheck.bindingRA") : t("protocols.cmpCheck.bindingSubject");
}
