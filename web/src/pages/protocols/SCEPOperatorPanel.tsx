import { useState } from "react";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SCEPQualificationResult } from "@/lib/api";

const previewChecks = [
  { method: "GET", endpoint: "/scep?operation=GetCACaps", outcomeKey: "protocols.scepCheck.capabilitiesExpected" as const },
  { method: "GET", endpoint: "/scep?operation=GetCACert", outcomeKey: "protocols.scepCheck.caExpected" as const },
  { method: "POST", endpoint: "/scep?operation=PKIOperation", outcomeKey: "protocols.scepCheck.emptyExpected" as const },
];

function isSCEPQualificationResult(value: unknown): value is SCEPQualificationResult {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Partial<SCEPQualificationResult>;
  return (
    typeof result.checked_at === "string" &&
    typeof result.passed === "boolean" &&
    Array.isArray(result.checks) &&
    result.checks.every(
      (check) =>
        typeof check === "object" &&
        check !== null &&
        typeof check.id === "string" &&
        typeof check.method === "string" &&
        typeof check.endpoint === "string" &&
        typeof check.expected === "string" &&
        typeof check.passed === "boolean" &&
        typeof check.detail === "string",
    )
  );
}

export function SCEPOperatorPanel() {
  const { t } = useTranslation();
  const [result, setResult] = useState<SCEPQualificationResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runCheck() {
    setRunning(true);
    setError(null);
    try {
      const next = await api.scepQualification();
      if (!isSCEPQualificationResult(next)) throw new Error(t("protocols.scepCheck.invalidResult"));
      setResult(next);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : t("protocols.scepCheck.failedBody"));
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card
      id="scep-operator-panel"
      role="region"
      aria-labelledby="scep-operator-heading"
      aria-label={t("protocols.scepCheck.region")}
      className="min-w-0 scroll-mt-24"
    >
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 max-w-3xl">
          <CardTitle id="scep-operator-heading">{t("protocols.scepCheck.heading")}</CardTitle>
          <p className="mt-1 text-body text-muted-foreground">{t("protocols.scepCheck.description")}</p>
        </div>
        {result ? (
          <StatusBadge
            value={result.passed ? "ready" : "blocked"}
            label={result.passed ? t("protocols.scepCheck.ready") : t("protocols.scepCheck.blocked")}
            tone={result.passed ? "success" : "warning"}
          />
        ) : null}
      </CardHeader>

      <CardContent className="grid min-w-0 gap-4">
        <div className="grid gap-3 border-y border-border py-4">
          <div>
            <p className="text-sm font-semibold">{t("protocols.scepCheck.previewHeading")}</p>
            <p className="mt-1 text-caption text-muted-foreground">{t("protocols.scepCheck.safePreview")}</p>
          </div>
          <ol className="grid gap-2">
            {previewChecks.map((check, index) => {
              const observed = result?.checks.find((candidate) => candidate.method === check.method && candidate.endpoint === check.endpoint);
              return (
                <li
                  key={`${check.method}:${check.endpoint}`}
                  className="grid min-w-0 gap-1 border-s-2 border-border ps-3 sm:grid-cols-[1.5rem_minmax(0,1fr)_auto] sm:items-start"
                >
                  <span className="text-caption font-medium text-muted-foreground" aria-hidden="true">
                    {index + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="break-all font-mono text-xs font-medium">
                      {check.method} {check.endpoint}
                    </p>
                    <p className="mt-1 text-caption text-muted-foreground">{t(check.outcomeKey)}</p>
                    {observed ? <p className="mt-1 text-sm">{observed.detail}</p> : null}
                  </div>
                  {observed ? (
                    <StatusBadge
                      value={observed.passed ? "passed" : "failed"}
                      label={observed.passed ? t("protocols.scepCheck.passed") : t("protocols.scepCheck.failed")}
                      tone={observed.passed ? "success" : "critical"}
                    />
                  ) : null}
                </li>
              );
            })}
          </ol>
        </div>

        {error ? <ErrorState title={t("protocols.scepCheck.failedTitle")}>{error}</ErrorState> : null}

        {result ? (
          <div role="status" aria-live="polite" className="grid gap-2">
            <p className={`text-body font-semibold ${result.passed ? "text-status-success" : "text-status-warning"}`}>
              {result.passed ? t("protocols.scepCheck.ready") : t("protocols.scepCheck.blocked")}
            </p>
            <p className="text-caption text-muted-foreground">{t("protocols.scepCheck.noIssuance")}</p>
            {!result.passed ? <p className="text-sm text-muted-foreground">{t("protocols.scepCheck.recovery")}</p> : null}
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-3">
          <Button type="button" disabled={running || typeof api.scepQualification !== "function"} onClick={() => void runCheck()}>
            {running ? t("protocols.scepCheck.running") : result ? t("protocols.scepCheck.runAgain") : t("protocols.scepCheck.run")}
          </Button>
          <p className="max-w-3xl text-caption text-muted-foreground">{t("protocols.scepCheck.clientBoundary")}</p>
        </div>
      </CardContent>
    </Card>
  );
}
