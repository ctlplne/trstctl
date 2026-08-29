import { useState } from "react";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ESTQualificationResult } from "@/lib/api";

const previewChecks = [
  { method: "GET", endpoint: "/.well-known/est/cacerts", outcomeKey: "protocols.estCheck.caExpected" as const },
  { method: "GET", endpoint: "/.well-known/est/csrattrs", outcomeKey: "protocols.estCheck.csrExpected" as const },
  { method: "POST", endpoint: "/.well-known/est/simpleenroll", outcomeKey: "protocols.estCheck.authExpected" as const },
];

function isESTQualificationResult(value: unknown): value is ESTQualificationResult {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Partial<ESTQualificationResult>;
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

export function ESTOperatorPanel() {
  const { t } = useTranslation();
  const [result, setResult] = useState<ESTQualificationResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runCheck() {
    setRunning(true);
    setError(null);
    try {
      const next = await api.estQualification();
      if (!isESTQualificationResult(next)) throw new Error(t("protocols.estCheck.invalidResult"));
      setResult(next);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : t("protocols.estCheck.failedBody"));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section
      id="est-operator-panel"
      aria-labelledby="est-operator-heading"
      aria-label={t("protocols.estCheck.region")}
      className="ui-panel grid min-w-0 scroll-mt-24 gap-4 p-comfortable"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-3xl">
          <h2 id="est-operator-heading" className="text-title font-semibold">
            {t("protocols.estCheck.heading")}
          </h2>
          <p className="mt-1 text-body text-muted-foreground">{t("protocols.estCheck.description")}</p>
        </div>
        {result ? (
          <StatusBadge
            value={result.passed ? "ready" : "blocked"}
            label={result.passed ? t("protocols.estCheck.ready") : t("protocols.estCheck.blocked")}
            tone={result.passed ? "success" : "warning"}
          />
        ) : null}
      </div>

      <div className="grid gap-3 border-y border-border py-4">
        <div>
          <p className="text-sm font-semibold">{t("protocols.estCheck.previewHeading")}</p>
          <p className="mt-1 text-caption text-muted-foreground">{t("protocols.estCheck.safePreview")}</p>
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
                    label={observed.passed ? t("protocols.estCheck.passed") : t("protocols.estCheck.failed")}
                    tone={observed.passed ? "success" : "critical"}
                  />
                ) : null}
              </li>
            );
          })}
        </ol>
      </div>

      {error ? <ErrorState title={t("protocols.estCheck.failedTitle")}>{error}</ErrorState> : null}

      {result ? (
        <div role="status" aria-live="polite" className="grid gap-2">
          <p className={`text-body font-semibold ${result.passed ? "text-status-success" : "text-status-warning"}`}>
            {result.passed ? t("protocols.estCheck.ready") : t("protocols.estCheck.blocked")}
          </p>
          <p className="text-caption text-muted-foreground">{t("protocols.estCheck.noIssuance")}</p>
          {!result.passed ? <p className="text-sm text-muted-foreground">{t("protocols.estCheck.recovery")}</p> : null}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" disabled={running || typeof api.estQualification !== "function"} onClick={() => void runCheck()}>
          {running ? t("protocols.estCheck.running") : result ? t("protocols.estCheck.runAgain") : t("protocols.estCheck.run")}
        </Button>
        <p className="max-w-3xl text-caption text-muted-foreground">{t("protocols.estCheck.clientBoundary")}</p>
      </div>
    </section>
  );
}
