import { useCallback, useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { api, type SPIFFEQualification } from "@/lib/api";

const previewChecks = [
  ["identity", "protocols.spiffeCheck.identityPreview", "protocols.spiffeCheck.identityPreviewDetail"],
  ["socket", "protocols.spiffeCheck.socketPreview", "protocols.spiffeCheck.socketPreviewDetail"],
  ["issue", "protocols.spiffeCheck.issuePreview", "protocols.spiffeCheck.issuePreviewDetail"],
  ["capacity", "protocols.spiffeCheck.capacityPreview", "protocols.spiffeCheck.capacityPreviewDetail"],
] as const;

function isSPIFFEQualification(value: unknown): value is SPIFFEQualification {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Partial<SPIFFEQualification>;
  return (
    typeof result.checked_at === "string" &&
    typeof result.ready === "boolean" &&
    result.effect_free === true &&
    typeof result.trust_domain === "string" &&
    typeof result.socket_uri === "string" &&
    result.transport === "unix" &&
    typeof result.registration_entry_count === "number" &&
    typeof result.local_socket_deprecated === "boolean" &&
    Array.isArray(result.supported_operations) &&
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

export function SPIFFEOperatorPanel({ onResult }: { onResult?: (result: SPIFFEQualification) => void }) {
  const { t } = useTranslation();
  const [result, setResult] = useState<SPIFFEQualification | null>(null);
  const [running, setRunning] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const runCheck = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const next = await api.spiffeQualification();
      if (!isSPIFFEQualification(next)) throw new Error(translateNow("protocols.spiffeCheck.invalidResult"));
      setResult(next);
      onResult?.(next);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : translateNow("protocols.spiffeCheck.failedBody"));
    } finally {
      setRunning(false);
    }
  }, [onResult]);

  useEffect(() => {
    void runCheck();
  }, [runCheck]);

  return (
    <Card
      id="spiffe-operator-panel"
      role="region"
      aria-labelledby="spiffe-operator-heading"
      aria-label={t("protocols.spiffeCheck.region")}
      className="min-w-0 scroll-mt-24"
    >
      <CardHeader className="flex-row flex-wrap items-start justify-between gap-3 space-y-0">
        <div className="min-w-0 max-w-3xl">
          <CardTitle id="spiffe-operator-heading">{t("protocols.spiffeCheck.heading")}</CardTitle>
          <p className="mt-1 text-body text-muted-foreground">{t("protocols.spiffeCheck.description")}</p>
        </div>
        {result ? (
          <StatusBadge
            value={result.ready ? "ready" : "blocked"}
            label={result.ready ? t("protocols.spiffeCheck.ready") : t("protocols.spiffeCheck.blocked")}
            tone={result.ready ? "success" : "warning"}
          />
        ) : null}
      </CardHeader>

      <CardContent className="grid min-w-0 gap-5">
        <div className="grid gap-3 border-y border-border py-4">
          <div>
            <p className="text-sm font-semibold">{t("protocols.spiffeCheck.previewHeading")}</p>
            <p className="mt-1 text-caption text-muted-foreground">{t("protocols.spiffeCheck.safePreview")}</p>
          </div>
          <ol className="grid gap-2 md:grid-cols-2">
            {previewChecks.map(([id, titleKey, detailKey], index) => (
              <li key={id} className="grid min-w-0 grid-cols-[1.5rem_minmax(0,1fr)] gap-1 border-s-2 border-border ps-3">
                <span className="text-caption font-medium text-muted-foreground" aria-hidden="true">
                  {index + 1}
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{t(titleKey)}</p>
                  <p className="mt-1 text-caption text-muted-foreground">{t(detailKey)}</p>
                </div>
              </li>
            ))}
          </ol>
        </div>

        {running && !result ? <LoadingState>{t("protocols.spiffeCheck.running")}</LoadingState> : null}
        {error ? <ErrorState title={t("protocols.spiffeCheck.failedTitle")}>{error}</ErrorState> : null}

        {result ? (
          <div role="status" aria-live="polite" className="grid gap-4">
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <RuntimeFact label={t("protocols.spiffeCheck.trustDomain")} value={result.trust_domain} />
              <RuntimeFact label={t("protocols.spiffeCheck.socket")} value={result.socket_uri} />
              <RuntimeFact
                label={t("protocols.spiffeCheck.entries")}
                value={t("protocols.spiffeCheck.entryCount", { count: result.registration_entry_count })}
              />
              <RuntimeFact
                label={t("protocols.spiffeCheck.operations")}
                value={t("protocols.spiffeCheck.operationCount", { count: result.supported_operations.length })}
              />
            </dl>

            <ul className="grid gap-2" aria-label={t("protocols.spiffeCheck.resultsLabel")}>
              {result.checks.map((check) => (
                <li key={check.id} className="grid min-w-0 gap-2 border-s-2 border-border ps-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{check.label}</p>
                    <p className="mt-1 text-caption text-muted-foreground">{check.detail}</p>
                    {!check.passed && check.recovery ? <p className="mt-1 text-sm text-status-warning">{check.recovery}</p> : null}
                  </div>
                  <StatusBadge
                    value={check.passed ? "passed" : "failed"}
                    label={check.passed ? t("protocols.spiffeCheck.passed") : t("protocols.spiffeCheck.failed")}
                    tone={check.passed ? "success" : "critical"}
                  />
                </li>
              ))}
            </ul>

            {result.local_socket_deprecated ? (
              <div className="rounded-control border border-status-warning/30 bg-status-warning/5 px-3 py-2 text-sm">
                <p className="font-medium">{t("protocols.spiffeCheck.migrationHeading")}</p>
                <p className="mt-1 text-caption text-muted-foreground">{t("protocols.spiffeCheck.migrationBody")}</p>
              </div>
            ) : null}

            <div className="rounded-control border border-status-success/30 bg-status-success/5 px-3 py-2 text-caption text-muted-foreground">
              {t("protocols.spiffeCheck.effectProof")}
            </div>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
          <Button type="button" disabled={running || typeof api.spiffeQualification !== "function"} onClick={() => void runCheck()}>
            {running ? t("protocols.spiffeCheck.running") : result ? t("protocols.spiffeCheck.runAgain") : t("protocols.spiffeCheck.run")}
          </Button>
          <p className="max-w-3xl text-caption text-muted-foreground">{result?.client_boundary || t("protocols.spiffeCheck.clientBoundary")}</p>
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
