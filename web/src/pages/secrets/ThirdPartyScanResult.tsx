import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DiscoveryRun } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";

const runIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function ThirdPartyScanResult() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const runID = searchParams.get("third_party_run")?.trim() ?? "";
  const [lookup, setLookup] = useState<string | null>(null);
  const [lookupError, setLookupError] = useState(false);
  const validRunID = runIDPattern.test(runID);
  const runQuery = useApiQuery(
    ["third-party-scan-run", runID],
    async () => {
      const result = await api.getDiscoveryRun(runID);
      if (result.id !== runID) throw new Error(t("secrets.thirdPartyScan.mismatchedRun"));
      return result;
    },
    { enabled: validRunID, retry: false },
  );
  const run = runQuery.data;
  const terminal = run?.status === "succeeded" || run?.status === "partial" || run?.status === "failed";
  const findingsQuery = useApiQuery(["third-party-scan-findings", runID], () => api.discoveryFindings({ runId: runID, limit: 50 }), {
    enabled: Boolean(terminal),
    retry: false,
  });
  const findings = findingsQuery.data?.items.filter((finding) => finding.run_id === runID) ?? [];

  function openRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requested = (lookup ?? runID).trim();
    if (!runIDPattern.test(requested)) {
      setLookupError(true);
      return;
    }
    setLookupError(false);
    setLookup(null);
    if (requested === runID) {
      runQuery.refetch();
      if (terminal) findingsQuery.refetch();
      return;
    }
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("third_party_run", requested);
      return next;
    });
  }

  return (
    <section aria-label={t("secrets.thirdPartyScan.resultTitle")} className="grid gap-3 rounded-control border border-border p-4">
      <div>
        <h3 className="font-semibold">{t("secrets.thirdPartyScan.resultTitle")}</h3>
        <p className="text-sm text-muted-foreground">{t("secrets.thirdPartyScan.resultHelp")}</p>
      </div>
      <form onSubmit={openRun} className="flex flex-wrap items-end gap-2">
        <label className="grid min-w-[18rem] flex-1 gap-1 text-sm">
          <span>{t("secrets.thirdPartyScan.runId")}</span>
          <Input value={lookup ?? runID} onChange={(event) => setLookup(event.target.value)} autoComplete="off" />
        </label>
        <Button type="submit" variant="outline">
          {t("secrets.thirdPartyScan.openRun")}
        </Button>
        {validRunID && (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              runQuery.refetch();
              if (terminal) findingsQuery.refetch();
            }}
            disabled={runQuery.fetching}
          >
            {t("secrets.thirdPartyScan.refreshRun")}
          </Button>
        )}
      </form>
      {lookupError && (
        <p role="alert" className="text-sm text-destructive">
          {t("secrets.thirdPartyScan.invalidRunId")}
        </p>
      )}
      {runID && !validRunID && (
        <p role="alert" className="text-sm text-destructive">
          {t("secrets.thirdPartyScan.invalidRunId")}
        </p>
      )}
      {validRunID && runQuery.loading && (
        <p role="status" className="text-sm">
          {t("secrets.thirdPartyScan.loadingRun")}
        </p>
      )}
      {runQuery.errorValue != null && (
        <p role="alert" className="text-sm text-destructive">
          {apiProblemMessage(runQuery.errorValue, t("secrets.thirdPartyScan.loadError"))}
        </p>
      )}
      {run && (
        <div className="grid gap-2 text-sm">
          <p>
            <span className="font-medium">{t("secrets.thirdPartyScan.status")}: </span>
            {statusLabel(run.status, t)}
          </p>
          {terminal ? (
            <>
              {findingsQuery.loading && <p role="status">{t("secrets.thirdPartyScan.loadingFindings")}</p>}
              {findingsQuery.errorValue != null && (
                <p role="alert" className="text-destructive">
                  {apiProblemMessage(findingsQuery.errorValue, t("secrets.thirdPartyScan.findingsError"))}
                </p>
              )}
              {findingsQuery.data && (
                <p>
                  {findingsQuery.data.next_cursor
                    ? t("secrets.thirdPartyScan.firstFindings", { count: findings.length })
                    : t("secrets.thirdPartyScan.findingCount", { count: findings.length })}
                </p>
              )}
              {findings.length > 0 && (
                <ul className="grid gap-1">
                  {findings.map((finding) => (
                    <li key={finding.id} className="rounded-control border border-border px-3 py-2">
                      {finding.kind} · {finding.ref} · {finding.triage_status ?? t("secrets.thirdPartyScan.unmanaged")}
                    </li>
                  ))}
                </ul>
              )}
            </>
          ) : (
            <p className="text-muted-foreground">{t("secrets.thirdPartyScan.pendingHelp")}</p>
          )}
          {(run.status === "failed" || run.status === "partial") && <p role="alert">{run.error || t("secrets.thirdPartyScan.runFailed")}</p>}
          <Link className="text-primary underline underline-offset-2" to={`/discovery?run_id=${encodeURIComponent(runID)}`}>
            {t("secrets.thirdPartyScan.reviewFindings")}
          </Link>
        </div>
      )}
    </section>
  );
}

function statusLabel(status: DiscoveryRun["status"], t: ReturnType<typeof useTranslation>["t"]): string {
  switch (status) {
    case "queued":
      return t("secrets.thirdPartyScan.statusQueued");
    case "running":
      return t("secrets.thirdPartyScan.statusRunning");
    case "succeeded":
      return t("secrets.thirdPartyScan.statusSucceeded");
    case "partial":
      return t("secrets.thirdPartyScan.statusPartial");
    case "failed":
      return t("secrets.thirdPartyScan.statusFailed");
  }
}
