import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { SectionCard, DashboardGrid } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { useTranslation, type I18nContextValue } from "@/i18n/I18nProvider";
import { api, ApiError, type CTMonitoring, type DiscoveryFinding, type DiscoveryRun } from "@/lib/api";

// Certificate Transparency monitoring, as a headline discovery capability (C5).
//
// The backend has been polling RFC 6962 logs, checkpointing them, and raising
// unexpected-issuance findings for a while. What it never had was a place an
// operator would look. On Discovery it was one number in a tile it shared with
// drift detection — "CT-log & drift findings" — which is not a capability, it is
// a footnote. The configuration lived on Posture, the findings surfaced
// elsewhere, and the question the feature actually answers ("is someone issuing
// certificates for my domains?") was not asked anywhere on the page.
//
// This is the whole loop on one surface: what is watched, whether the logs are
// actually being polled, what was found, and where to take it next. It also says
// out loud what it does not cover, because an empty findings list from two
// configured domains is not an all-clear for an estate.

type CTRead = { kind: "ready"; monitoring: CTMonitoring } | { kind: "permission-denied" } | { kind: "unavailable" };

async function readCTMonitoring(): Promise<CTRead> {
  try {
    return { kind: "ready", monitoring: await api.ctMonitoring() };
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) return { kind: "permission-denied" };
    if (error instanceof ApiError && [0, 404, 501, 503].includes(error.status)) return { kind: "unavailable" };
    throw error;
  }
}

function linesOf(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

/** The certificate an unexpected-issuance finding is about, as far as the
 * finding records it. Metadata is free-form, so read defensively rather than
 * rendering "undefined" at an operator. */
function findingDetail(finding: DiscoveryFinding): { subject: string; issuer: string } {
  const metadata = (finding.metadata ?? {}) as Record<string, unknown>;
  const read = (key: string) => (typeof metadata[key] === "string" ? (metadata[key] as string) : "");
  return {
    subject: read("subject") || read("common_name") || finding.ref,
    issuer: read("issuer") || read("issuer_name"),
  };
}

function pollStatusLabel(status: string, t: I18nContextValue["t"]): string {
  if (status === "succeeded") return t("discovery.ct.pollSucceeded");
  if (status === "failed") return t("discovery.ct.pollFailed");
  return t("discovery.ct.neverPolled");
}

type CTMonitoringPanelProps = {
  refreshToken?: number;
  pollIntervalMs?: number;
  onRunTerminal?: (run: DiscoveryRun) => void | Promise<void>;
};

function discoveryRunIsActive(run: DiscoveryRun | undefined): boolean {
  return run?.status === "queued" || run?.status === "running";
}

export function CTMonitoringPanel({ refreshToken = 0, pollIntervalMs = 1000, onRunTerminal }: CTMonitoringPanelProps) {
  const { formatDateTime, t } = useTranslation();
  const canRead = useCan("discovery:read");
  const canWrite = useCan("discovery:write");
  // Plain fetch-on-mount rather than the query cache, matching how the rest of
  // the Discovery page loads: the panel then renders anywhere the page does,
  // without every consumer having to provide a query client.
  const [read, setRead] = useState<CTRead | null>(null);
  const refresh = useCallback(() => {
    if (!canRead) return Promise.resolve();
    return readCTMonitoring()
      .then(setRead)
      .catch(() => setRead({ kind: "unavailable" }));
  }, [canRead]);
  useEffect(() => {
    void refresh();
  }, [refresh, refreshToken]);
  const monitoring = read?.kind === "ready" ? read.monitoring : null;

  const [domains, setDomains] = useState<string | null>(null);
  const [logs, setLogs] = useState<string | null>(null);
  const [batch, setBatch] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [activeRunID, setActiveRunID] = useState<string | null>(null);
  const runToPoll = activeRunID ?? (discoveryRunIsActive(monitoring?.run) ? monitoring?.run?.id : null);

  useEffect(() => {
    if (!runToPoll) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const run = await api.getDiscoveryRun(runToPoll);
        if (cancelled) return;
        if (discoveryRunIsActive(run)) {
          timer = setTimeout(() => void poll(), Math.max(1, pollIntervalMs));
          return;
        }
        setResult(`run ${run.id} ${run.status}`);
        await refresh();
        if (cancelled) return;
        await onRunTerminal?.(run);
        if (!cancelled) setActiveRunID(null);
      } catch {
        if (!cancelled) timer = setTimeout(() => void poll(), Math.max(1, pollIntervalMs));
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [onRunTerminal, pollIntervalMs, refresh, runToPoll]);

  if (!canRead) return null;

  const summary = monitoring?.summary;
  const domainsValue = domains ?? (monitoring?.watched_domains ?? []).join("\n");
  const logsValue = logs ?? (monitoring?.logs ?? []).map((log) => log.url).join("\n");
  const batchValue = batch ?? "25";
  const findings = monitoring?.findings ?? [];

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setResult(null);
    try {
      const parsedBatch = Number.parseInt(batchValue, 10);
      const next = await api.updateCTMonitoring({
        name: monitoring?.source?.name || "certificate-transparency",
        watched_domains: linesOf(domainsValue),
        logs: linesOf(logsValue),
        max_batch: Number.isFinite(parsedBatch) && parsedBatch > 0 ? parsedBatch : 25,
        run_now: true,
      });
      setResult(next.run?.id ? `run ${next.run.id}` : "saved");
      setDomains(null);
      setLogs(null);
      setRead({ kind: "ready", monitoring: next });
      if (discoveryRunIsActive(next.run)) {
        setActiveRunID(next.run?.id ?? null);
      } else {
        await refresh();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <SectionCard title={t("discovery.ct.heading")} description={t("discovery.ct.description")}>
      <DashboardGrid>
        <StatTile label={t("discovery.ct.watchedDomains")} value={summary?.watched_domain_count ?? 0} />
        <StatTile label={t("discovery.ct.logs")} value={summary?.log_count ?? 0} />
        <StatTile
          label={t("discovery.ct.unexpectedIssuance")}
          value={summary?.unexpected_issuance_count ?? 0}
          tone={summary?.unexpected_issuance_count ? "critical" : undefined}
          hint={summary ? t("discovery.ct.openFindings", { count: summary.open_finding_count }) : undefined}
        />
        <StatTile
          label={t("discovery.ct.alertChannels")
            .replace("{count}", String(summary?.outbox_alert_channel_count ?? 0))
            .trim()}
          value={summary?.outbox_alert_channel_count ?? 0}
        />
      </DashboardGrid>

      <p className="mt-3 text-xs text-muted-foreground">{t("discovery.ct.coverageHonesty")}</p>

      {read?.kind === "unavailable" ? <p className="mt-3 text-sm text-muted-foreground">{t("discovery.ct.notConfigured")}</p> : null}

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="grid content-start gap-2">
          <h3 className="text-sm font-semibold">{t("discovery.ct.logHealth")}</h3>
          {(monitoring?.logs ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("discovery.ct.notConfigured")}</p>
          ) : (
            <ul className="grid gap-1">
              {(monitoring?.logs ?? []).map((log) => (
                <li key={log.url} className="grid gap-0.5 border-l-2 border-brand-accent/60 pl-2">
                  <span className="break-all font-mono text-xs">{log.url}</span>
                  <span className="text-2xs text-muted-foreground">
                    {pollStatusLabel(log.status, t)} · {t("discovery.ct.nextIndex", { value: log.next_index })}
                  </span>
                  {log.last_polled_at ? <span className="text-2xs text-muted-foreground">{formatDateTime(log.last_polled_at)}</span> : null}
                  {log.last_error ? (
                    <span className="break-words text-2xs text-risk-critical">{t("discovery.ct.lastPollError", { detail: log.last_error })}</span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          {(monitoring?.retired_logs ?? []).length > 0 ? (
            <div className="mt-3 grid gap-2 border-t border-border pt-3">
              <h4 className="text-xs font-semibold text-muted-foreground">{t("discovery.ct.retiredLogs")}</h4>
              <ul className="grid gap-1">
                {(monitoring?.retired_logs ?? []).map((log) => (
                  <li key={log.url} className="grid gap-0.5 border-l-2 border-muted-foreground/40 pl-2">
                    <span className="break-all font-mono text-xs text-muted-foreground">{log.url}</span>
                    <span className="text-2xs text-muted-foreground">
                      {pollStatusLabel(log.status, t)} · {t("discovery.ct.nextIndex", { value: log.next_index })}
                    </span>
                    {log.retired_at ? (
                      <span className="text-2xs text-muted-foreground">{t("discovery.ct.retiredAt", { value: formatDateTime(log.retired_at) })}</span>
                    ) : null}
                    {log.last_error ? (
                      <span className="break-words text-2xs text-muted-foreground">{t("discovery.ct.lastPollError", { detail: log.last_error })}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {monitoring?.run?.completed_at ? <p className="text-2xs text-muted-foreground">{formatDateTime(monitoring.run.completed_at)}</p> : null}
        </div>

        <div className="grid content-start gap-2">
          <h3 className="text-sm font-semibold">{t("discovery.ct.unexpectedIssuance")}</h3>
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("discovery.ct.noFindings")}</p>
          ) : (
            <ul className="grid gap-2">
              {findings.map((finding) => {
                const detail = findingDetail(finding);
                return (
                  <li key={finding.id} className="grid gap-0.5 border-l-2 border-risk-critical/60 pl-2">
                    <span className="text-sm font-medium">{detail.subject}</span>
                    {detail.issuer ? <span className="text-2xs text-muted-foreground">{detail.issuer}</span> : null}
                    <span className="break-all font-mono text-2xs text-muted-foreground">{finding.fingerprint}</span>
                    <span className="text-2xs text-muted-foreground">{formatDateTime(finding.discovered_at)}</span>
                    {/* One click to the rogue-certificate posture, which owns
                        revoke and the incident hand-off. The finding is the
                        detection; remediation already has a home. */}
                    <Link className="text-xs underline" to="/certificates?view=rogue">
                      {t("discovery.ct.investigate")}
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>

      {canWrite ? (
        <form className="mt-4 grid gap-2 border-t border-border pt-4" onSubmit={(event) => void submit(event)}>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">{t("discovery.ct.watchedDomains")}</span>
            <textarea
              className="min-h-16 rounded-control border border-border bg-transparent p-2 font-mono text-xs"
              value={domainsValue}
              onChange={(event) => setDomains(event.target.value)}
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">{t("discovery.ct.logs")}</span>
            <textarea
              className="min-h-16 rounded-control border border-border bg-transparent p-2 font-mono text-xs"
              value={logsValue}
              onChange={(event) => setLogs(event.target.value)}
            />
          </label>
          <label className="grid gap-1 text-sm sm:max-w-32">
            <span className="font-medium">{t("discovery.ct.cadence")}</span>
            <input
              className="rounded-control border border-border bg-transparent p-2 font-mono text-xs"
              inputMode="numeric"
              value={batchValue}
              onChange={(event) => setBatch(event.target.value)}
            />
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" size="sm" disabled={saving}>
              {t("discovery.ct.save")}
            </Button>
            {result ? <span className="text-xs text-muted-foreground">{result}</span> : null}
            {error ? <span className="text-xs text-risk-critical">{error}</span> : null}
          </div>
        </form>
      ) : null}
    </SectionCard>
  );
}
