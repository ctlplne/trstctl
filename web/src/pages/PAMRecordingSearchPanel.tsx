/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow region needs keyboard focus for horizontal scrolling. */
import { useId, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type PAMRecordingSearchHit, type PAMRecordingSearchResult } from "@/lib/api";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A275: search every recorded session of the tenant at once — SSH commands
// and output, SQL statements and results, remote desktop indexes. Results
// are masked; every search is recorded.

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function offset(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

export function PAMRecordingSearchPanel() {
  const { locale, timeZone, t } = useTranslation();
  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const ids = { query: useId(), target: useId() };
  const [query, setQuery] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PAMRecordingSearchResult | null>(null);

  async function search() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.searchPAMRecordings({ q: query.trim(), targetID: target.trim() || undefined }));
    } catch (err) {
      setResult(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const source = (hit: PAMRecordingSearchHit) =>
    t(
      (
        {
          command: "admin.access.recordingSearch.sourceCommand",
          sql: "admin.access.recordingSearch.sourceSQL",
          result: "admin.access.recordingSearch.sourceResult",
          output: "admin.access.recordingSearch.sourceOutput",
          index: "admin.access.recordingSearch.sourceIndex",
          request: "admin.access.recordingSearch.sourceRequest",
        } as const
      )[hit.source],
    );

  return (
    <section aria-labelledby="pam-recording-search-heading" className="grid gap-3">
      <div>
        <h3 id="pam-recording-search-heading" className="text-body font-semibold">
          {t("admin.access.recordingSearch.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("admin.access.recordingSearch.description")}</p>
      </div>
      <form
        className="flex flex-wrap items-end gap-3 text-sm"
        aria-label={t("admin.access.recordingSearch.form")}
        onSubmit={(event) => {
          event.preventDefault();
          void search();
        }}
      >
        <div className="grid gap-1">
          <label htmlFor={ids.query}>{t("admin.access.recordingSearch.query")}</label>
          <Input id={ids.query} required minLength={3} maxLength={200} value={query} onChange={(event) => setQuery(event.target.value)} />
        </div>
        <div className="grid gap-1">
          <label htmlFor={ids.target}>{t("admin.access.recordingSearch.target")}</label>
          <Input id={ids.target} value={target} onChange={(event) => setTarget(event.target.value)} />
        </div>
        <Button type="submit" size="sm" variant="outline" loading={busy} disabled={query.trim().length < 3}>
          {t("admin.access.recordingSearch.search")}
        </Button>
      </form>
      {busy ? <LoadingState>{t("admin.access.recordingSearch.searching")}</LoadingState> : null}
      {error ? <ErrorState title={t("admin.access.recordingSearch.failed")}>{error}</ErrorState> : null}
      {result ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t(result.truncated ? "admin.access.recordingSearch.summaryTruncated" : "admin.access.recordingSearch.summary", {
            matches: result.items.length,
            sessions: result.sessions_searched,
          })}
        </p>
      ) : null}
      {result && result.items.length === 0 ? <UnavailableState title={t("admin.access.recordingSearch.none")} /> : null}
      {result && result.items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.recordingSearch.results")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.recordingSearch.results")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.recordingSearch.session")}</th>
                <th scope="col">{t("admin.access.recordingSearch.where")}</th>
                <th scope="col">{t("admin.access.recordingSearch.what")}</th>
                <th scope="col">{t("admin.access.recordingSearch.line")}</th>
              </tr>
            </thead>
            <tbody>
              {result.items.map((hit, i) => (
                <tr key={`${hit.session_id}:${hit.at_millis}:${i}`}>
                  <td>
                    <Link to={`/admin/access?session=${encodeURIComponent(hit.session_id)}`} className="underline">
                      {t("admin.access.recordingSearch.open", {
                        started: formatDateTime(hit.session_started_at, policy),
                        at: offset(hit.at_millis),
                      })}
                    </Link>
                  </td>
                  <td>
                    {hit.target_type}/{hit.target_id}
                    <span className="block text-caption text-muted-foreground">{hit.subject}</span>
                  </td>
                  <td>{source(hit)}</td>
                  <td className="whitespace-pre-wrap break-all font-mono text-xs">{hit.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
