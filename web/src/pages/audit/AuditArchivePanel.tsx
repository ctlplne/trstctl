import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type AuditArchiveSegment } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";

/** A234: the tenant's own archived audit segments. Each download is the exact
 * signed retention segment (verify it offline with the published audit keys);
 * the server records every download in the audit log before releasing it. */
export function AuditArchivePanel() {
  const { t, formatDateTime } = useTranslation();
  const query = useApiQuery(["audit", "archives"], () => api.auditArchives(), { retry: false });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function download(segment: AuditArchiveSegment) {
    setBusy(segment.id);
    setError(null);
    try {
      const release = await api.downloadAuditArchive(segment.id);
      const blob = new Blob([release.bundle], { type: "application/jose" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `audit-segment-${release.first_record}-${release.last_record}.jws`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(apiProblemMessage(err, t("audit.archives.downloadFailed")));
    } finally {
      setBusy(null);
    }
  }

  const segments = query.data?.items ?? [];
  return (
    <section aria-labelledby="audit-archive-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="audit-archive-heading" className="text-title font-semibold">
        {t("audit.archives.heading")}
      </h2>
      <p className="mt-1 max-w-3xl text-muted-foreground">{t("audit.archives.description")}</p>
      {query.errorValue ? (
        <ErrorState title={t("audit.archives.unavailable")}>{apiProblemMessage(query.errorValue, t("audit.archives.unavailable"))}</ErrorState>
      ) : null}
      {error ? <ErrorState title={t("audit.archives.downloadFailed")}>{error}</ErrorState> : null}
      {query.data && segments.length === 0 ? <p className="mt-2 text-muted-foreground">{t("audit.archives.empty")}</p> : null}
      {segments.length > 0 ? (
        <table className="mt-3 w-full text-left" aria-label={t("audit.archives.heading")}>
          <thead>
            <tr className="border-b border-border text-caption text-muted-foreground">
              <th className="py-2 font-medium">{t("audit.archives.records")}</th>
              <th className="py-2 font-medium">{t("audit.archives.archivedAt")}</th>
              <th className="py-2 font-medium">{t("audit.archives.chainHead")}</th>
              <th className="py-2 font-medium">
                <span className="sr-only">{t("audit.archives.download")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {segments.map((segment) => (
              <tr key={segment.id} className="border-b border-border/60">
                <td className="py-2">
                  {segment.first_record > 0
                    ? t("audit.archives.range", { first: segment.first_record, last: segment.last_record })
                    : t("audit.archives.rangeThrough", { last: segment.last_record })}
                </td>
                <td className="py-2">{formatDateTime(segment.archived_at)}</td>
                <td className="py-2 font-mono text-caption" title={segment.chain_head}>
                  {segment.chain_head.slice(0, 16)}
                </td>
                <td className="py-2 text-right">
                  <Button type="button" size="sm" variant="outline" disabled={busy !== null} onClick={() => void download(segment)}>
                    {t("audit.archives.download")}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <p className="mt-3 text-caption text-muted-foreground">{t("audit.archives.verifyHint")}</p>
    </section>
  );
}
