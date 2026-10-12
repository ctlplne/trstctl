import { useEffect, useState } from "react";

import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type BreakglassIssueReceipt, type BreakglassIssueReceiptList } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

/** Recovery is a tenant-scoped, bounded SQL read, even after a browser reload. */
export function BreakglassIssueHistory({ latestCeremonyID }: { latestCeremonyID: string | null }) {
  const { t, formatDateTime } = useTranslation();
  const [cursor, setCursor] = useState("");
  const [previous, setPrevious] = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const page = useApiQuery<BreakglassIssueReceiptList>(["breakglass-issues", cursor], () => api.breakglassIssues({ limit: 20, cursor }));
  const detail = useApiQuery<BreakglassIssueReceipt>(["breakglass-issue", selected], () => api.getBreakglassIssue(selected), { enabled: selected !== "" });

  useEffect(() => {
    if (latestCeremonyID) {
      setCursor("");
      setPrevious([]);
      setSelected(latestCeremonyID);
    }
  }, [latestCeremonyID]);
  useEffect(() => {
    if (!selected && page.data?.items.length) setSelected(page.data.items[0].ceremony_id);
  }, [page.data, selected]);

  function nextPage() {
    if (!page.data?.next_cursor) return;
    setPrevious((current) => [...current, cursor]);
    setCursor(page.data.next_cursor);
    setSelected("");
  }
  function previousPage() {
    setCursor(previous[previous.length - 1] ?? "");
    setPrevious((current) => current.slice(0, -1));
    setSelected("");
  }

  return (
    <details open className="rounded-panel border border-border bg-card">
      <summary className="cursor-pointer px-4 py-3 font-medium">{t("breakglass.history.title")}</summary>
      <div className="grid gap-3 border-t border-border p-4">
        <p className="text-sm text-muted-foreground">{t("breakglass.history.help")}</p>
        {page.error ? <ErrorState title={t("breakglass.history.failed")}>{page.error}</ErrorState> : null}
        {page.loading ? <p role="status">{t("breakglass.history.loading")}</p> : null}
        {page.data && page.data.items.length === 0 ? <p>{t("breakglass.history.empty")}</p> : null}
        {page.data?.items.map((item) => (
          <Button
            key={item.ceremony_id}
            type="button"
            variant={selected === item.ceremony_id ? "default" : "outline"}
            className="h-auto justify-start whitespace-normal text-start"
            onClick={() => setSelected(item.ceremony_id)}
          >
            {item.subject} · {item.request_id} · {formatDateTime(item.issued_at)}
          </Button>
        ))}
        <div className="flex flex-wrap gap-2">
          {previous.length ? (
            <Button type="button" variant="outline" onClick={previousPage}>
              {t("breakglass.history.previous")}
            </Button>
          ) : null}
          {page.data?.next_cursor ? (
            <Button type="button" variant="outline" onClick={nextPage}>
              {t("breakglass.history.more")}
            </Button>
          ) : null}
          <Button type="button" variant="outline" onClick={page.refetch}>
            {t("breakglass.history.refresh")}
          </Button>
        </div>
        {detail.error ? <ErrorState title={t("breakglass.history.readFailed")}>{detail.error}</ErrorState> : null}
        {detail.data?.bundle ? (
          <div className="grid gap-3 rounded-control border border-border p-3 text-sm">
            <p className="font-medium">{t("breakglass.history.signed", { subject: detail.data.subject })}</p>
            <p className="break-all font-mono text-xs">{t("breakglass.history.ceremony", { id: detail.data.ceremony_id })}</p>
            <p>{t("breakglass.history.issued", { time: formatDateTime(detail.data.issued_at) })}</p>
            <p>{t("breakglass.history.sequence", { sequence: detail.data.event_sequence })}</p>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                onClick={() => downloadText(`breakglass-${detail.data!.ceremony_id}.json`, JSON.stringify(detail.data!.bundle, null, 2), "application/json")}
              >
                {t("breakglass.history.downloadBundle")}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  downloadText(`breakglass-${detail.data!.ceremony_id}.pem`, certificatePEM(detail.data!.bundle!.cert_der), "application/x-pem-file")
                }
              >
                {t("breakglass.history.downloadCertificate")}
              </Button>
            </div>
            <p className="text-muted-foreground">{t("breakglass.history.privateKey")}</p>
          </div>
        ) : null}
      </div>
    </details>
  );
}

function certificatePEM(base64DER: string): string {
  const lines = base64DER.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function downloadText(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
