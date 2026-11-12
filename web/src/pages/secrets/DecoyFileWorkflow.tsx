import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DecoyFile } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// Q6-O1: decoy SSH keys host agents planted (trstctl-agent --decoy-ssh-keys).
// Each program that opens one raises one critical alert naming the program and
// the host; the list shows who opened each first and how often. Decoys are
// planted by the agent, so the console lists and retires them.
export function DecoyFileWorkflow() {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const [items, setItems] = useState<DecoyFile[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The read failure is kept as its cause and worded at render, so the
  // refresh does not change with the translator.
  const [readFailure, setReadFailure] = useState<{ cause: unknown } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const decoys = await api.listDecoyFiles();
      setItems(decoys.items);
      setReadFailure(null);
    } catch (cause) {
      setReadFailure({ cause });
    }
  }, []);

  useEffect(() => {
    if (canWrite) void refresh();
  }, [canWrite, refresh]);

  if (!canWrite) return null;

  async function retire(id: string) {
    setBusy(true);
    setError(null);
    try {
      await api.retireDecoyFile(id);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.decoyFiles.retireFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="decoy-file-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="decoy-file-heading" className="text-title font-semibold">
          {t("secrets.decoyFiles.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.decoyFiles.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.decoyFiles.error")}>{error}</ErrorState> : null}
      {readFailure ? (
        <ErrorState title={t("secrets.decoyFiles.error")}>{apiProblemMessage(readFailure.cause, t("secrets.decoyFiles.readFailed"))}</ErrorState>
      ) : null}
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.decoyFiles.empty")}</p>
      ) : (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong className="break-all font-mono">{item.file_path}</strong>
                <span className={item.state === "triggered" ? "font-semibold text-destructive" : "text-muted-foreground"}>{item.state}</span>
              </div>
              <p>{t("secrets.decoyFiles.host", { host: item.file_host })}</p>
              <p className="break-all text-muted-foreground">{t("secrets.decoyFiles.key", { fingerprint: item.file_key_fingerprint })}</p>
              {item.triggered_at && item.trigger_subject ? (
                <p>
                  {t("secrets.decoyFiles.opened", {
                    reader: item.trigger_subject,
                    at: formatDateTime(item.triggered_at),
                    method: item.trigger_method ?? "",
                  })}
                </p>
              ) : null}
              {item.readers && item.last_read_at ? (
                <p>{t("secrets.decoyFiles.readers", { readers: item.readers, reads: item.reads ?? item.readers, at: formatDateTime(item.last_read_at) })}</p>
              ) : null}
              {item.state !== "revoked" ? (
                <Button type="button" variant="outline" className="mt-2" onClick={() => void retire(item.id)} disabled={busy}>
                  {t("secrets.decoyFiles.retire")}
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
