import { useId, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type PAMQueryResult } from "@/lib/api";

// A259 part 2: a database console on a PostgreSQL session opened for the
// browser. The control plane runs each SQL text through the session's gateway,
// which signs in as the session's login and records the statement; the
// console shows the last result's rows or the database's own refusal. No
// credential or ticket reaches the browser.

export function SqlConsole({ sessionID, onClose }: { sessionID: string; onClose: () => void }) {
  const { t } = useTranslation();
  const sqlID = useId();
  const [sql, setSQL] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PAMQueryResult | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const runs = useRef(0);

  async function run() {
    const text = sql.trim();
    if (!text || busy) return;
    setBusy(true);
    setFailure(null);
    runs.current += 1;
    try {
      setResult(await api.runPAMQuery(sessionID, text, `pam-query:${sessionID}:${crypto.randomUUID()}`));
    } catch (err) {
      setResult(null);
      setFailure(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby={`pam-console-${sessionID}`} className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 id={`pam-console-${sessionID}`} className="text-sm font-semibold">
          {t("admin.access.console.title")}
        </h3>
        <Button type="button" variant="outline" onClick={onClose}>
          {t("admin.access.console.close")}
        </Button>
      </div>
      <label htmlFor={sqlID} className="text-sm">
        {t("admin.access.console.sql")}
      </label>
      <textarea
        id={sqlID}
        className="min-h-24 rounded-control border border-border bg-background p-2 font-mono text-xs"
        value={sql}
        onChange={(event) => setSQL(event.target.value)}
        spellCheck={false}
      />
      <div>
        <Button type="button" disabled={busy || !sql.trim()} onClick={() => void run()}>
          {t("admin.access.console.run")}
        </Button>
      </div>
      <div role="status" aria-live="polite" className="text-sm text-muted-foreground">
        {busy
          ? t("admin.access.console.running")
          : failure
            ? t("admin.access.console.failed", { error: failure })
            : result?.error
              ? t("admin.access.console.refused", { code: result.error.code, message: result.error.message })
              : result
                ? t("admin.access.console.rows", { count: result.rows.length, tag: result.command_tag ?? "" })
                : null}
      </div>
      {result && !result.error && result.columns.length > 0 ? (
        <div className="overflow-auto">
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.console.caption")}</caption>
            <thead>
              <tr>
                {result.columns.map((column, i) => (
                  <th key={`${column}-${i}`} scope="col">
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row, r) => (
                <tr key={r}>
                  {row.map((cell, c) => {
                    // The contract's cells are strings or null (SQL NULL).
                    const value = cell as string | null;
                    return (
                      <td key={c} className="font-mono text-xs">
                        {value === null ? <span className="text-muted-foreground">{t("admin.access.console.null")}</span> : value}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          {result.truncated ? <p className="text-xs text-muted-foreground">{t("admin.access.console.truncated")}</p> : null}
        </div>
      ) : null}
    </section>
  );
}
