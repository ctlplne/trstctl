import { useEffect, useRef, useState } from "react";

import { PAMCommandActions } from "@/components/access/PAMCommandActions";
import { Field } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type PAMQueryResult } from "@/lib/api";

// A259 part 2: a database console on a PostgreSQL session opened for the
// browser. The control plane runs each SQL text through the session's gateway,
// which signs in as the session's login and records the statement; the
// console shows the last result's rows or the database's own refusal. No
// credential or ticket reaches the browser.

export function SqlConsole({ sessionID, onClose, commandRules = false }: { sessionID: string; onClose: () => void; commandRules?: boolean }) {
  const { t } = useTranslation();
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  const [sql, setSQL] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PAMQueryResult | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  async function run() {
    const text = sql.trim();
    if (!text || busy) return;
    setBusy(true);
    setFailure(null);
    const controller = new AbortController();
    active.current = controller;
    try {
      setResult(await api.runPAMQuery(sessionID, text, `pam-query:${sessionID}:${crypto.randomUUID()}`, controller.signal));
    } catch (err) {
      setResult(null);
      setFailure(controller.signal.aborted ? t("admin.access.rules.queryCanceled") : err instanceof Error ? err.message : String(err));
    } finally {
      active.current = null;
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby={`pam-console-${sessionID}`} className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 id={`pam-console-${sessionID}`} className="text-sm font-semibold">
          {t("admin.access.console.title")}
        </h3>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            active.current?.abort();
            onClose();
          }}
        >
          {t("admin.access.console.close")}
        </Button>
      </div>
      <Field label={t("admin.access.console.sql")}>
        {(control) => (
          <Textarea {...control} className="min-h-24 font-mono text-xs" value={sql} onChange={(event) => setSQL(event.target.value)} spellCheck={false} />
        )}
      </Field>
      <div>
        <Button type="button" disabled={busy || !sql.trim()} onClick={() => void run()}>
          {t("admin.access.console.run")}
        </Button>
        {busy ? (
          <Button type="button" variant="outline" onClick={() => active.current?.abort()}>
            {t("admin.access.rules.cancelQuery")}
          </Button>
        ) : null}
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
      {commandRules ? <PAMCommandActions sessionID={sessionID} live={busy} /> : null}
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
