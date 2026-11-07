import { useId, useRef, useState } from "react";
import { api } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A258: the named responders who may open emergency access — an emergency
// session, or a break-glass release (A272) — at once, without review. Each
// is a named principal; every approver is notified when one acts.

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function PAMEmergencyRespondersPanel({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const editorID = useId();
  const responders = useApiQuery(["pam-emergency-responders"], api.pamEmergencyResponders, { retry: false });
  const [draft, setDraft] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const saveKey = useRef(crypto.randomUUID());
  const subjects = responders.data?.subjects ?? [];

  async function save() {
    if (draft === null) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const next = draft
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      await api.setPAMEmergencyResponders({ subjects: next }, saveKey.current);
      saveKey.current = crypto.randomUUID();
      setDraft(null);
      setNotice(t("admin.access.responders.saved", { count: next.length }));
      await queryClient.invalidateQueries({ queryKey: ["pam-emergency-responders"] });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="pam-responders-heading" className="grid gap-3">
      <div>
        <h3 id="pam-responders-heading" className="text-body font-semibold">
          {t("admin.access.responders.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("admin.access.responders.description")}</p>
      </div>
      {notice ? (
        <p role="status" className="text-sm text-status-success">
          {notice}
        </p>
      ) : null}
      {error ? <ErrorState title={t("admin.access.responders.failed")}>{error}</ErrorState> : null}
      {responders.loading ? <LoadingState>{t("admin.access.responders.loading")}</LoadingState> : null}
      {responders.data && subjects.length === 0 && draft === null ? <UnavailableState title={t("admin.access.responders.none")} /> : null}
      {subjects.length > 0 && draft === null ? (
        <ul aria-label={t("admin.access.responders.heading")} className="grid gap-1 text-sm">
          {subjects.map((subject) => (
            <li key={subject} className="font-mono text-xs">
              {subject}
            </li>
          ))}
        </ul>
      ) : null}
      {canManage ? (
        draft === null ? (
          <div>
            <Button type="button" size="sm" variant="outline" disabled={busy || !!responders.error} onClick={() => setDraft(subjects.join("\n"))}>
              {t("admin.access.responders.edit")}
            </Button>
          </div>
        ) : (
          <form
            className="grid gap-2 text-sm"
            onSubmit={(event) => {
              event.preventDefault();
              void save();
            }}
          >
            <label htmlFor={editorID}>{t("admin.access.responders.editor")}</label>
            <textarea
              id={editorID}
              className="min-h-24 rounded-md border border-input bg-background p-2 font-mono text-xs"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
            />
            <div className="flex gap-2">
              <Button type="submit" size="sm" disabled={busy}>
                {t("admin.access.responders.save")}
              </Button>
              <Button type="button" size="sm" variant="ghost" onClick={() => setDraft(null)}>
                {t("admin.access.responders.cancel")}
              </Button>
            </div>
          </form>
        )
      ) : null}
    </section>
  );
}
