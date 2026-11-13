import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DeletedSecret } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { newIdempotencyKey } from "@/lib/apiTransport";

// A236-L4: a deleted secret is kept, sealed with its version history, until
// the deleted-secret retention window ends. This panel lists what is kept
// (never a value), restores one at the version it had, or purges one now. A
// restore under dual control names its approval request and keeps the same
// request, so restoring again after the approval applies exactly it.
export function DeletedSecrets({ refreshKey, onRestored }: { refreshKey: number; onRestored: () => void }) {
  const { t } = useTranslation();
  const [items, setItems] = useState<DeletedSecret[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loadFailure, setLoadFailure] = useState<{ cause: unknown } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [awaiting, setAwaiting] = useState<{ name: string; request: string } | null>(null);
  const [confirmPurge, setConfirmPurge] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const restoreKeys = useRef(new Map<string, string>());

  // The list loads on mount and after each deletion (refreshKey); a failure
  // keeps its cause and is worded at render, so the loader never depends on
  // the translation function's identity.
  const load = useCallback(async () => {
    try {
      setItems((await api.listDeletedSecrets()).items);
      setLoadFailure(null);
    } catch (cause) {
      setLoadFailure({ cause });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  async function restore(name: string) {
    // One request per deleted secret: a retry after an approval or a lost
    // answer replays the same command instead of asking for a second one.
    const key = restoreKeys.current.get(name) ?? newIdempotencyKey();
    restoreKeys.current.set(name, key);
    setBusy(name);
    setMessage(null);
    try {
      const restored = await api.restoreDeletedSecret(name, key);
      restoreKeys.current.delete(name);
      setAwaiting(null);
      setError(null);
      setMessage(t("secrets.deleted.restored", { name: restored.name, version: String(restored.version) }));
      onRestored();
      await load();
    } catch (cause) {
      const reason = apiProblemMessage(cause, t("secrets.deleted.restoreFailed"));
      const pending = /approval_required:\S+ request_id=([0-9a-f-]{36})/.exec(reason);
      if (pending) {
        setError(null);
        setAwaiting({ name, request: pending[1] });
      } else {
        restoreKeys.current.delete(name);
        setError(reason);
      }
    } finally {
      setBusy(null);
    }
  }

  async function purge(name: string) {
    setBusy(name);
    setMessage(null);
    try {
      await api.purgeDeletedSecret(name, newIdempotencyKey());
      setConfirmPurge(null);
      setError(null);
      setMessage(t("secrets.deleted.purged", { name }));
      await load();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.deleted.purgeFailed")));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section aria-labelledby="deleted-secrets-heading" className="grid gap-3 border-t border-border pt-3">
      <h3 id="deleted-secrets-heading" className="font-semibold">
        {t("secrets.deleted.heading")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("secrets.deleted.help")}</p>
      {error || loadFailure ? (
        <ErrorState title={t("secrets.deleted.error")}>{error ?? apiProblemMessage(loadFailure?.cause, t("secrets.deleted.loadFailed"))}</ErrorState>
      ) : null}
      {awaiting ? (
        <p role="status" className="rounded-control border border-border p-3">
          {t("secrets.deleted.awaitingApproval", { name: awaiting.name, request: awaiting.request })}{" "}
          <Link to="/approvals" className="text-primary underline">
            {t("secrets.deleted.openApprovals")}
          </Link>
        </p>
      ) : null}
      {message ? <p role="status">{message}</p> : null}
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.deleted.empty")}</p>
      ) : (
        <ul className="grid gap-2" aria-label={t("secrets.deleted.listLabel")}>
          {items.map((item) => (
            <li key={item.name} className="flex flex-wrap items-center gap-2 rounded-control border border-border p-2">
              <span className="font-mono text-xs">{item.name}</span>
              <span className="text-muted-foreground">
                {t("secrets.deleted.kept", {
                  version: String(item.version),
                  versions: String(item.versions),
                  deleted: formatDateTime(item.deleted_at),
                  purge: formatDateTime(item.purge_after),
                })}
              </span>
              <Button type="button" variant="outline" disabled={busy !== null} onClick={() => void restore(item.name)}>
                {t("secrets.deleted.restore")}
              </Button>
              {confirmPurge === item.name ? (
                <>
                  <Button type="button" variant="destructive" disabled={busy !== null} onClick={() => void purge(item.name)}>
                    {t("secrets.deleted.confirmPurge", { name: item.name })}
                  </Button>
                  <Button type="button" variant="ghost" onClick={() => setConfirmPurge(null)}>
                    {t("secrets.deleted.cancel")}
                  </Button>
                </>
              ) : (
                <Button type="button" variant="ghost" disabled={busy !== null} onClick={() => setConfirmPurge(item.name)}>
                  {t("secrets.deleted.purge")}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
