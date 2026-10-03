import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type HoneyToken, type HoneyTokenCreateResponse } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RevealPanel } from "./SecretsPageParts";

// A decoy has no scopes and cannot authenticate. Its value stays in memory only
// until the operator dismisses the reveal panel or leaves this workflow.
export function HoneyTokenWorkflow() {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const [name, setName] = useState("");
  const [placement, setPlacement] = useState("");
  const [items, setItems] = useState<HoneyToken[]>([]);
  const [nextCursor, setNextCursor] = useState("");
  const [revealed, setRevealed] = useState<HoneyTokenCreateResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const result = await api.listHoneyTokens();
      setItems(result.items);
      setNextCursor(result.next_cursor ?? "");
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.honeytokens.readFailed")));
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function loadMore() {
    if (!nextCursor) return;
    setBusy(true);
    try {
      const result = await api.listHoneyTokens(nextCursor);
      setItems((current) => [...current, ...result.items]);
      setNextCursor(result.next_cursor ?? "");
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.honeytokens.readFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function plant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const key = pendingKey ?? crypto.randomUUID();
    setPendingKey(key);
    try {
      const result = await api.createHoneyToken({ name: name.trim(), placement: placement.trim() }, key);
      setRevealed(result);
      setPendingKey(null);
      setName("");
      setPlacement("");
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.honeytokens.plantFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    setBusy(true);
    setError(null);
    try {
      await api.revokeHoneyToken(id);
      if (revealed?.id === id) setRevealed(null);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.honeytokens.revokeFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="honeytoken-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="honeytoken-heading" className="text-title font-semibold">
          {t("secrets.honeytokens.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.honeytokens.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.honeytokens.error")}>{error}</ErrorState> : null}
      {canWrite ? (
        <form onSubmit={(event) => void plant(event)} className="grid max-w-xl gap-3">
          <label className="grid gap-1 text-sm">
            <span>{t("secrets.honeytokens.name")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              value={name}
              maxLength={128}
              required
              onChange={(event) => {
                setName(event.target.value);
                setPendingKey(null);
              }}
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span>{t("secrets.honeytokens.placement")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              value={placement}
              maxLength={256}
              required
              onChange={(event) => {
                setPlacement(event.target.value);
                setPendingKey(null);
              }}
            />
          </label>
          <p className="text-xs text-muted-foreground">{t("secrets.honeytokens.placementHelp")}</p>
          <Button type="submit" disabled={busy || !name.trim() || !placement.trim()}>
            {t("secrets.honeytokens.plant")}
          </Button>
        </form>
      ) : (
        <p className="text-sm text-muted-foreground">{t("secrets.honeytokens.permissionBlocked")}</p>
      )}
      {revealed ? (
        <RevealPanel title={t("secrets.honeytokens.revealTitle")} value={revealed.token} onDismiss={() => setRevealed(null)}>
          {t("secrets.honeytokens.revealHelp")}
        </RevealPanel>
      ) : null}
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-semibold">{t("secrets.honeytokens.planted")}</h3>
        <Button type="button" variant="outline" onClick={() => void refresh()} disabled={busy}>
          {t("secrets.honeytokens.refresh")}
        </Button>
      </div>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.honeytokens.empty")}</p>
      ) : (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong>{item.name}</strong>
                <span className={item.state === "triggered" ? "font-semibold text-destructive" : "text-muted-foreground"}>{item.state}</span>
              </div>
              <p>
                {t("secrets.honeytokens.placement")}: {item.placement}
              </p>
              <p>
                {t("secrets.honeytokens.created")}: {formatDateTime(item.created_at)}
              </p>
              {item.triggered_at ? (
                <p>
                  {t("secrets.honeytokens.triggered")}: {formatDateTime(item.triggered_at)} ({item.trigger_method} {item.trigger_path})
                </p>
              ) : null}
              {item.state !== "revoked" && canWrite ? (
                <Button type="button" variant="outline" className="mt-2" onClick={() => void revoke(item.id)} disabled={busy}>
                  {t("secrets.honeytokens.revoke")}
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
      {nextCursor ? (
        <Button type="button" variant="outline" onClick={() => void loadMore()} disabled={busy}>
          {t("secrets.honeytokens.loadMore")}
        </Button>
      ) : null}
    </section>
  );
}
