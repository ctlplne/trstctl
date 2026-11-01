import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DatabaseDecoy, type DatabaseDecoyCreateResponse, type DynamicSecretConfiguredProvider } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RevealPanel } from "./SecretsPageParts";

// Q6: a decoy PostgreSQL login. A tenant PostgreSQL provider that lists the
// role "decoy" mints a login that reaches only its own empty database; any use
// of it raises one critical alert. Its connection string is shown once.
export function DecoyDatabaseWorkflow() {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const [providers, setProviders] = useState<DynamicSecretConfiguredProvider[]>([]);
  const [provider, setProvider] = useState("");
  const [name, setName] = useState("");
  const [placement, setPlacement] = useState("");
  const [days, setDays] = useState("30");
  const [items, setItems] = useState<DatabaseDecoy[]>([]);
  const [revealed, setRevealed] = useState<DatabaseDecoyCreateResponse | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [readError, setReadError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [catalog, decoys] = await Promise.all([api.dynamicSecretProviders(), api.listDatabaseDecoys()]);
      setProviders(catalog.configured_providers.filter((item) => item.type === "postgresql"));
      setItems(decoys.items);
      setReadError(null);
    } catch (cause) {
      setReadError(apiProblemMessage(cause, t("secrets.decoyLogins.readFailed")));
    }
  }, [t]);

  useEffect(() => {
    if (canWrite) void refresh();
  }, [canWrite, refresh]);

  if (!canWrite) return null;

  async function plant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    // The same key on a retry replays the same login instead of minting another.
    const key = pendingKey ?? crypto.randomUUID();
    setPendingKey(key);
    try {
      const result = await api.createDatabaseDecoy(
        { provider, name: name.trim(), placement: placement.trim(), ttl_seconds: Math.round(Number(days) * 86400) },
        key,
      );
      setRevealed(result);
      setPendingKey(null);
      setName("");
      setPlacement("");
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.decoyLogins.plantFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function retire(id: string) {
    setBusy(true);
    setError(null);
    try {
      await api.retireDatabaseDecoy(id);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.decoyLogins.retireFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="decoy-login-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="decoy-login-heading" className="text-title font-semibold">
          {t("secrets.decoyLogins.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.decoyLogins.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.decoyLogins.error")}>{error}</ErrorState> : null}
      {readError ? <ErrorState title={t("secrets.decoyLogins.error")}>{readError}</ErrorState> : null}
      <form onSubmit={(event) => void plant(event)} className="grid max-w-xl gap-3">
        <Field label={t("secrets.decoyLogins.provider")} description={t("secrets.decoyLogins.providerHelp")}>
          {(control) => (
            <Select
              {...control}
              value={provider}
              onChange={(event) => {
                setProvider(event.target.value);
                setPendingKey(null);
              }}
            >
              <option value="">{t("secrets.decoyLogins.chooseProvider")}</option>
              {providers.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("secrets.decoys.name")}>
          {(control) => <Input {...control} value={name} maxLength={128} required onChange={(event) => setName(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoys.placement")} description={t("secrets.decoys.placementHelp")}>
          {(control) => <Input {...control} value={placement} maxLength={256} required onChange={(event) => setPlacement(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoyLogins.days")}>
          {(control) => <Input {...control} type="number" min={1} value={days} required onChange={(event) => setDays(event.target.value)} />}
        </Field>
        <Button type="submit" disabled={busy || !provider || !name.trim() || !placement.trim() || !(Number(days) > 0)}>
          {t("secrets.decoyLogins.plant")}
        </Button>
      </form>
      {revealed ? (
        <RevealPanel title={t("secrets.decoyLogins.revealTitle")} value={revealed.dsn} onDismiss={() => setRevealed(null)}>
          {t("secrets.decoyLogins.revealHelp")}
        </RevealPanel>
      ) : null}
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.decoyLogins.empty")}</p>
      ) : (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong>{item.db_role}</strong>
                <span className={item.state === "triggered" ? "font-semibold text-destructive" : "text-muted-foreground"}>{item.state}</span>
              </div>
              <p>
                {item.name} · {item.placement} · {item.db_provider_id}
              </p>
              {item.triggered_at ? <p>{t("secrets.decoyLogins.used", { at: formatDateTime(item.triggered_at) })}</p> : null}
              {item.state !== "revoked" ? (
                <Button type="button" variant="outline" className="mt-2" onClick={() => void retire(item.id)} disabled={busy}>
                  {t("secrets.decoys.retire")}
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
