import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type DecoySecret } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// Q6: a decoy secret is an ordinary stored secret registered as bait. The
// console writes a realistic generated value through the normal create path,
// then registers it; every served read of that value alerts, naming the reader.
// Only people who can plant decoys see this registry.

type ValueKind = "password" | "api_key" | "connection_string";

const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

function randomText(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

export function decoyValue(kind: ValueKind): string {
  switch (kind) {
    case "api_key":
      return `key_${randomText(40)}`;
    case "connection_string":
      return `postgres://svc_${randomText(6).toLowerCase()}:${randomText(24)}@db-${randomText(4).toLowerCase()}.internal:5432/app`;
    default:
      return randomText(24);
  }
}

export function DecoySecretWorkflow() {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const [secretName, setSecretName] = useState("");
  const [name, setName] = useState("");
  const [placement, setPlacement] = useState("");
  const [kind, setKind] = useState<ValueKind>("password");
  const [created, setCreated] = useState<string | null>(null);
  const [items, setItems] = useState<DecoySecret[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The list keeps its own error: a refresh that succeeds must not erase the
  // message of a plant or retire that failed.
  const [readError, setReadError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setItems((await api.listDecoySecrets()).items);
      setReadError(null);
    } catch (cause) {
      setReadError(apiProblemMessage(cause, t("secrets.decoys.readFailed")));
    }
  }, [t]);

  useEffect(() => {
    if (canWrite) void refresh();
  }, [canWrite, refresh]);

  if (!canWrite) return null;

  async function plant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const path = secretName.trim();
    setBusy(true);
    setError(null);
    try {
      // A retry after a failed registration must not plant a second secret.
      if (created !== path) {
        await api.createSecret({ name: path, value: decoyValue(kind) });
        setCreated(path);
      }
      await api.registerDecoySecret({ secret_name: path, name: name.trim(), placement: placement.trim() });
      setCreated(null);
      setSecretName("");
      setName("");
      setPlacement("");
      await refresh();
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 409 && created !== path) {
        setError(t("secrets.decoys.exists"));
      } else {
        setError(apiProblemMessage(cause, t("secrets.decoys.plantFailed")));
      }
    } finally {
      setBusy(false);
    }
  }

  async function retire(id: string) {
    setBusy(true);
    setError(null);
    try {
      await api.retireDecoySecret(id);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.decoys.retireFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="decoy-secret-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="decoy-secret-heading" className="text-title font-semibold">
          {t("secrets.decoys.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.decoys.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.decoys.error")}>{error}</ErrorState> : null}
      {readError ? <ErrorState title={t("secrets.decoys.error")}>{readError}</ErrorState> : null}
      <form onSubmit={(event) => void plant(event)} className="grid max-w-xl gap-3">
        <Field label={t("secrets.decoys.secretName")} description={t("secrets.decoys.secretNameHelp")}>
          {(control) => <Input {...control} value={secretName} maxLength={1024} required onChange={(event) => setSecretName(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoys.valueKind")}>
          {(control) => (
            <Select {...control} value={kind} onChange={(event) => setKind(event.target.value as ValueKind)}>
              <option value="password">{t("secrets.decoys.kind.password")}</option>
              <option value="api_key">{t("secrets.decoys.kind.apiKey")}</option>
              <option value="connection_string">{t("secrets.decoys.kind.connectionString")}</option>
            </Select>
          )}
        </Field>
        <Field label={t("secrets.decoys.name")}>
          {(control) => <Input {...control} value={name} maxLength={128} required onChange={(event) => setName(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoys.placement")} description={t("secrets.decoys.placementHelp")}>
          {(control) => <Input {...control} value={placement} maxLength={256} required onChange={(event) => setPlacement(event.target.value)} />}
        </Field>
        <Button type="submit" disabled={busy || !secretName.trim() || !name.trim() || !placement.trim()}>
          {t("secrets.decoys.plant")}
        </Button>
      </form>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.decoys.empty")}</p>
      ) : (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong>{item.secret_name}</strong>
                <span className={item.state === "triggered" ? "font-semibold text-destructive" : "text-muted-foreground"}>{item.state}</span>
              </div>
              <p>
                {item.name} · {item.placement}
              </p>
              {item.triggered_at ? <p>{t("secrets.decoys.firstRead", { reader: item.trigger_subject ?? "", at: formatDateTime(item.triggered_at) })}</p> : null}
              {/* Q6-L1: the decoy keeps its readers, so a reader who reads again stays one alert. */}
              {item.readers && item.last_read_at ? (
                <p>
                  {t("secrets.decoys.readers", {
                    reads: item.reads ?? item.readers,
                    readers: item.readers,
                    at: formatDateTime(item.last_read_at),
                  })}
                </p>
              ) : null}
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
