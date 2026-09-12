import { useEffect, useId, useRef, useState } from "react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

/** A read proves only the secret the operator explicitly chose. Keep this
 * separate from the store/developer workspace's automatically selected row. */
export function GrantSecretVerification({ token, secretNames, onDismiss }: { token: string; secretNames: readonly string[]; onDismiss: () => void }) {
  const { t } = useTranslation();
  const listId = useId();
  const requestRef = useRef(0);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ name: string; version?: number } | null>(null);

  useEffect(() => {
    setName("");
    setBusy(false);
    setError(null);
    setResult(null);
    return () => {
      requestRef.current += 1;
    };
  }, [token]);

  async function verify() {
    const selectedName = name.trim();
    if (!selectedName) {
      setError(t("secrets.grant.verifyMissingSecret"));
      return;
    }
    const request = ++requestRef.current;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      // No human-session cookie, query cache, or retained secret value: only
      // exact-name metadata is kept after the workload bearer authorizes it.
      const value = await api.getSecretWithToken(selectedName, token);
      if (request !== requestRef.current) return;
      if (value.name !== selectedName) throw new Error(t("secrets.grant.verifyMismatch"));
      setResult({ name: value.name, version: value.version });
    } catch (err) {
      if (request === requestRef.current) setError(apiProblemMessage(err, t("secrets.grant.verifyFailedTitle")));
    } finally {
      if (request === requestRef.current) setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <div role="status" className="rounded-panel border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="font-medium">{t("secrets.grant.revealTitle")}</p>
          <Button type="button" size="sm" variant="ghost" onClick={onDismiss}>
            {t("secrets.grant.dismiss")}
          </Button>
        </div>
        <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{token}</code>
        <p className="mt-1 text-xs text-muted-foreground">{t("secrets.grant.revealNote")}</p>
      </div>
      <Field label={t("secrets.grant.verifyName")} description={t("secrets.grant.verifyScope")} required>
        {(control) => (
          <Input
            {...control}
            list={listId}
            value={name}
            disabled={busy}
            onChange={(event) => {
              setName(event.target.value);
              setError(null);
              setResult(null);
            }}
          />
        )}
      </Field>
      <datalist id={listId}>
        {secretNames.map((secretName) => (
          <option key={secretName} value={secretName} />
        ))}
      </datalist>
      <Button type="button" size="sm" variant="outline" loading={busy} disabled={busy || !name.trim()} onClick={() => void verify()}>
        {t("secrets.grant.verify")}
      </Button>
      {error && <ErrorState title={t("secrets.grant.verifyFailedTitle")}>{error}</ErrorState>}
      {result && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
          {t("secrets.grant.verifyPassed", { name: result.name, version: String(result.version ?? "latest") })}
        </p>
      )}
    </div>
  );
}
