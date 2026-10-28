import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DeploymentTarget } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery } from "@/lib/query";

// A214: where discovery saw a certificate trstctl delivered to this target,
// offered as its verification address. Nothing changes until the operator
// confirms one; any other address is set by editing the target.
export function VerificationAddressSuggestions({ target }: { target: DeploymentTarget }) {
  const { t } = useTranslation();
  const suggestions = useApiQuery(["verification-suggestions", target.id], () => api.verificationSuggestions(target.id), { retry: false });
  const [choice, setChoice] = useState<string | null>(null);
  const [serverName, setServerName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState<string | null>(null);
  const attempt = useRef<{ body: string; key: string } | null>(null);
  const data = suggestions.data;

  async function confirm() {
    if (!data || !choice || busy) return;
    const request = { address: choice, server_name: serverName.trim() || undefined, target_revision: data.target_revision };
    const body = JSON.stringify(request);
    if (attempt.current?.body !== body) attempt.current = { body, key: newIdempotencyKey() };
    setBusy(true);
    setError(null);
    try {
      await api.confirmVerificationAddress(target.id, request, attempt.current.key);
      setConfirmed(choice);
      setChoice(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
      suggestions.refetch();
    }
  }

  if (!data) {
    return suggestions.error ? (
      <p role="alert" className="text-sm text-status-warning md:col-span-3">
        {suggestions.error}
      </p>
    ) : null;
  }
  return (
    <section aria-labelledby="verification-suggestions-heading" className="grid gap-2 rounded-control border border-border bg-muted/20 p-3 md:col-span-3">
      <div>
        <h3 id="verification-suggestions-heading" className="font-semibold">
          {t("connectors.verificationSuggestions.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">
          {data.verify_address
            ? t("connectors.verificationSuggestions.current", { address: data.verify_address })
            : t("connectors.verificationSuggestions.none")}
        </p>
      </div>
      {data.suggestions.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("connectors.verificationSuggestions.empty")}</p>
      ) : (
        <ul className="grid gap-2">
          {data.suggestions.map((suggestion) => (
            <li key={suggestion.address} className="grid gap-1 rounded-control border border-border bg-card p-2 text-sm">
              <p className="font-mono">{suggestion.address}</p>
              <ul className="text-xs text-muted-foreground">
                {suggestion.evidence.map((evidence) => (
                  <li key={evidence.finding_id}>
                    {t("connectors.verificationSuggestions.evidence", {
                      fingerprint: evidence.fingerprint.slice(0, 16),
                      seen: formatDateTime(evidence.discovered_at),
                      run: evidence.run_id,
                    })}
                  </li>
                ))}
              </ul>
              {suggestion.address !== data.verify_address && (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="justify-self-start"
                  onClick={() => {
                    setChoice(suggestion.address);
                    setServerName("");
                    setError(null);
                  }}
                >
                  {t("connectors.verificationSuggestions.use")}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {choice && (
        <div role="group" aria-labelledby="verification-confirm-heading" className="grid gap-2 rounded-control border border-border bg-card p-3 text-sm">
          <p id="verification-confirm-heading" className="font-semibold">
            {t("connectors.verificationSuggestions.confirmTitle", { address: choice })}
          </p>
          <p>{t("connectors.verificationSuggestions.confirmEffect")}</p>
          <label className="grid gap-1" htmlFor="verification-server-name">
            {t("connectors.verificationSuggestions.serverName")}
            <input
              id="verification-server-name"
              value={serverName}
              onChange={(event) => setServerName(event.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
          </label>
          <div className="flex gap-2">
            <Button type="button" loading={busy} disabled={busy} onClick={() => void confirm()}>
              {t("connectors.verificationSuggestions.confirm")}
            </Button>
            <Button type="button" variant="ghost" disabled={busy} onClick={() => setChoice(null)}>
              {t("connectors.verificationSuggestions.cancel")}
            </Button>
          </div>
        </div>
      )}
      {confirmed && (
        <p role="status" className="text-sm text-status-success">
          {t("connectors.verificationSuggestions.confirmed", { address: confirmed })}
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-status-warning">
          {error}
        </p>
      )}
      <p className="text-xs text-muted-foreground">{t("connectors.verificationSuggestions.note")}</p>
    </section>
  );
}
