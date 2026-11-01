import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { useCan } from "@/components/rbac";
import { useTranslation } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// Q4: revoke one AI agent's identity in one call. Relying parties refuse its
// next use through OCSP, the CRL and the agent key set. A retry reuses the same
// Idempotency-Key, so it replays the result instead of revoking twice.
const reasons = ["keyCompromise", "cessationOfOperation", "superseded", "affiliationChanged", "unspecified"] as const;

export function BrokerRevokeAction({ certificateId, onRevoked }: { certificateId: string; onRevoked: () => void }) {
  const { t } = useTranslation();
  const canRevoke = useCan("certs:issue");
  const [reason, setReason] = useState<(typeof reasons)[number]>("keyCompromise");
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  if (!canRevoke) return null;

  async function revoke() {
    setBusy(true);
    setMessage(null);
    const key = pendingKey ?? crypto.randomUUID();
    setPendingKey(key);
    try {
      await api.revokeBrokerAgentIdentity(certificateId, { reason }, key);
      setPendingKey(null);
      setMessage(t("broker.revoke.done"));
      onRevoked();
    } catch (cause) {
      setMessage(apiProblemMessage(cause, t("broker.revoke.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="broker-revoke-heading" className="grid gap-2 rounded-panel border border-border p-3">
      <h3 id="broker-revoke-heading" className="text-sm font-semibold">
        {t("broker.revoke.heading")}
      </h3>
      <p className="text-caption text-muted-foreground">{t("broker.revoke.help")}</p>
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t("broker.revoke.reason")}>
          {(control) => (
            <Select
              {...control}
              value={reason}
              onChange={(event) => {
                setReason(event.target.value as (typeof reasons)[number]);
                setPendingKey(null);
              }}
            >
              {reasons.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button type="button" variant="destructive" disabled={busy} onClick={() => void revoke()}>
          {t("broker.revoke.action")}
        </Button>
      </div>
      {message ? <p role="status">{message}</p> : null}
    </section>
  );
}
