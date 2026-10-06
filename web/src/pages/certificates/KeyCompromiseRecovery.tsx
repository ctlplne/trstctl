import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type KeyCompromiseResult } from "@/lib/api";
import { apiProblemContext } from "@/lib/apiProblem";
import { KeyCompromiseEffects } from "./KeyCompromiseEffects";

/** Reopen an incident after refresh or cold restart without issuing another
 * destructive command. Both identifiers are operator-held, not browser-stored. */
export function KeyCompromiseRecovery() {
  const { t } = useTranslation();
  const [identityID, setIdentityID] = useState("");
  const [requestKey, setRequestKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recovered, setRecovered] = useState<{
    identityID: string;
    requestKey: string;
    result: KeyCompromiseResult;
  } | null>(null);

  async function load() {
    const id = identityID.trim();
    const key = requestKey.trim();
    if (!id || !key) return;
    setLoading(true);
    setError(null);
    setRecovered(null);
    try {
      const result = await api.readKeyCompromise(id, key);
      if (
        result.identity.id !== id ||
        result.revocation.destination !== "revocation.publish" ||
        result.containment.identity_id !== id ||
        result.containment.destination !== "endpoint.contain"
      ) {
        throw new Error(t("certificates.revocation.compromiseReadMismatch"));
      }
      setRecovered({ identityID: id, requestKey: key, result });
    } catch (cause) {
      setError(apiProblemContext(cause, t("certificates.revocation.compromiseReadFailed")));
    } finally {
      setLoading(false);
    }
  }

  return (
    <details className="rounded-control border border-border p-3 text-sm">
      <summary className="cursor-pointer font-medium">{t("certificates.revocation.compromiseResume")}</summary>
      <div className="mt-3 grid max-w-2xl gap-3">
        <p className="text-muted-foreground">{t("certificates.revocation.compromiseResumeHelp")}</p>
        <Field label={t("certificates.revocation.compromiseIdentityID")} controlId="compromise-recovery-identity">
          {(control) => (
            <Input
              {...control}
              value={identityID}
              onChange={(event) => {
                setIdentityID(event.target.value);
                setRecovered(null);
              }}
            />
          )}
        </Field>
        <Field label={t("certificates.revocation.compromiseRequestKey")} controlId="compromise-recovery-key">
          {(control) => (
            <Input
              {...control}
              value={requestKey}
              onChange={(event) => {
                setRequestKey(event.target.value);
                setRecovered(null);
              }}
            />
          )}
        </Field>
        <Button
          type="button"
          variant="outline"
          className="justify-self-start"
          loading={loading}
          disabled={!identityID.trim() || !requestKey.trim()}
          onClick={() => void load()}
        >
          {t("certificates.revocation.compromiseResumeAction")}
        </Button>
        {error ? (
          <p role="alert" className="text-status-warning">
            {error}
          </p>
        ) : null}
        {recovered ? <KeyCompromiseEffects {...recovered} initial={recovered.result} /> : null}
      </div>
    </details>
  );
}
