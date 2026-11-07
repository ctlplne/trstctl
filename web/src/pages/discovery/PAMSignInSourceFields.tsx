import { useId } from "react";
import { api } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";

// A274: a pam_signin source names the dynamic-secret provider whose static
// accounts it watches for sign-ins outside trstctl, read through the
// provider's administrator connection.
const SIGN_IN_PROVIDER_TYPES = new Set(["unix", "postgresql", "mysql", "mssql"]);

export function PAMSignInSourceFields({
  providerID,
  lookback,
  onProvider,
  onLookback,
}: {
  providerID: string;
  lookback: string;
  onProvider: (value: string) => void;
  onLookback: (value: string) => void;
}) {
  const { t } = useTranslation();
  const lookbackID = useId();
  const hintID = useId();
  const providers = useApiQuery(["dynamic-secret-providers"], api.dynamicSecretProviders, { retry: false });
  const choices = (providers.data?.configured_providers ?? []).filter((provider) => SIGN_IN_PROVIDER_TYPES.has(provider.type));
  return (
    <div className="grid gap-3">
      <p className="text-sm text-muted-foreground">{t("discovery.pamSignIn.help")}</p>
      <label className="grid gap-1 text-sm font-medium">
        {t("discovery.pamSignIn.provider")}
        <select className="ui-input" value={providerID} onChange={(event) => onProvider(event.target.value)} required>
          <option value="" disabled>
            {t("discovery.pamSignIn.chooseProvider")}
          </option>
          {choices.map((provider) => (
            <option key={provider.id} value={provider.id}>
              {t("discovery.pamSignIn.providerOption", { label: provider.label, type: provider.type })}
            </option>
          ))}
        </select>
      </label>
      <div className="grid gap-1 text-sm font-medium">
        <label htmlFor={lookbackID}>{t("discovery.pamSignIn.lookback")}</label>
        <input
          id={lookbackID}
          className="ui-input"
          type="number"
          min={300}
          max={604800}
          value={lookback}
          aria-describedby={hintID}
          onChange={(event) => onLookback(event.target.value)}
        />
        <span id={hintID} className="text-xs font-normal text-muted-foreground">
          {t("discovery.pamSignIn.lookbackHint")}
        </span>
      </div>
    </div>
  );
}
