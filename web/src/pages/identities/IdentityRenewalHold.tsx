import { useState } from "react";

import { api, type Identity } from "@/lib/api";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { invalidateAppQueryKeys } from "@/lib/query";
import { apiProblemMessage } from "@/lib/apiProblem";
import { Button } from "@/components/ui/button";

/** B4-8: an operator rollback holds automatic renewal of the identity on that
 * target until an operator resumes it. The hold is shown per target with its
 * time and reason; resuming appends the audited identity.renewal_resumed event. */
export function IdentityRenewalHold({ identity }: { identity: Identity }) {
  const { t, locale, timeZone } = useTranslation();
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pauses = identity.renewal_paused ?? [];
  if (pauses.length === 0) return null;

  const resume = async (targetID: string) => {
    setBusy(targetID);
    setError(null);
    try {
      await api.resumeIdentityRenewal(identity.id, { target_id: targetID });
      setNotice(t("identities.renewal.resumed"));
      invalidateAppQueryKeys([["identity", identity.id], ["identities"]]);
    } catch (err) {
      setError(apiProblemMessage(err, t("identities.renewal.resume")));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section aria-labelledby="identity-renewal-hold-heading" className="mt-4 rounded-md border border-status-warning/60 p-3">
      <h3 id="identity-renewal-hold-heading" className="font-semibold">
        {t("identities.renewal.pausedHeading")}
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">{t("identities.renewal.pausedBody")}</p>
      <ul className="mt-2 grid gap-2">
        {pauses.map((pause) => (
          <li key={pause.target_id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span>
              <code className="break-all text-xs">{pause.target_id}</code>
              <span className="ms-2 text-muted-foreground">
                {t("identities.renewal.pausedSince", { at: formatDateTimePolicy(pause.paused_at, { locale, timeZone }), reason: pause.reason })}
              </span>
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void resume(pause.target_id)}
              disabled={busy !== null}
              loading={busy === pause.target_id}
            >
              {t("identities.renewal.resume")}
            </Button>
          </li>
        ))}
      </ul>
      {notice && (
        <p role="status" className="mt-2 text-sm text-status-success">
          {notice}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-2 text-sm text-destructive">
          {error}
        </p>
      )}
    </section>
  );
}
