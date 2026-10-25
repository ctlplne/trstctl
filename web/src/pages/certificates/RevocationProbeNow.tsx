// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";

// An operator who fixed a relay's trust bundle or a distribution point used to
// wait up to an hour for the next scheduled probe. This asks the network relay
// to probe every CRL and OCSP endpoint now; the health summary refreshes as the
// relay's signed observations arrive.
export function RevocationProbeNow() {
  const { t } = useTranslation();
  const canProbe = useCan("certs:write");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  if (!canProbe || typeof api.probeRevocationHealth !== "function") return null;

  const probe = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await api.probeRevocationHealth(newIdempotencyKey());
      setMessage(t(result.queued ? "certificates.revocation.probeQueued" : "certificates.revocation.probeAlreadyQueued"));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2 sm:col-span-2">
      <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => void probe()}>
        {t("certificates.revocation.probeNow")}
      </Button>
      {message ? (
        <p role="status" className="text-caption text-muted-foreground">
          {message}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </div>
  );
}
