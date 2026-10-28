import { useState } from "react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { EndpointRecoveryReadiness } from "@/lib/api-types.gen";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useTranslation } from "@/i18n/I18nProvider";

// A210: after containment stopped a listener, a replacement waits until the
// target's enrolled host says, in a signed job receipt, that its profile pins a
// recovery action the deploy runs and that the listener is not serving the
// contained certificate.
export function EndpointRecoveryReadinessPanel({
  readiness,
  targetId,
  identityId,
}: {
  readiness: EndpointRecoveryReadiness;
  targetId: string;
  identityId: string;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [requested, setRequested] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = readiness.state === "ready";
  const stateText: Record<string, string> = {
    ready: t("connectors.hostRecovery.ready"),
    not_ready: t("connectors.hostRecovery.notReady"),
    unchecked: t("connectors.hostRecovery.unchecked"),
    queued: t("connectors.hostRecovery.queued"),
    stale: t("connectors.hostRecovery.stale"),
    failed: t("connectors.hostRecovery.failed"),
  };
  const check = readiness.check;

  async function requestCheck() {
    setBusy(true);
    setError(null);
    try {
      await api.requestEndpointRecoveryCheck(targetId, { identity_id: identityId }, newIdempotencyKey());
      setRequested(true);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-label={t("connectors.hostRecovery.heading")}
      className={
        ready
          ? "grid gap-2 rounded-control border border-status-success/30 bg-status-success/10 p-4 text-sm"
          : "grid gap-2 rounded-control border border-status-warning/30 bg-status-warning/10 p-4 text-sm"
      }
    >
      <h3 className="font-semibold">{t("connectors.hostRecovery.heading")}</h3>
      <p>{stateText[readiness.state] ?? readiness.state}</p>
      {readiness.reasons.length > 0 ? (
        <ul className="grid list-disc gap-1 ps-5">
          {readiness.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      {check?.recovery_action ? (
        <dl className="grid gap-2 sm:grid-cols-2">
          <div className="min-w-0">
            <dt className="font-medium text-muted-foreground">{t("connectors.hostRecovery.action")}</dt>
            <dd className="font-mono text-xs">{check.recovery_action}</dd>
          </div>
          <div className="min-w-0">
            <dt className="font-medium text-muted-foreground">{t("connectors.hostRecovery.listener")}</dt>
            <dd className="font-mono text-xs">{check.listener ?? ""}</dd>
          </div>
          <div className="min-w-0">
            <dt className="font-medium text-muted-foreground">{t("connectors.hostRecovery.executableDigest")}</dt>
            <dd className="font-mono text-xs wrap-break-word">{check.executable_sha256 ?? ""}</dd>
          </div>
          <div className="min-w-0">
            <dt className="font-medium text-muted-foreground">{t("connectors.hostRecovery.commandDigest")}</dt>
            <dd className="font-mono text-xs wrap-break-word">{check.argv_sha256 ?? ""}</dd>
          </div>
        </dl>
      ) : null}
      {!ready ? (
        <div className="flex flex-wrap items-center gap-3">
          <Button type="button" variant="outline" onClick={() => void requestCheck()} disabled={busy}>
            {busy ? t("connectors.hostRecovery.checking") : t("connectors.hostRecovery.check")}
          </Button>
          {requested ? <p role="status">{t("connectors.hostRecovery.requested")}</p> : null}
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-status-danger">
          {t("connectors.hostRecovery.checkFailed")}: {error}
        </p>
      ) : null}
    </section>
  );
}
