// SPDX-License-Identifier: BUSL-1.1

import { api, type RevocationRelayWait } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";

type Translate = (key: MessageKey, values?: Record<string, number | string>) => string;

// A revocation through an AD CS issuer waits for that issuer's domain-joined
// relay (A162-L5): the certificate stays active until the relay runs certutil
// and reports. The reason it is still waiting — a relay that has never
// connected, one that is offline, or one running the revocation now — is shown here
// instead of leaving the operator to find a deferred job in the queue.

/** The relay's serial form: lower-case hex without separators. */
export function relayWaitSerial(serial: string): string {
  return serial.replace(/:/g, "").toLowerCase();
}

export function revocationRelayWaitReason(wait: RevocationRelayWait, t: Translate): string {
  const relay = wait.relay || wait.relay_agent_id;
  if (wait.state === "relay_working") return t("certificates.revocation.relayWorking", { relay, ca: wait.ca_config });
  switch (wait.relay_presence) {
    case "never_seen":
      return t("certificates.revocation.relayNeverSeen", { relay });
    case "online":
      return t("certificates.revocation.relayOnlineWaiting", { relay });
    case "offboarded":
      return t("certificates.revocation.relayOffboarded", { relay });
    default:
      return wait.relay_last_seen_at
        ? t("certificates.revocation.relayOffline", { relay, seen: wait.relay_last_seen_at })
        : t("certificates.revocation.relayNotReported", { relay });
  }
}

/** Every revocation waiting on a relay, or only the one for `serial`. */
export function RevocationRelayWaits({ serial }: { serial?: string }) {
  const { t } = useTranslation();
  const available = typeof api.revocationRelayWaits === "function";
  const waits = useApiQuery(["revocation", "relay-waits"], () => api.revocationRelayWaits(), {
    enabled: available,
    live: { intervalMs: 15_000 },
    retry: false,
  });
  const wanted = serial ? relayWaitSerial(serial) : "";
  const items = (waits.data?.items ?? []).filter((item) => !wanted || item.serial === wanted);
  if (!available || items.length === 0) return null;
  return (
    <section aria-label={t("certificates.revocation.relayWaitsTitle")} className="rounded-control border border-status-warning/40 bg-muted/30 p-3 text-sm">
      {serial ? null : <h3 className="font-semibold">{t("certificates.revocation.relayWaitsTitle")}</h3>}
      <ul className="grid gap-2">
        {items.map((item) => (
          <li key={item.revocation_id}>
            <p role="status" className="font-medium text-status-warning">
              {revocationRelayWaitReason(item, t)}
            </p>
            <p className="break-all text-xs text-muted-foreground">
              {t("certificates.revocation.relayWaitFacts", { serial: item.serial, ca: item.ca_config, since: item.queued_at, attempt: item.attempt })}
            </p>
            {item.last_error ? <p className="break-all text-xs">{t("certificates.revocation.relayWaitLastError", { error: item.last_error })}</p> : null}
          </li>
        ))}
      </ul>
      {serial ? null : <p className="mt-2 text-xs text-muted-foreground">{t("certificates.revocation.relayWaitsHelp")}</p>}
    </section>
  );
}
