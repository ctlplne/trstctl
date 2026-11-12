import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { api, type ExternalCA, type RogueCertificateFinding } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";

// A163: revoke a rogue certificate at the CA that issued it. A Certificate
// Transparency finding is revoked by serial at the external CA the operator
// names (only kinds that revoke by serial are offered), or at an ACME CA from
// the certificate's bytes once trstctl's account is authorized for its names
// (N10); an inventory finding goes through the exact revocation, which reaches
// its recorded issuer.

/**
 * Whether the server says an authority can revoke a certificate trstctl found:
 * by its serial alone, or from its bytes (an ACME authority, N10). The server
 * serves this per authority (A163-L3), so the console keeps no list of kinds.
 */
export function revokesFoundCertificates(ca: ExternalCA): boolean {
  return ca.revokes_by_serial || ca.revokes_by_certificate;
}

/** RFC 5280 reasons an operator chooses from when revoking a rogue certificate. */
export const ROGUE_REVOCATION_REASONS = [
  "keyCompromise",
  "superseded",
  "cessationOfOperation",
  "affiliationChanged",
  "privilegeWithdrawn",
  "unspecified",
] as const;

export type RogueRevocationReason = (typeof ROGUE_REVOCATION_REASONS)[number];

/** A163-L1: an AD CS issuer revokes through its relay's certutil, which takes
 * the reasons unspecified through cessationOfOperation. */
const ADCS_REVOCATION_REASONS: ReadonlySet<string> = new Set([
  "unspecified",
  "keyCompromise",
  "cACompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
]);

function stateKey(state: string): MessageKey {
  switch (state) {
    case "revoked":
      return "certificates.rogue.issuerRevoked";
    case "failed":
      return "certificates.rogue.issuerFailed";
    default:
      return "certificates.rogue.issuerQueued";
  }
}

export function RogueIssuerRevocationCell({
  finding,
  reason,
  authorities,
  onDone,
}: {
  finding: RogueCertificateFinding;
  reason: RogueRevocationReason | "";
  authorities: ExternalCA[];
  onDone: (message: string) => void;
}) {
  const { t } = useTranslation();
  const [authority, setAuthority] = useState("");
  const [busy, setBusy] = useState(false);
  const current = finding.issuer_revocation;
  if (current) {
    return (
      <span className="grid gap-1 text-xs">
        <span className="font-medium">{t(stateKey(current.status), { authority: current.authority_id })}</span>
        {current.last_error ? <span className="text-destructive">{current.last_error}</span> : null}
      </span>
    );
  }
  const revoke = async () => {
    if (busy || !reason) return;
    setBusy(true);
    try {
      if (finding.certificate_id) {
        const result = await api.bulkRevokeCertificates({ certificate_ids: [finding.certificate_id], reason });
        onDone(
          t("certificates.rogue.issuerInventoryResult", {
            queued: result.total_queued ?? 0,
            revoked: result.total_revoked ?? 0,
            failed: result.total_failed ?? 0,
          }),
        );
      } else if (finding.discovery_id && authority) {
        const queued = await api.revokeRogueCertificateAtIssuer({ discovery_id: finding.discovery_id, authority_id: authority, reason }, newIdempotencyKey());
        onDone(t("certificates.rogue.issuerQueuedResult", { authority: queued.authority_id }));
      }
    } catch (error) {
      onDone(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };
  if (finding.certificate_id) {
    return (
      <Button type="button" size="sm" variant="outline" disabled={busy || !reason} onClick={() => void revoke()}>
        {t("certificates.rogue.revokeAtIssuer")}
      </Button>
    );
  }
  if (!finding.discovery_id) {
    return <span className="text-xs text-muted-foreground">{t("certificates.rogue.issuerNone")}</span>;
  }
  const offered = authorities.filter(revokesFoundCertificates);
  const chosen = offered.find((ca) => ca.id === authority);
  const reasonRefused = chosen?.type === "adcs" && reason !== "" && !ADCS_REVOCATION_REASONS.has(reason);
  return (
    <span className="grid gap-1 text-xs">
      <label className="grid gap-1">
        <span className="text-muted-foreground">{t("certificates.rogue.issuerAuthority")}</span>
        <Select value={authority} onChange={(event) => setAuthority(event.target.value)}>
          <option value="">{t("certificates.rogue.issuerChoose")}</option>
          {offered.map((ca) => (
            <option key={ca.id} value={ca.id}>
              {ca.revoke_by === "certificate_dn" ? t("certificates.rogue.issuerByCertificateDN", { name: ca.name }) : ca.name}
            </option>
          ))}
        </Select>
      </label>
      {reasonRefused ? <span className="text-destructive">{t("certificates.rogue.adcsReason")}</span> : null}
      <Button type="button" size="sm" variant="outline" disabled={busy || !reason || !authority || reasonRefused} onClick={() => void revoke()}>
        {t("certificates.rogue.revokeAtIssuer")}
      </Button>
    </span>
  );
}
