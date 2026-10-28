import { useState } from "react";

import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type Certificate } from "@/lib/api";
import type { CertificateDERRecovery, CertificateDERRecoveryRequest } from "@/lib/api-types.gen";
import { newIdempotencyKey } from "@/lib/apiTransport";

// A215: a row recorded without the certificate itself (a scan, a cloud
// listing) cannot take part in authority agreement checks. The operator asks
// for the bytes from the tenant's CA records or the endpoint the row names;
// they are attached only when they match the row's fingerprint.
export function CertificateBytesRecovery({ detail, onRecovered }: { detail: Certificate; onRecovered: (updated: Certificate) => void }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<CertificateDERRecovery | null>(null);
  const [error, setError] = useState<string | null>(null);
  const address = endpointAddress(detail.deployment_location);

  async function recover(request: CertificateDERRecoveryRequest) {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const answer = await api.recoverCertificateDER(detail.id, request, newIdempotencyKey());
      setResult(answer);
      if (answer.outcome === "recovered") onRecovered(await api.getCertificate(detail.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (detail.der_recovery) {
    return (
      <div className="md:col-span-2">
        <dt className="font-medium text-muted-foreground">{t("certificateCockpit.detail.bytes")}</dt>
        <dd className="break-all text-sm">
          {t(detail.der_recovery.method === "endpoint" ? "certificateCockpit.detail.bytesFromEndpoint" : "certificateCockpit.detail.bytesFromLedger", {
            evidence: detail.der_recovery.evidence,
            when: formatDateTime(detail.der_recovery.recovered_at),
          })}
        </dd>
      </div>
    );
  }
  if (detail.certificate_bytes_held) return null;
  return (
    <div className="md:col-span-2">
      <dt className="font-medium text-muted-foreground">{t("certificateCockpit.detail.bytes")}</dt>
      <dd className="text-sm">{t("certificateCockpit.detail.bytesMissing")}</dd>
      <dd className="mt-2 flex flex-wrap gap-2">
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void recover({ method: "ca_ledger" })}>
          {t("certificateCockpit.detail.bytesFromLedgerAction")}
        </Button>
        {address ? (
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void recover(endpointRequest(address))}>
            {t("certificateCockpit.detail.bytesFromEndpointAction", { address })}
          </Button>
        ) : null}
      </dd>
      {result && result.outcome !== "recovered" ? (
        <dd role="status" className="mt-1 text-xs text-muted-foreground">
          {t(outcomeMessages[result.outcome] ?? "certificateCockpit.detail.bytesNotFound", { detail: result.detail ?? "" })}
        </dd>
      ) : null}
      {error ? (
        <dd role="alert" className="mt-1 text-xs text-status-warning">
          {error}
        </dd>
      ) : null}
    </div>
  );
}

const outcomeMessages = {
  already_held: "certificateCockpit.detail.bytesAlreadyHeld",
  not_found: "certificateCockpit.detail.bytesNotFound",
  mismatch: "certificateCockpit.detail.bytesMismatch",
  unreachable: "certificateCockpit.detail.bytesUnreachable",
} as const;

// endpointAddress is the row's deployment location when it is host:port.
function endpointAddress(location: string | undefined): string | null {
  const value = (location ?? "").trim();
  return /^(\[[0-9a-fA-F:.]+\]|[^\s/:]+):\d{1,5}$/.test(value) ? value : null;
}

// endpointRequest allows a private address only for the exact address the row
// names, so the control plane dials that one host and nothing else.
function endpointRequest(address: string): CertificateDERRecoveryRequest {
  const host = address.slice(0, address.lastIndexOf(":")).replace(/^\[|\]$/g, "");
  if (/^(10|127)\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(host)) {
    return { method: "endpoint", allow_private_endpoint: true, private_egress_cidrs: [`${host}/32`] };
  }
  return { method: "endpoint" };
}
