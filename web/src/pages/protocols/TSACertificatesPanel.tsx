import { useState } from "react";
import { useCan } from "@/components/rbac";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type TSACertificate } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery, useQueryClient } from "@/lib/query";

// RFC 5280 reasons an operator would revoke a TSA certificate for. A
// compromise taints every timestamp the certificate signed; the others keep
// the timestamps it signed before the revocation.
const revocationReasons = ["keyCompromise", "superseded", "cessationOfOperation", "affiliationChanged", "privilegeWithdrawn"] as const;

function stateTone(state: TSACertificate["state"]): "success" | "critical" | "neutral" {
  if (state === "active") return "success";
  if (state === "revoked") return "critical";
  return "neutral";
}

/** A145: the timestamp authority's certificates, rotation and revocation. */
export function TSACertificatesPanel() {
  const { t, formatDateTime } = useTranslation();
  const canWrite = useCan("issuers:write");
  const queryClient = useQueryClient();
  const query = useApiQuery(["protocols", "tsa", "certificates"], () => api.tsaCertificates(), { retry: false });
  const [rotateReason, setRotateReason] = useState("");
  const [revokeReason, setRevokeReason] = useState<string>("superseded");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const stateLabel = (state: TSACertificate["state"]) => {
    switch (state) {
      case "active":
        return t("protocols.tsaCertificates.state.active");
      case "revoked":
        return t("protocols.tsaCertificates.state.revoked");
      default:
        return t("protocols.tsaCertificates.state.retired");
    }
  };

  async function run(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(done);
      await queryClient.invalidateQueries({ queryKey: ["protocols", "tsa", "certificates"] });
    } catch (cause) {
      setError(apiProblemMessage(cause, t("protocols.tsaCertificates.failed")));
    } finally {
      setBusy(false);
    }
  }

  // The list answers 404 where this tenant does not run the TSA; the panel
  // then stays out of the way.
  if (query.errorValue && !query.data) {
    return null;
  }
  const list = query.data;
  return (
    <Card role="region" aria-labelledby="tsa-certificates-heading" className="min-w-0 scroll-mt-24">
      <CardHeader className="space-y-0">
        <CardTitle id="tsa-certificates-heading">{t("protocols.tsaCertificates.heading")}</CardTitle>
        <p className="mt-1 max-w-3xl text-body text-muted-foreground">{t("protocols.tsaCertificates.description")}</p>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4">
        {error ? <ErrorState title={t("protocols.tsaCertificates.failed")}>{error}</ErrorState> : null}
        {notice ? (
          <p role="status" className="text-sm">
            {notice}
          </p>
        ) : null}
        {list ? (
          <>
            <ul className="grid gap-2" aria-label={t("protocols.tsaCertificates.listLabel")}>
              {list.items.map((certificate) => (
                <li key={certificate.serial} className="grid min-w-0 gap-2 border-s-2 border-border ps-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                  <div className="min-w-0">
                    <p className="break-all font-mono text-sm">{certificate.serial}</p>
                    <p className="mt-1 text-caption text-muted-foreground">
                      {certificate.state === "revoked" && certificate.revoked_at
                        ? t("protocols.tsaCertificates.revokedAt", { time: formatDateTime(certificate.revoked_at), reason: certificate.reason ?? "" })
                        : t("protocols.tsaCertificates.validUntil", { time: formatDateTime(certificate.not_after) })}
                    </p>
                    {canWrite && certificate.state === "retired" ? (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="mt-2"
                        disabled={busy}
                        onClick={() => void run(() => api.revokeTSACertificate(certificate.serial, revokeReason), t("protocols.tsaCertificates.revoked"))}
                      >
                        {t("protocols.tsaCertificates.revoke")}
                      </Button>
                    ) : null}
                  </div>
                  <StatusBadge value={certificate.state} label={stateLabel(certificate.state)} tone={stateTone(certificate.state)} />
                </li>
              ))}
            </ul>
            <p className="text-caption text-muted-foreground">{t("protocols.tsaCertificates.status", { crl: list.crl, ocsp: list.ocsp })}</p>
            {canWrite ? (
              <div className="grid gap-3 border-t border-border pt-4 sm:grid-cols-2">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("protocols.tsaCertificates.rotateReason")}</span>
                  <Select value={rotateReason} onChange={(event) => setRotateReason(event.target.value)} disabled={busy}>
                    <option value="">{t("protocols.tsaCertificates.retireOnly")}</option>
                    {revocationReasons.map((reason) => (
                      <option key={reason} value={reason}>
                        {reason}
                      </option>
                    ))}
                  </Select>
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("protocols.tsaCertificates.revokeReason")}</span>
                  <Select value={revokeReason} onChange={(event) => setRevokeReason(event.target.value)} disabled={busy}>
                    {revocationReasons.map((reason) => (
                      <option key={reason} value={reason}>
                        {reason}
                      </option>
                    ))}
                  </Select>
                </label>
                <div className="sm:col-span-2">
                  <Button
                    type="button"
                    disabled={busy}
                    onClick={() => void run(() => api.rotateTSACertificate(rotateReason || undefined), t("protocols.tsaCertificates.rotated"))}
                  >
                    {t("protocols.tsaCertificates.rotate")}
                  </Button>
                  <p className="mt-1 text-caption text-muted-foreground">{t("protocols.tsaCertificates.rotateHelp")}</p>
                </div>
              </div>
            ) : null}
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
