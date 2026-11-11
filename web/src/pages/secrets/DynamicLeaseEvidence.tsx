import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { DynamicLease } from "@/lib/api";
import { DynamicLeaseMetadata, RevealPanel } from "./SecretsPageParts";

// sshLeaseCredential reads an SSH certificate lease's credential (A239-L11).
// Its private key and its certificate are saved as two files beside each
// other, so each gets a reveal of its own rather than one JSON blob.
function sshLeaseCredential(value: string): { privateKey: string; certificate: string; principals: string[] } | null {
  try {
    const parsed = JSON.parse(value) as { private_key?: unknown; certificate?: unknown; principals?: unknown };
    if (typeof parsed.private_key !== "string" || typeof parsed.certificate !== "string" || !parsed.certificate.includes("-cert-v01@openssh.com")) {
      return null;
    }
    const principals = Array.isArray(parsed.principals) ? parsed.principals.filter((p): p is string => typeof p === "string") : [];
    return { privateKey: parsed.private_key, certificate: parsed.certificate, principals };
  } catch {
    return null;
  }
}

export function DynamicLeaseEvidence({
  lease,
  active,
  error,
  refresh,
  credential,
  dismiss,
}: {
  lease: DynamicLease;
  active: boolean;
  error: string | null;
  refresh: () => void;
  credential: { leaseID: string; value: string } | null;
  dismiss: () => void;
}) {
  const { t } = useTranslation();
  const ssh = credential ? sshLeaseCredential(credential.value) : null;
  const complete = lease.revocation_status === "completed" && !!lease.revocation_completed_at;
  const awsSession = !!lease.native_expires_at;
  const status = error
    ? t("secrets.dynamic.statusUnavailable")
    : complete
      ? t(awsSession ? "secrets.dynamic.awsExpired" : "secrets.dynamic.providerRemoved")
      : lease.revocation_status === "failed"
        ? t("secrets.dynamic.providerRevokeFailed")
        : lease.revocation_status === "pending"
          ? t(awsSession ? "secrets.dynamic.awsPendingExpiry" : "secrets.dynamic.providerRevokePending")
          : active
            ? t("secrets.dynamic.issuedTitle")
            : t("secrets.dynamic.providerRemovalUnconfirmed");
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="status">
          <h3 className="font-semibold">{status}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {t(
              awsSession
                ? lease.role_chaining
                  ? "secrets.dynamic.awsChainingRevocationTiming"
                  : "secrets.dynamic.awsRevocationTiming"
                : "secrets.dynamic.revocationTiming",
            )}
          </p>
        </div>
        <Button type="button" variant="outline" onClick={refresh}>
          {t("secrets.dynamic.refreshStatus")}
        </Button>
      </div>
      {error ? <ErrorState title={t("secrets.dynamic.statusUnavailable")}>{error}</ErrorState> : null}
      <DynamicLeaseMetadata lease={lease} />
      {credential && active && credential.leaseID === lease.id ? (
        ssh ? (
          <>
            <RevealPanel title={t("secrets.dynamic.sshKeyTitle", { id: credential.leaseID })} onDismiss={dismiss} value={ssh.privateKey}>
              {t("secrets.dynamic.sshKeyHelp")}
            </RevealPanel>
            <RevealPanel title={t("secrets.dynamic.sshCertificateTitle")} onDismiss={dismiss} value={ssh.certificate}>
              {t("secrets.dynamic.sshCertificateHelp", { principals: ssh.principals.join(", ") })}
            </RevealPanel>
          </>
        ) : (
          <RevealPanel title={t("secrets.dynamic.credentialTitle", { id: credential.leaseID })} onDismiss={dismiss} value={credential.value}>
            {t("secrets.dynamic.credentialHelp")}
          </RevealPanel>
        )
      ) : null}
    </div>
  );
}
