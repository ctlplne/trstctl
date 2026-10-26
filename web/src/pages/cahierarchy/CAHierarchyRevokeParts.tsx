import { FileKey2, ShieldOff } from "lucide-react";
import { useState } from "react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CAAuthority, type CAAuthorityRevocation, type CACeremonyStartRequest, type CAKeyCeremony } from "@/lib/api";
import { KeyValue, LabeledInput, LabeledSelect } from "./CAHierarchyFormParts";

type RevocationReason = CAAuthorityRevocation["reason"];

const revocationReasonLabels = {
  key_compromise: "caHierarchy.revoke.reasonKeyCompromise",
  ca_compromise: "caHierarchy.revoke.reasonCACompromise",
  affiliation_changed: "caHierarchy.revoke.reasonAffiliationChanged",
  superseded: "caHierarchy.revoke.reasonSuperseded",
  cessation_of_operation: "caHierarchy.revoke.reasonCessation",
  privilege_withdrawn: "caHierarchy.revoke.reasonPrivilegeWithdrawn",
} as const satisfies Record<RevocationReason, string>;

const revocationReasons = Object.keys(revocationReasonLabels) as RevocationReason[];

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

// CARevokePanel revokes a signer-backed authority's key after two custodians
// approve a revoke_ca ceremony for the exact authority and reason (A128).
export function CARevokePanel({
  authorities,
  openCeremonyReview,
  onRevoked,
}: {
  authorities: CAAuthority[];
  openCeremonyReview: (
    request: CACeremonyStartRequest,
    onCreated: (ceremony: CAKeyCeremony) => void,
    onError: (message: string) => void,
    setBusy: (busy: boolean) => void,
  ) => Promise<void>;
  onRevoked: () => void;
}) {
  const { t } = useTranslation();
  const [authorityID, setAuthorityID] = useState("");
  const [reason, setReason] = useState<RevocationReason>("key_compromise");
  const [ceremonyID, setCeremonyID] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CAAuthorityRevocation | null>(null);
  const eligible = authorities.filter((item) => (item.status === "active" || item.status === "superseded") && item.signer_handle !== "");
  const readyToStart = authorityID.trim() !== "";
  const readyToRevoke = readyToStart && ceremonyID.trim() !== "";

  async function startCeremony() {
    if (!eligible.some((item) => item.id === authorityID)) {
      setError(t("caHierarchy.revoke.selectAuthority"));
      return;
    }
    await openCeremonyReview(
      { operation: "revoke_ca", authority_id: authorityID, reason, threshold: 2 },
      (next) => setCeremonyID(next.id),
      (message) => setError(message || null),
      setBusy,
    );
  }

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      const next = await api.revokeCAAuthority(authorityID.trim(), { ceremony_id: ceremonyID.trim(), reason });
      setResult(next);
      onRevoked();
    } catch (err) {
      setError(errorMessage(err, t("caHierarchy.revoke.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="ca-revoke-heading" className="grid gap-3 border-b border-border py-4">
      <div className="flex items-start gap-3">
        <ShieldOff className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="ca-revoke-heading" className="text-title font-semibold">
            {t("caHierarchy.revoke.title")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.revoke.body")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.revoke.failed")}>{error}</ErrorState>}
      <section aria-labelledby="ca-revoke-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <h3 id="ca-revoke-form-heading" className="text-title font-semibold">
            {t("caHierarchy.revoke.formTitle")}
          </h3>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => void startCeremony()} disabled={busy || !readyToStart}>
              <FileKey2 className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {t("caHierarchy.revoke.start")}
            </Button>
            <Button type="button" size="sm" variant="destructive" onClick={() => void revoke()} disabled={busy || !readyToRevoke}>
              <ShieldOff className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {t("caHierarchy.revoke.execute")}
            </Button>
          </div>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <LabeledSelect id="ca-revoke-authority" label={t("caHierarchy.revoke.authority")} value={authorityID} onChange={setAuthorityID}>
            <option value="">{t("caHierarchy.revoke.chooseAuthority")}</option>
            {eligible.map((item) => (
              <option key={item.id} value={item.id}>
                {item.common_name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledSelect id="ca-revoke-reason" label={t("caHierarchy.revoke.reason")} value={reason} onChange={(value) => setReason(value as RevocationReason)}>
            {revocationReasons.map((item) => (
              <option key={item} value={item}>
                {t(revocationReasonLabels[item])}
              </option>
            ))}
          </LabeledSelect>
          <LabeledInput id="ca-revoke-ceremony" label={t("caHierarchy.revoke.ceremony")} value={ceremonyID} onChange={setCeremonyID} />
        </div>
        {eligible.length === 0 && <p className="mt-3 text-sm text-muted-foreground">{t("caHierarchy.revoke.none")}</p>}
        {result && (
          <div className="mt-4 grid gap-3">
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <KeyValue label={t("caHierarchy.revoke.resultStatus")} value={`${result.authority.common_name} (${result.authority.status})`} />
              <KeyValue label={t("caHierarchy.revoke.resultSigner")} value={result.signer_revoked ? t("caHierarchy.revoke.yes") : t("caHierarchy.revoke.no")} />
              <KeyValue
                label={t("caHierarchy.revoke.resultParentCRL")}
                value={result.revoked_on_parent_crl ? t("caHierarchy.revoke.yes") : t("caHierarchy.revoke.no")}
              />
              <KeyValue label={t("caHierarchy.revoke.resultAt")} value={result.revoked_at} mono />
            </dl>
            <div>
              <h4 className="font-medium">{t("caHierarchy.revoke.followUp")}</h4>
              <ul className="mt-1 list-disc pl-5 text-muted-foreground">
                {result.follow_up.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </section>
    </section>
  );
}
