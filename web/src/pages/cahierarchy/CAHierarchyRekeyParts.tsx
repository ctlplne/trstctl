import { FileKey2, KeyRound } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { CAAuthority, CAAuthorityRotation } from "@/lib/api";
import { KeyValue, LabeledInput, LabeledSelect } from "./CAHierarchyFormParts";

export function CARekeyPanel({
  authorityID,
  authorities,
  busy,
  ceremonyID,
  error,
  reason,
  result,
  ttlDays,
  onActivate,
  onAuthorityChange,
  onCeremonyChange,
  onReasonChange,
  onStartCeremony,
  onTTLChange,
}: {
  authorityID: string;
  authorities: CAAuthority[];
  busy: boolean;
  ceremonyID: string;
  error: string | null;
  reason: string;
  result: CAAuthorityRotation | null;
  ttlDays: string;
  onActivate: () => void;
  onAuthorityChange: (value: string) => void;
  onCeremonyChange: (value: string) => void;
  onReasonChange: (value: string) => void;
  onStartCeremony: () => void;
  onTTLChange: (value: string) => void;
}) {
  const { t } = useTranslation();
  const eligibleAuthorities = authorities.filter((item) => item.status === "active" && item.signer_handle !== "");
  const readyToStart = authorityID.trim() !== "";
  const readyToRekey = readyToStart && ceremonyID.trim() !== "";

  return (
    <section aria-labelledby="ca-rekey-heading" className="grid gap-3 border-b border-border py-4">
      <div className="flex items-start gap-3">
        <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="ca-rekey-heading" className="text-title font-semibold">
            {translateNow("source.ca.renewal.and.re.key.fb27d9e180")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.mint.a.fresh.signer.backed.ca.key.and.cert.4f35946ce6")}</p>
        </div>
      </div>
      {error && <ErrorState title={translateNow("source.ca.re.key.failed.c94515c43b")}>{error}</ErrorState>}
      <section aria-labelledby="ca-rekey-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="ca-rekey-form-heading" className="text-title font-semibold">
              {translateNow("source.fresh.ca.material.d1a53a627a")}
            </h3>
            {result && <p className="mt-1 font-mono text-xs">{result.active_issue_path}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={onStartCeremony} disabled={busy || !readyToStart}>
              <FileKey2 className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {translateNow("source.start.re.key.ceremony.c2e02a1a0c")}
            </Button>
            <Button type="button" size="sm" onClick={onActivate} disabled={busy || !readyToRekey}>
              <KeyRound className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {translateNow("source.re.key.ca.4aadf37c7a")}
            </Button>
          </div>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-4">
          <LabeledSelect id="ca-rekey-authority" label="CA authority" value={authorityID} onChange={onAuthorityChange}>
            <option value="">{translateNow("source.select.authority.b2858bf4f3")}</option>
            {eligibleAuthorities.map((item) => (
              <option key={item.id} value={item.id}>
                {item.common_name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledInput id="ca-rekey-ceremony" label={t("parity.ceremonyId_6f8ee6")} value={ceremonyID} onChange={onCeremonyChange} />
          <LabeledInput id="ca-rekey-ttl" label="Validity days" value={ttlDays} type="number" onChange={onTTLChange} />
          <LabeledInput id="ca-rekey-reason" label="Re-key reason" value={reason} onChange={onReasonChange} />
        </div>
        {eligibleAuthorities.length === 0 && (
          <p className="mt-3 text-sm text-muted-foreground">{translateNow("source.create.or.import.a.signer.backed.authority.938d8e0658")}</p>
        )}
        {result && (
          <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <KeyValue label="Predecessor" value={`${result.predecessor.common_name} (${result.predecessor.status})`} />
            <KeyValue label="Fresh successor" value={`${result.successor.common_name} (${result.successor.status})`} />
            <KeyValue label="Stable issue URL" value={result.issue_path} mono />
            <KeyValue label="Active issue URL" value={result.active_issue_path} mono />
          </dl>
        )}
      </section>
    </section>
  );
}
