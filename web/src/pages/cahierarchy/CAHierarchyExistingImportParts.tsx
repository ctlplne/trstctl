import { ShieldCheck } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { CAAuthority } from "@/lib/api";
import { KeyValue, LabeledInput, LabeledSelect, OfflineSpecFields, type OfflineCAForm } from "./CAHierarchyFormParts";

export type ExistingCAForm = OfflineCAForm & { parentID: string; signerHandle: string };

export function ExistingCAImportWorkflow({
  authorities,
  busy,
  ceremonyID,
  error,
  form,
  imported,
  onCeremonyIDChange,
  onFormChange,
  onImport,
  onStartCeremony,
}: {
  authorities: CAAuthority[];
  busy: boolean;
  ceremonyID: string;
  error: string | null;
  form: ExistingCAForm;
  imported: CAAuthority | null;
  onCeremonyIDChange: (value: string) => void;
  onFormChange: (patch: Partial<ExistingCAForm>) => void;
  onImport: () => void;
  onStartCeremony: () => void;
}) {
  const { t } = useTranslation();
  const ready = form.certificatePEM.trim() !== "" && form.commonName.trim() !== "" && form.signerHandle.trim() !== "";
  const importReady = ready && ceremonyID.trim() !== "";
  const parents = authorities.filter((authority) => authority.status === "active");

  return (
    <section aria-labelledby="existing-ca-import-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="existing-ca-import-heading" className="text-title font-semibold">
            {t("caHierarchy.existing.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.existing.description")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.existing.errorTitle")}>{error}</ErrorState>}
      <section aria-labelledby="existing-ca-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="existing-ca-form-heading" className="text-title font-semibold">
              {t("caHierarchy.existing.formHeading")}
            </h3>
            {imported && <p className="mt-1 font-mono text-xs">{imported.id}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={onStartCeremony} disabled={busy || !ready}>
              {t("caHierarchy.existing.startCeremony")}
            </Button>
            <Button type="button" size="sm" onClick={onImport} disabled={busy || !importReady}>
              {t("caHierarchy.existing.import")}
            </Button>
          </div>
        </div>
        <div className="mt-4 grid gap-4">
          <OfflineSpecFields
            commonNameId="existing-ca-common-name"
            dnsDomainsId="existing-ca-dns-domains"
            form={form}
            maxPathLenId="existing-ca-max-path-len"
            onChange={onFormChange}
            ttlDaysId="existing-ca-ttl-days"
          />
          <LabeledSelect
            id="existing-ca-parent-id"
            label={t("caHierarchy.existing.parentAuthority")}
            value={form.parentID}
            onChange={(value) => onFormChange({ parentID: value })}
          >
            <option value="">{t("caHierarchy.existing.noRegisteredParent")}</option>
            {parents.map((authority) => (
              <option key={authority.id} value={authority.id}>
                {authority.common_name} ({authority.id})
              </option>
            ))}
          </LabeledSelect>
          <p className="text-sm text-muted-foreground">{t("caHierarchy.existing.parentHelp")}</p>
          <LabeledInput
            id="existing-ca-signer-handle"
            label={t("caHierarchy.offline.signerHandle")}
            value={form.signerHandle}
            required
            onChange={(value) => onFormChange({ signerHandle: value })}
            placeholder={t("caHierarchy.existing.placeholderSignerHandle")}
          />
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="existing-ca-chain">
              {t("caHierarchy.existing.chainPEM")}
            </label>
            <textarea
              id="existing-ca-chain"
              rows={6}
              value={form.certificatePEM}
              onChange={(event) => onFormChange({ certificatePEM: event.target.value })}
              className="min-h-36 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
              placeholder={t("caHierarchy.offline.placeholderCertificate")}
            />
          </div>
          <LabeledInput
            id="existing-ca-ceremony-id"
            label={t("caHierarchy.existing.ceremonyID")}
            value={ceremonyID}
            onChange={onCeremonyIDChange}
            placeholder={t("caHierarchy.existing.placeholderCeremonyID")}
          />
          {imported && (
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <KeyValue label={t("caHierarchy.offline.commonName")} value={imported.common_name} />
              <KeyValue label={t("caHierarchy.existing.kind")} value={imported.kind} />
              <KeyValue label={t("caHierarchy.existing.parentAuthority")} value={imported.parent_id || "-"} mono />
              <KeyValue label={t("caHierarchy.offline.signerHandle")} value={imported.signer_handle || "-"} mono />
              <KeyValue label={t("caHierarchy.existing.serial")} value={imported.serial || "-"} mono />
            </dl>
          )}
        </div>
      </section>
    </section>
  );
}
