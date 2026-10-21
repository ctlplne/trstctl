import type { ReactNode, RefObject } from "react";
import { useTranslation } from "@/i18n/I18nProvider";

export type OfflineCAForm = { certificatePEM: string; commonName: string; dnsDomains: string; maxPathLen: string; ttlDays: string; signatureAlgorithm: string };

/** Reviewed key algorithms an imported (offline-held) CA may carry (A25). The
 * served signer still mints ECDSA-P256 only; these labels are what the import
 * path verifies against the certificate's actual key. */
export const OFFLINE_CA_SIGNATURE_ALGORITHMS = ["ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "Ed25519", "RSA-2048", "RSA-3072", "RSA-4096"] as const;

export function LabeledSelect({
  children,
  id,
  label,
  onChange,
  value,
}: {
  children: ReactNode;
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-control border border-border bg-background px-3 py-2 outline-none transition-colors focus:border-focus focus:ring-2 focus:ring-focus/20"
      >
        {children}
      </select>
    </div>
  );
}

export function LabeledInput({
  id,
  label,
  onChange,
  placeholder,
  required,
  type = "text",
  value,
  inputRef,
}: {
  id: string;
  label: string;
  value: string;
  type?: "text" | "password" | "number";
  required?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
  inputRef?: RefObject<HTMLInputElement>;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <input
        ref={inputRef}
        id={id}
        type={type}
        required={required}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
      />
    </div>
  );
}

export function KeyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: ReactNode }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}

export function OfflineSpecFields({
  commonNameId,
  dnsDomainsId,
  form,
  maxPathLenId,
  onChange,
  ttlDaysId,
}: {
  commonNameId: string;
  dnsDomainsId: string;
  form: OfflineCAForm;
  maxPathLenId: string;
  onChange: (patch: Partial<OfflineCAForm>) => void;
  ttlDaysId: string;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <LabeledInput
        id={commonNameId}
        label={t("caHierarchy.offline.commonName")}
        value={form.commonName}
        required
        onChange={(value) => onChange({ commonName: value })}
      />
      <LabeledInput
        id={dnsDomainsId}
        label={t("caHierarchy.offline.permittedDNSDomains")}
        value={form.dnsDomains}
        onChange={(value) => onChange({ dnsDomains: value })}
        placeholder={t("caHierarchy.offline.placeholderDNSDomain")}
      />
      <LabeledInput
        id={maxPathLenId}
        label={t("caHierarchy.offline.maxPathLen")}
        value={form.maxPathLen}
        required
        type="number"
        onChange={(value) => onChange({ maxPathLen: value })}
      />
      <LabeledSelect
        id={`${commonNameId}-signature-algorithm`}
        label={t("caHierarchy.offline.signatureAlgorithm")}
        value={form.signatureAlgorithm}
        onChange={(value) => onChange({ signatureAlgorithm: value })}
      >
        {OFFLINE_CA_SIGNATURE_ALGORITHMS.map((algorithm) => (
          <option key={algorithm} value={algorithm}>
            {algorithm}
          </option>
        ))}
      </LabeledSelect>
      <LabeledInput
        id={ttlDaysId}
        label={t("caHierarchy.offline.ttlDays")}
        value={form.ttlDays}
        required
        type="number"
        onChange={(value) => onChange({ ttlDays: value })}
      />
    </div>
  );
}
