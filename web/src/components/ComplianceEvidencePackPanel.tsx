import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { ComplianceEvidencePack } from "@/lib/api";

interface ComplianceEvidenceWindow {
  from?: string;
  through?: string;
}

interface ComplianceEvidenceReference {
  ref?: string;
  source?: string;
  type?: string;
  observed_at?: string;
  sequence?: number;
  digest?: string;
}

interface ComplianceControl {
  id?: string;
  title?: string;
  status?: string;
  evidence?: string[];
  evidence_refs?: ComplianceEvidenceReference[];
  missing?: string[];
  coverage_window?: ComplianceEvidenceWindow;
}

interface ComplianceManifest {
  tenant_id?: string;
  generated_at?: string;
  evidence_window?: ComplianceEvidenceWindow;
  controls?: ComplianceControl[];
  posture?: {
    total_crypto_assets?: number;
    quantum_vulnerable?: number;
    post_quantum?: number;
  };
  custody?: ComplianceEvidencePack["custody"];
  adcs?: ComplianceEvidencePack["adcs"];
  product_evidences?: string[];
  operator_attests?: string[];
}

export function ComplianceEvidencePackPanel({ label, pack }: { label: string; pack: ComplianceEvidencePack }) {
  const { formatDate, t } = useTranslation();
  const manifest = manifestFromPack(pack);
  const controls = manifest.controls ?? [];
  const evidenced = controls.filter((control) => control.status === "evidenced").length;
  const gaps = controls.filter((control) => control.status === "gap").length;
  const posture = manifest.posture ?? {};
  const custody = manifest.custody;
  const productEvidence = manifest.product_evidences ?? [];
  const operatorAttests = manifest.operator_attests ?? [];
  // V4 always serves this field, but keeping the renderer tolerant of older
  // cached packs prevents a schema upgrade from turning historical evidence
  // into a blank page before the operator downloads a fresh artifact.
  const adcsEvidence = manifest.adcs ?? pack.adcs ?? { observations: [], drift: [] };
  const payload = JSON.stringify(pack, null, 2);

  return (
    <section aria-labelledby="compliance-pack-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="compliance-pack-heading" className="text-title font-semibold">
            {label} {translateNow("source.evidence.pack.dbd6e1203e")}
          </h3>
          <p className="mt-1 text-muted-foreground">{translateNow("source.signed.export.plus.offline.verification.ke.f03caf9838")}</p>
        </div>
        <a
          className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
          download={`${pack.framework}-evidence-pack.json`}
          href={`data:application/json;charset=utf-8,${encodeURIComponent(payload)}`}
        >
          {translateNow("source.download.signed.bundle.c6373a92cb")}
        </a>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <EvidenceMetric label="Format" value={pack.format} mono />
        <EvidenceMetric label={t("policy.compliance.tenant")} value={manifest.tenant_id ?? t("policy.compliance.unbound")} mono />
        <EvidenceMetric
          label={t("policy.compliance.generated")}
          value={manifest.generated_at ? formatDate(manifest.generated_at) : t("policy.compliance.unknown")}
        />
        <EvidenceMetric
          label={t("policy.compliance.coverageWindow")}
          value={formatEvidenceWindow(manifest.evidence_window, formatDate, t("policy.compliance.unknown"))}
        />
        <EvidenceMetric label="Controls" value={`${controls.length} ${plural(controls.length, "control")}`} />
        <EvidenceMetric label="Evidenced" value={`${evidenced} evidenced`} />
        <EvidenceMetric label="Gaps" value={`${gaps} ${plural(gaps, "gap")}`} />
        <EvidenceMetric label="Crypto assets" value={String(posture.total_crypto_assets ?? 0)} />
        <EvidenceMetric label="Quantum vulnerable" value={`${posture.quantum_vulnerable ?? 0} quantum vulnerable`} />
        <EvidenceMetric label="Post-quantum" value={String(posture.post_quantum ?? 0)} />
        <EvidenceMetric label={t("policy.compliance.custodyTotal")} value={String(custody?.total ?? 0)} />
        <EvidenceMetric label={t("policy.compliance.custodyRecorded")} value={String(custody?.recorded ?? 0)} />
        <EvidenceMetric label={t("policy.compliance.custodyUnrecorded")} value={String(custody?.unrecorded ?? 0)} />
        <EvidenceMetric label="Public key DER" value={`${pack.public_key_der.length} bytes`} />
        <EvidenceMetric label={translateNow("source.adcs.compliance.observations.aud370012")} value={String(adcsEvidence.observations.length)} />
        <EvidenceMetric label={translateNow("source.adcs.compliance.drift.aud370013")} value={String(adcsEvidence.drift.length)} />
      </dl>

      {adcsEvidence.observations.length > 0 ? (
        <section aria-labelledby="compliance-adcs-heading" className="mt-4 grid gap-2 rounded-md border border-border p-3">
          <h4 id="compliance-adcs-heading" className="font-medium">
            {translateNow("source.adcs.compliance.heading.aud370014")}
          </h4>
          <p className="text-xs text-muted-foreground">{translateNow("source.adcs.compliance.help.aud370015")}</p>
          <ul className="grid gap-2">
            {adcsEvidence.observations.map((observation) => (
              <li key={observation.reference.event_id} className="grid gap-1 border-l-2 border-status-info pl-2 text-xs">
                <span className="font-medium">
                  {observation.domain} · {observation.findings.length} {translateNow("source.adcs.compliance.findings.aud370016")}
                </span>
                <span className="font-mono text-muted-foreground">
                  {translateNow("source.adcs.compliance.event.aud370018")}:{observation.reference.event_id} · #{observation.reference.sequence}
                </span>
                <span className="break-all font-mono text-muted-foreground">{observation.reference.digest}</span>
                {observation.findings.map((finding) => (
                  <span key={`${finding.resource_kind}/${finding.resource}/${finding.id}`}>
                    <span className="font-mono">{finding.id}</span> · {finding.resource}: {finding.summary}
                  </span>
                ))}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {custody && custody.unrecorded_certificates.length > 0 && (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[48rem]">
            <caption className="text-left font-medium">{t("policy.compliance.custodyGaps")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.compliance.certificate")}</th>
                <th scope="col">{t("policy.compliance.fingerprint")}</th>
                <th scope="col">{t("policy.compliance.missingCustodyFields")}</th>
              </tr>
            </thead>
            <tbody>
              {custody.unrecorded_certificates.map((certificate) => (
                <tr key={certificate.id}>
                  <td>
                    <p>{certificate.subject}</p>
                    <p className="font-mono text-xs text-muted-foreground">{certificate.id}</p>
                  </td>
                  <td className="break-all font-mono text-xs">{certificate.fingerprint}</td>
                  <td>{certificate.missing_fields.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {controls.length > 0 && (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[72rem]">
            <caption className="sr-only">
              {label} {translateNow("source.controls.1e2135d1b5")}
            </caption>
            <thead>
              <tr>
                <th scope="col">{translateNow("source.control.32d7e82082")}</th>
                <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                <th scope="col">{translateNow("source.evidence.03867aea70")}</th>
                <th scope="col">{t("policy.compliance.evidenceRefs")}</th>
                <th scope="col">{t("policy.compliance.missingPrerequisites")}</th>
              </tr>
            </thead>
            <tbody>
              {controls.map((control) => (
                <tr key={control.id ?? control.title ?? "control"} className="align-top">
                  <td>
                    <p className="font-medium">{control.title ?? control.id ?? translateNow("source.control.32d7e82082")}</p>
                    {control.id && <p className="mt-1 font-mono text-xs text-muted-foreground">{control.id}</p>}
                  </td>
                  <td>{control.status ?? translateNow("source.unknown.b23a6a8439")}</td>
                  <td>
                    <p>{control.evidence?.join(", ") || translateNow("source.no.evidence.label.f46f14947d")}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t("policy.compliance.coverageWindow")}: {formatEvidenceWindow(control.coverage_window, formatDate, t("policy.compliance.unknown"))}
                    </p>
                  </td>
                  <td>
                    {control.evidence_refs && control.evidence_refs.length > 0 ? (
                      <ul className="space-y-2">
                        {control.evidence_refs.map((ref, index) => (
                          <li key={`${ref.ref ?? "evidence"}:${index}`}>
                            <p className="break-all font-mono text-xs">{ref.ref ?? t("policy.compliance.unknown")}</p>
                            <p className="text-xs text-muted-foreground">
                              {[ref.source, ref.type, ref.observed_at ? formatDate(ref.observed_at) : undefined, ref.sequence ? `#${ref.sequence}` : undefined]
                                .filter(Boolean)
                                .join(" · ")}
                            </p>
                            {ref.digest && <p className="break-all font-mono text-xs text-muted-foreground">{ref.digest}</p>}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      translateNow("source.no.evidence.ref.0697e8fb68")
                    )}
                  </td>
                  <td>{control.missing?.join(", ") || t("policy.compliance.noneMissing")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <EvidenceList title={translateNow("source.product.evidence.1b4586bcc7")} items={productEvidence} />
        <EvidenceList title={translateNow("source.operator.attestations.bb1bff1074")} items={operatorAttests} />
      </div>
    </section>
  );
}

function EvidenceMetric({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "text-base font-semibold"}>{value}</dd>
    </div>
  );
}

function EvidenceList({ items, title }: { items: string[]; title: string }) {
  return (
    <div role="group" aria-label={title} className="rounded-md border border-border p-3">
      <p className="font-medium">{title}</p>
      {items.length > 0 ? (
        <ul className="mt-2 grid gap-1 text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-muted-foreground">{translateNow("source.no.labels.in.this.pack.afb9ef5039")}</p>
      )}
    </div>
  );
}

function manifestFromPack(pack: ComplianceEvidencePack): ComplianceManifest {
  const raw = pack.signed_export.manifest ?? pack.signed_export.Manifest;
  if (isRecord(raw)) return raw as ComplianceManifest;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (isRecord(parsed)) return parsed as ComplianceManifest;
    } catch {
      return {};
    }
  }
  return {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatEvidenceWindow(window: ComplianceEvidenceWindow | undefined, formatDate: (value: string) => string, unknown: string): string {
  if (!window?.from || !window.through) return unknown;
  return `${formatDate(window.from)} – ${formatDate(window.through)}`;
}

function plural(count: number, singular: string): string {
  if (count === 1) return singular;
  return `${singular}s`;
}
