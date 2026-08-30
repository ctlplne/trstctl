import { ShieldCheck, TriangleAlert } from "lucide-react";
import { useTranslation } from "@/i18n/I18nProvider";
import type { ACMEDNS01ProviderCatalogItem } from "@/lib/api";

/** Explains why the running control plane trusts a DNS provider.
 * Catalog absence is a recovery state: a saved config can outlive a removed plugin. */
export function DNS01ProviderTrustPanel({ provider }: { provider?: ACMEDNS01ProviderCatalogItem }) {
  const { t } = useTranslation();

  if (!provider) {
    return (
      <section aria-label={t("protocols.dns01.providerTrust.label")} className="rounded-control border border-status-warning/30 bg-status-warning/10 p-4">
        <div className="flex items-start gap-3">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
          <div>
            <h3 className="font-semibold">{t("protocols.dns01.providerTrust.unavailable")}</h3>
            <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.providerTrust.unavailableHelp")}</p>
          </div>
        </div>
      </section>
    );
  }

  const isPlugin = provider.kind === "plugin";
  const provenance =
    provider.provenance === "ed25519-signature-verified"
      ? t("protocols.dns01.providerTrust.signatureVerified")
      : provider.provenance === "core-build"
        ? t("protocols.dns01.providerTrust.coreBuild")
        : provider.provenance || t("protocols.dns01.providerTrust.notReported");
  const conformance =
    provider.conformance === "signed-present-cleanup"
      ? t("protocols.dns01.providerTrust.pluginContractPassed")
      : provider.conformance === "present-validate-cleanup"
        ? t("protocols.dns01.providerTrust.builtInContractPassed")
        : provider.conformance;
  const admission =
    provider.admission_state === "verified"
      ? t("protocols.dns01.providerTrust.startupVerified")
      : provider.admission_state === "built-in"
        ? t("protocols.dns01.providerTrust.builtInAdmission")
        : provider.admission_state || t("protocols.dns01.providerTrust.notReported");

  return (
    <section aria-label={t("protocols.dns01.providerTrust.label")} className="rounded-control border border-border bg-muted/20 p-4">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
        <div>
          <h3 className="font-semibold">{isPlugin ? t("protocols.dns01.providerTrust.verifiedPlugin") : t("protocols.dns01.providerTrust.builtInProvider")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            {isPlugin ? t("protocols.dns01.providerTrust.pluginHelp") : t("protocols.dns01.providerTrust.builtInHelp")}
          </p>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
        <TrustFact label={t("protocols.dns01.providerTrust.package")} value={provider.provider_package} mono />
        <TrustFact label={t("protocols.dns01.admission")} value={admission} />
        <TrustFact label={t("protocols.dns01.provenance")} value={provenance} />
        <TrustFact label={t("protocols.dns01.conformance")} value={conformance} />
      </dl>
      <div className="mt-4">
        <h4 className="text-sm font-semibold">{t("protocols.dns01.providerTrust.grants")}</h4>
        {(provider.capabilities ?? []).length === 0 ? (
          <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.providerTrust.noGrants")}</p>
        ) : (
          <ul className="mt-1 flex flex-wrap gap-2">
            {(provider.capabilities ?? []).map((capability) => (
              <li key={capability} className="rounded-control border border-border bg-background px-2 py-1 font-mono text-xs">
                {capability}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function TrustFact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className={`mt-0.5 ${mono ? "break-all font-mono text-xs" : "break-words font-medium"}`}>{value}</dd>
    </div>
  );
}
