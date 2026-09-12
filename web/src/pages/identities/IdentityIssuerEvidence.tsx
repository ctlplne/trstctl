import type { Identity } from "@/lib/api";
import { useTranslation } from "@/i18n/I18nProvider";

const sourceLabels = {
  external: "connectors.binding.sourceExternal",
  private: "connectors.binding.sourcePrivate",
  platform: "connectors.binding.sourcePlatform",
} as const;

/** Endpoint CA selection is separate from the protocol issuer catalog. Neither
 * field substitutes for a historical certificate's retained issuance evidence. */
export function IdentityIssuerEvidence({ identity }: { identity: Identity }) {
  const { t } = useTranslation();
  const attribute = (key: string) => {
    const value = identity.attributes?.[key];
    return typeof value === "string" ? value.trim() : "";
  };
  const source = attribute("issuing_authority_source");
  const id = attribute("issuing_authority_id");
  const name = attribute("issuing_authority_name");
  const selected = ["x509_certificate", "x509"].includes(identity.kind) && Boolean(source || id || name);
  const sourceLabel = source === "external" || source === "private" || source === "platform" ? sourceLabels[source] : null;

  return (
    <div>
      <dt className="font-medium text-muted-foreground">{t(selected ? "identities.issuer.selectedCA" : "source.issuer.39e02c46a0")}</dt>
      <dd>
        {selected ? (
          <>
            <p>{id && sourceLabel ? t("identities.issuer.selection", { source: t(sourceLabel), name: name || id }) : t("identities.issuer.incomplete")}</p>
            <p className="mt-1 text-xs text-muted-foreground">{t("identities.issuer.selectionScope")}</p>
          </>
        ) : identity.issuer_id ? (
          <a className="text-primary underline" href={`/protocols?issuer=${encodeURIComponent(identity.issuer_id)}`}>
            {t("source.issuer.39e02c46a0")} {identity.issuer_id}
          </a>
        ) : (
          t("source.no.issuer.bound.d1e424a34f")
        )}
      </dd>
    </div>
  );
}
