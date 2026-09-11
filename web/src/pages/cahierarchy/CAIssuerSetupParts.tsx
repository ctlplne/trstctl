import { useRef } from "react";
import { X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { translateNow as t } from "@/i18n/I18nProvider";
import type { IssuerTypeConfig } from "@/lib/issuerCatalog";

export const vaultOperatorConfig = {
  external_cas: [
    {
      id: "vault-prod",
      type: "vaultpki",
      name: "Production Vault PKI",
      endpoint: "https://vault.internal:8200",
      mount: "pki",
      role: "web-certs",
      bearer_token_ref: "file:/run/secrets/vault-token",
      network: {
        root_ca_file: "/etc/trstctl/vault-server-ca.pem",
        allow_private_endpoint: true,
        private_egress_cidrs: ["10.40.0.15/32"],
        timeout: "15s",
      },
    },
  ],
};

/** Setup selects a real operator configuration or a protected local-CA flow.
 * It never substitutes a metadata-only issuer mutation for either operation. */
export function IssuerSetupDialog({
  type,
  onClose,
  onCreateLocal,
}: {
  type: IssuerTypeConfig;
  onClose: () => void;
  onCreateLocal: (kind: "root" | "intermediate") => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  return (
    <Dialog
      open
      onClose={onClose}
      titleId="issuer-create-heading"
      descriptionId="issuer-create-description"
      initialFocusRef={closeRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[min(42rem,calc(100vh-2rem))] w-full max-w-3xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <h2 id="issuer-create-heading" className="text-title font-semibold">
          {t("source.configure.6defafa2ca")} {type.name} {t("source.issuer.535c6f8eb5")}
        </h2>
        <Button ref={closeRef} type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("source.close.issuer.form.b40f6c2037")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <div className="grid gap-4 p-5">
        <p id="issuer-create-description">{t(type.internal ? "caSetup.localBoundary" : "caSetup.operatorBoundary")}</p>
        {type.internal ? (
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => onCreateLocal("root")}>
              {t("parity.createRootCa_94fb33")}
            </Button>
            <Button type="button" variant="outline" onClick={() => onCreateLocal("intermediate")}>
              {t("parity.createIntermediateCa_829ab7")}
            </Button>
          </div>
        ) : (
          <>
            <ol className="list-decimal space-y-3 pl-5 text-sm">
              <li>{t("caSetup.configure")}</li>
              <li>{t("caSetup.trust")}</li>
              <li>{t("caSetup.restart")}</li>
              <li>{t("caSetup.verify")}</li>
            </ol>
            {type.id === "VaultPKI" && (
              <>
                <p className="text-sm">{t("caSetup.vaultExample")}</p>
                <pre
                  data-testid="vault-operator-config"
                  className="max-h-64 overflow-auto rounded-control border border-border bg-muted/40 p-3 font-mono text-xs"
                >
                  {JSON.stringify(vaultOperatorConfig, null, 2)}
                </pre>
              </>
            )}
            <p className="text-sm text-muted-foreground">{t("caSetup.reference")}</p>
          </>
        )}
      </div>
      <footer className="flex justify-end gap-2 border-t border-border px-5 py-4">
        <Button type="button" variant="outline" onClick={onClose}>
          {t("source.cancel.19766ed6cc")}
        </Button>
      </footer>
    </Dialog>
  );
}
