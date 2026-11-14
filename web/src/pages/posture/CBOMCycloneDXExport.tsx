import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CBOMCycloneDXExport as Export } from "@/lib/api";

function save(filename: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type: "application/json" }));
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

// Q3-L1: the BOM's own JSF signature, when it carries one.
function embeddedSignature(bom: unknown): { algorithm: string; keyId: string } | null {
  if (!bom || typeof bom !== "object") return null;
  const signature = (bom as { signature?: unknown }).signature;
  if (!signature || typeof signature !== "object") return null;
  const { algorithm, keyId } = signature as { algorithm?: unknown; keyId?: unknown };
  return typeof algorithm === "string" && typeof keyId === "string" ? { algorithm, keyId } : null;
}

// Q3: the crypto inventory as a signed CycloneDX 1.6 CBOM. "CycloneDX CBOM"
// saves the BOM a scanner or an agency ingests, signed in place (Q3-L1);
// "Signed export" saves it with the JWS beside it for offline verification
// (trstctl cbom verify-cyclonedx).
export function CBOMCycloneDXExport() {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function download(kind: "bom" | "signed") {
    setBusy(true);
    setMessage(null);
    try {
      const exported: Export = await api.exportCBOMCycloneDX();
      if (kind === "bom") {
        save("trstctl-cbom.cdx.json", JSON.stringify(exported.bom, null, 2));
      } else {
        save("trstctl-cbom-signed-export.json", JSON.stringify(exported, null, 2));
      }
      const signature = embeddedSignature(exported.bom);
      const saved = t("posture.cbom.cyclonedx.saved", { components: exported.components });
      setMessage(signature ? `${saved} ${t("posture.cbom.cyclonedx.embedded", signature)}` : saved);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : t("posture.cbom.cyclonedx.failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="cbom-cyclonedx-heading" className="grid gap-2 rounded-panel border border-border p-comfortable text-sm">
      <h3 id="cbom-cyclonedx-heading" className="font-medium">
        {t("posture.cbom.cyclonedx.heading")}
      </h3>
      <p className="text-muted-foreground">{t("posture.cbom.cyclonedx.help")}</p>
      <div className="flex flex-wrap gap-2">
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void download("bom")}>
          {t("posture.cbom.cyclonedx.downloadBom")}
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void download("signed")}>
          {t("posture.cbom.cyclonedx.downloadSigned")}
        </Button>
      </div>
      {message ? <p role="status">{message}</p> : null}
    </section>
  );
}
