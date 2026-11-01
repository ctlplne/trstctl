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

// Q3: the crypto inventory as a signed CycloneDX 1.6 CBOM. "CycloneDX CBOM"
// saves the BOM a scanner or an agency ingests; "Signed export" saves it with
// its signature for offline verification (trstctl cbom verify-cyclonedx).
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
      setMessage(t("posture.cbom.cyclonedx.saved", { components: exported.components }));
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
