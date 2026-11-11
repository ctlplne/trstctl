// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CBOMImport, type CBOMInventory } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";

const sourceKinds = ["vendor", "source", "image"] as const;

// The file's text exactly as chosen.
function readText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error("the file could not be read"));
    reader.readAsText(file);
  });
}
type SourceKind = (typeof sourceKinds)[number];

const sourceKindLabel = {
  vendor: "posture.cbom.import.kind.vendor",
  source: "posture.cbom.import.kind.source",
  image: "posture.cbom.import.kind.image",
} as const;

// X6-L4: import a CycloneDX CBOM (a vendor's, a source scan's or an image
// scan's) into the crypto inventory. The file is sent exactly as chosen, so
// importing the same file again changes nothing; one idempotency key covers
// a request until it succeeds or its inputs change.
export function CBOMImportPanel({ onImported }: { onImported: (result: CBOMImport, inventory: CBOMInventory) => void }) {
  const { t } = useTranslation();
  const [kind, setKind] = useState<SourceKind>("vendor");
  const [name, setName] = useState("");
  const [file, setFile] = useState<{ name: string; text: string } | null>(null);
  const [key, setKey] = useState(() => newIdempotencyKey());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CBOMImport | null>(null);

  function changed() {
    setKey(newIdempotencyKey());
    setResult(null);
    setError(null);
  }

  async function choose(files: FileList | null) {
    changed();
    const chosen = files?.[0];
    setFile(chosen ? { name: chosen.name, text: await readText(chosen) } : null);
  }

  async function importFile() {
    if (!file || !name.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const imported = await api.importCBOM(`${kind}:${name.trim()}`, file.text, key);
      setResult(imported);
      setKey(newIdempotencyKey());
      onImported(imported, await api.listCBOMAssets());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="cbom-import-heading" className="grid gap-3 rounded-panel border border-border bg-card p-4">
      <div>
        <h3 id="cbom-import-heading" className="font-semibold">
          {t("posture.cbom.import.title")}
        </h3>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("posture.cbom.import.description")}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <Field label={t("posture.cbom.import.kind")} controlId="cbom-import-kind">
          {(control) => (
            <Select
              {...control}
              value={kind}
              onChange={(event) => {
                changed();
                setKind(event.target.value as SourceKind);
              }}
            >
              {sourceKinds.map((value) => (
                <option key={value} value={value}>
                  {t(sourceKindLabel[value])}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("posture.cbom.import.name")} controlId="cbom-import-name" description={t("posture.cbom.import.nameHelp")}>
          {(control) => (
            <Input
              {...control}
              value={name}
              onChange={(event) => {
                changed();
                setName(event.target.value);
              }}
            />
          )}
        </Field>
        <Field label={t("posture.cbom.import.file")} controlId="cbom-import-file">
          {(control) => <input {...control} type="file" accept=".json,application/json" onChange={(event) => void choose(event.target.files)} />}
        </Field>
      </div>
      <div>
        <Button type="button" loading={busy} disabled={busy || !file || !name.trim()} onClick={() => void importFile()}>
          {t("posture.cbom.import.submit")}
        </Button>
      </div>
      {error ? (
        <p role="alert" className="text-sm text-status-danger">
          {error}
        </p>
      ) : null}
      {result ? (
        <p role="status" className="text-sm">
          {result.replayed
            ? t("posture.cbom.import.replayed", { source: result.source, version: String(result.version) })
            : t("posture.cbom.import.imported", {
                source: result.source,
                components: String(result.components),
                findings: String(result.findings),
                version: String(result.version),
                run: result.run_id,
              })}
        </p>
      ) : null}
    </section>
  );
}
