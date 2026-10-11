import { useRef, useState } from "react";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { api, type SecretImportRequest, type SecretImportResponse } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { translateNow } from "@/i18n/I18nProvider";

type SecretImportReview = {
  fileName: string;
  request: SecretImportRequest;
  names: string[];
  idempotencyKey: string;
};

// JSON.parse keeps only the final spelling of a duplicate object key. Check
// the validated source text too, so the operator's reviewed name list cannot
// differ from the bytes in the selected file before the request is sent.
function rejectDuplicateImportJSONKeys(raw: string): void {
  let index = 0;
  const whitespace = () => {
    while (/\s/.test(raw[index] ?? "") && index < raw.length) index += 1;
  };
  const stringToken = (decode: boolean): string => {
    const start = index;
    index += 1;
    while (index < raw.length) {
      if (raw[index] === "\\") {
        index += 2;
      } else if (raw[index] === '"') {
        index += 1;
        return decode ? (JSON.parse(raw.slice(start, index)) as string) : "";
      } else {
        index += 1;
      }
    }
    throw new Error(translateNow("secrets.import.invalidFile"));
  };
  const value = (): void => {
    whitespace();
    if (raw[index] === "{") {
      index += 1;
      whitespace();
      const seen = new Set<string>();
      while (raw[index] !== "}") {
        const key = stringToken(true);
        if (seen.has(key)) throw new Error(translateNow("secrets.import.duplicateKey"));
        seen.add(key);
        whitespace();
        index += 1; // JSON.parse already validated ':' at this position.
        value();
        whitespace();
        if (raw[index] !== ",") break;
        index += 1;
        whitespace();
      }
      index += 1;
    } else if (raw[index] === "[") {
      index += 1;
      whitespace();
      while (raw[index] !== "]") {
        value();
        whitespace();
        if (raw[index] !== ",") break;
        index += 1;
      }
      index += 1;
    } else if (raw[index] === '"') {
      stringToken(false);
    } else {
      while (index < raw.length && !/[\s,\]}]/.test(raw[index] ?? "")) index += 1;
    }
  };
  value();
}

function parseSecretImportFile(raw: string, fileName: string): SecretImportReview {
  const parsed: unknown = JSON.parse(raw);
  rejectDuplicateImportJSONKeys(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(translateNow("secrets.import.invalidFile"));
  const object = parsed as Record<string, unknown>;
  const prefix = object.prefix === undefined ? "" : object.prefix;
  const values = object.values;
  if (typeof prefix !== "string" || !values || typeof values !== "object" || Array.isArray(values)) {
    throw new Error(translateNow("secrets.import.invalidFile"));
  }
  const entries = Object.entries(values);
  if (entries.length === 0 || entries.length > 100 || entries.some(([name, value]) => !name || typeof value !== "string" || !value)) {
    throw new Error(translateNow("secrets.import.invalidValues"));
  }
  const names = entries.map(([name]) => (prefix ? `${prefix}/${name}` : name)).sort();
  if (names.some((name) => name.length > 512 || name.split("/").some((segment) => !segment || segment === "." || segment === ".."))) {
    throw new Error(translateNow("secrets.import.invalidNames"));
  }
  return {
    fileName,
    request: { prefix, values: Object.fromEntries(entries) },
    names,
    idempotencyKey: newIdempotencyKey(),
  };
}

export function SecretImport({ reason, safePath, onImported }: { reason?: string; safePath?: string; onImported?: () => void } = {}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [review, setReview] = useState<SecretImportReview | null>(null);
  const [receipt, setReceipt] = useState<SecretImportResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function selectFile(file: File | undefined) {
    setReview(null);
    setReceipt(null);
    setError(null);
    if (!file) return;
    if (file.size > 1024 * 1024) {
      setError(translateNow("secrets.import.fileTooLarge"));
      return;
    }
    try {
      const raw = await file.text();
      setReview(parseSecretImportFile(raw, file.name));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : translateNow("secrets.import.invalidFile"));
    }
  }

  async function execute() {
    if (!review || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.importSecrets(review.request, review.idempotencyKey);
      setReceipt(result);
      setReview(null);
      if (fileRef.current) fileRef.current.value = "";
      onImported?.();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SectionCard title={translateNow("secrets.import.title")} description={translateNow("secrets.import.description")}>
      <p className="text-body text-muted-foreground">{translateNow("secrets.import.body")}</p>
      {reason ? <p className="mt-2 text-body text-muted-foreground">{reason}</p> : null}
      {safePath ? <p className="mt-2 text-body text-muted-foreground">{safePath}</p> : null}
      <label className="mt-3 grid gap-1 text-body">
        <span className="font-medium">{translateNow("secrets.import.chooseFile")}</span>
        <input ref={fileRef} type="file" accept=".json,application/json" onChange={(event) => void selectFile(event.target.files?.[0])} />
      </label>
      {review ? (
        <div role="status" className="mt-3 rounded-control border border-border p-3">
          <p className="font-medium">{translateNow("secrets.import.review", { count: String(review.names.length), file: review.fileName })}</p>
          <p className="mt-1 text-caption text-muted-foreground">{translateNow("secrets.import.atomicWarning")}</p>
          <ul className="mt-2 max-h-44 overflow-auto text-caption">
            {review.names.map((name) => (
              <li key={name} className="break-all font-mono">
                {name}
              </li>
            ))}
          </ul>
          <Button type="button" className="mt-3" disabled={busy} onClick={() => void execute()}>
            {busy ? translateNow("secrets.import.importing") : translateNow("secrets.import.execute")}
          </Button>
        </div>
      ) : null}
      {receipt ? (
        <div role="status" className="mt-3 rounded-control border border-status-success/30 bg-status-success/10 p-3 text-body">
          <p className="font-medium">
            {translateNow(receipt.count === 1 ? "secrets.import.completedOne" : "secrets.import.completed", { count: String(receipt.count) })}
          </p>
          <p className="mt-1 break-all font-mono text-caption">{receipt.batch_id}</p>
          <ul className="mt-2 text-caption">
            {receipt.items.map((item) => (
              <li key={item.name}>{translateNow("secrets.import.itemVersion", { name: item.name, version: String(item.version) })}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="mt-2 text-body text-risk-critical">
          {error}
        </p>
      ) : null}
    </SectionCard>
  );
}
