import { useRef, useState } from "react";
import { api, type OwnershipImportResult } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useQueryClient } from "@/lib/query";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";

const maxCSVBytes = 8 * 1024 * 1024;

type ReviewedCSV = { name: string; bytes: number; body: string; idempotencyKey: string };

function readCSV(file: File): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error(translateNow("owners.import.readFailed")));
    reader.readAsText(file);
  });
}

// The browser shows the exact selected file before a write. A failed or lost
// response keeps the same bytes and idempotency key, so retry asks for the same
// operation rather than generating a second import decision.
export function OwnershipCSVImport() {
  const canWrite = useCan("owners:write");
  const queryClient = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [review, setReview] = useState<ReviewedCSV | null>(null);
  const [result, setResult] = useState<OwnershipImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function select(file?: File) {
    setReview(null);
    setResult(null);
    setError(null);
    if (!file) return;
    if (file.size > maxCSVBytes) {
      setError(translateNow("owners.import.tooLarge"));
      return;
    }
    try {
      const body = await readCSV(file);
      if (!body.trim()) {
        setError(translateNow("owners.import.empty"));
        return;
      }
      setReview({ name: file.name, bytes: file.size, body, idempotencyKey: newIdempotencyKey() });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : translateNow("owners.import.readFailed"));
    }
  }

  async function apply() {
    if (!review || busy) return;
    setBusy(true);
    setError(null);
    try {
      const receipt = await api.importOwnership(review.body, review.idempotencyKey);
      setResult(receipt);
      setReview(null);
      if (input.current) input.current.value = "";
      for (const key of ["owners", "ownership-attribution", "ownership-conflicts", "unowned-identities"]) {
        void queryClient.invalidateQueries({ queryKey: [key] });
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  if (!canWrite) return null;
  return (
    <section aria-labelledby="ownership-import-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="ownership-import-heading" className="text-title font-semibold">
        {translateNow("owners.import.title")}
      </h2>
      <p className="text-sm text-muted-foreground">{translateNow("owners.import.description")}</p>
      <label className="grid gap-1 text-body font-medium">
        {translateNow("owners.import.chooseFile")}
        <input ref={input} type="file" accept=".csv,text/csv" onChange={(event) => void select(event.target.files?.[0])} />
      </label>
      {review && (
        <div role="status" className="space-y-2 rounded-control border border-border p-3 text-sm">
          <p>{translateNow("owners.import.review", { name: review.name, bytes: String(review.bytes) })}</p>
          <p className="text-muted-foreground">{translateNow("owners.import.effect")}</p>
          <Button type="button" disabled={busy} onClick={() => void apply()}>
            {busy ? translateNow("owners.import.applying") : translateNow("owners.import.apply")}
          </Button>
        </div>
      )}
      {result && (
        <div role="status" className="space-y-2 rounded-control border border-status-success/30 bg-status-success/10 p-3 text-sm">
          <p>
            {result.conflicts.length === 1
              ? translateNow("owners.import.resultOne", { applied: String(result.applied), unchanged: String(result.unchanged) })
              : translateNow("owners.import.resultMany", {
                  applied: String(result.applied),
                  unchanged: String(result.unchanged),
                  conflicts: String(result.conflicts.length),
                })}
          </p>
          {result.conflicts.length > 0 && <p>{translateNow("owners.import.reviewConflicts")}</p>}
          <p className="text-muted-foreground">{result.guidance}</p>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-risk-critical">
          {error}
        </p>
      )}
    </section>
  );
}
