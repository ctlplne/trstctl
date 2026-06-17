import { useState } from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { useResource } from "@/lib/useResource";

export function Audit() {
  const { data, loading, error } = useResource(api.auditEvents);
  const [bundle, setBundle] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function exportEvidence() {
    setBusy(true);
    setExportError(null);
    try {
      const out = await api.exportAudit();
      setBundle(`${out.format}: ${out.bundle}`);
    } catch (err) {
      setExportError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="audit-heading">
      <div className="mb-4 flex items-center justify-between">
        <h1 id="audit-heading" className="text-2xl font-semibold">
          Audit
        </h1>
        <Button type="button" onClick={() => void exportEvidence()} disabled={busy}>
          Export evidence
        </Button>
      </div>

      {loading && <p role="status">Loading audit events...</p>}
      {error && <p role="alert">Could not load audit events: {error}</p>}
      {exportError && <p role="alert">Could not export evidence: {exportError}</p>}
      {bundle && <p className="mb-3 break-all rounded-md border border-border p-3 text-sm">{bundle}</p>}

      {data && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Tenant audit events</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pr-4 font-medium">Sequence</th>
              <th scope="col" className="py-2 pr-4 font-medium">Type</th>
              <th scope="col" className="py-2 pr-4 font-medium">Time</th>
              <th scope="col" className="py-2 font-medium">Hash</th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr>
                <td colSpan={4} className="py-4 text-muted-foreground">No audit events returned.</td>
              </tr>
            )}
            {data.map((event) => (
              <tr key={event.id ?? `${event.sequence}:${event.type}`} className="border-b border-border">
                <td className="py-2 pr-4">{event.sequence}</td>
                <td className="py-2 pr-4">{event.type}</td>
                <td className="py-2 pr-4">{event.time}</td>
                <td className="py-2 font-mono text-xs">{event.hash ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
