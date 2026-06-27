import { useState } from "react";
import { runBulk, type BulkResult } from "@/lib/bulk";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";

export interface BulkTarget {
  id: string;
  label: string;
}

/** BulkActionRunner applies the U0-6 bulk primitive (runBulk) to a set of
 * selected inventory rows — bulk renew / revoke / rotate — and renders a
 * per-item result so a partial failure is visible row-by-row instead of one
 * opaque "some failed". The action is idempotent at the orchestrator (AN-5),
 * so a retried fan-out is safe. */
export function BulkActionRunner({ targets, actionLabel, action }: { targets: BulkTarget[]; actionLabel: string; action: (id: string) => Promise<unknown> }) {
  const [results, setResults] = useState<BulkResult<unknown>[] | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setResults(null);
    const res = await runBulk(
      targets.map((target) => target.id),
      action,
    );
    setResults(res);
    setBusy(false);
  }

  const labelFor = (id: string) => targets.find((target) => target.id === id)?.label ?? id;

  return (
    <SectionCard
      title={actionLabel}
      description="Fan out an idempotent mutation across the selected rows; each row reports its own success or failure."
      actions={
        <Button type="button" onClick={() => void run()} disabled={busy || targets.length === 0}>
          {busy ? "Running…" : `${actionLabel} (${targets.length})`}
        </Button>
      }
    >
      {results ? (
        <table className="w-full text-sm" aria-label="Bulk action results">
          <thead>
            <tr className="border-b border-border text-left text-caption text-muted-foreground">
              <th className="py-2 font-medium">Row</th>
              <th className="py-2 font-medium">Result</th>
              <th className="py-2 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => (
              <tr key={result.id} className="border-b border-border/60 align-top">
                <td className="py-2">{labelFor(result.id)}</td>
                <td className="py-2">
                  <StatusBadge vocabulary="risk" value={result.ok ? "low" : "critical"} />
                </td>
                <td className="py-2 text-muted-foreground">{result.ok ? "applied" : result.error}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-caption text-muted-foreground">Select rows and run a bulk action to see per-row results.</p>
      )}
    </SectionCard>
  );
}
