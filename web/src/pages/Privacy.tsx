import { FormEvent, useEffect, useState } from "react";
import { api, type PrivacyCatalog, type PrivacyRetentionRun, type PrivacySubjectErasure, type PrivacySubjectExport } from "@/lib/api";

type PrivacyCatalogEntry = PrivacyCatalog["items"][number];
import { PageHeader } from "@/components/PageHeader";
import { SectionCard, DashboardGrid } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

function countTotal(counts: Record<string, unknown>): number {
  return Object.values(counts).reduce<number>((sum, value) => sum + (typeof value === "number" ? value : 0), 0);
}

/** Privacy is the GDPR/data-governance console over the served-but-previously
 * unsurfaced privacy stack: the data catalog, subject erasure (right to be
 * forgotten), and retention enforcement runs. Every panel reads or writes a
 * real /privacy endpoint; nothing here is a mock or a placeholder. */
export function Privacy() {
  const [catalog, setCatalog] = useState<PrivacyCatalogEntry[]>([]);
  const [erasures, setErasures] = useState<PrivacySubjectErasure[]>([]);
  const [runs, setRuns] = useState<PrivacyRetentionRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [subject, setSubject] = useState("");
  const [reason, setReason] = useState("");
  const [exportSubject, setExportSubject] = useState("");
  const [subjectExport, setSubjectExport] = useState<PrivacySubjectExport | null>(null);
  const [busy, setBusy] = useState<null | "erase" | "retention">(null);
  const [exportBusy, setExportBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([api.privacyCatalog(), api.privacySubjectErasures({ limit: 50 }), api.privacyRetentionRuns({ limit: 50 })]).then((results) => {
      if (cancelled) return;
      const [catalogResult, erasureResult, runResult] = results;
      if (catalogResult.status === "fulfilled") setCatalog(catalogResult.value.items ?? []);
      if (erasureResult.status === "fulfilled") setErasures(erasureResult.value.items ?? []);
      if (runResult.status === "fulfilled") setRuns(runResult.value.items ?? []);
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function submitErasure(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!subject.trim()) return;
    setBusy("erase");
    setError(null);
    try {
      const result = await api.erasePrivacySubject({ subject: subject.trim(), reason: reason.trim() || undefined });
      setErasures((current) => [result, ...current]);
      setSubject("");
      setReason("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function runRetention() {
    setBusy("retention");
    setError(null);
    try {
      const run = await api.enforcePrivacyRetention();
      setRuns((current) => [run, ...current]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function submitExport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!exportSubject.trim()) return;
    setExportBusy(true);
    setExportError(null);
    try {
      setSubjectExport(await api.exportPrivacySubject({ subject: exportSubject.trim() }));
      setExportSubject("");
    } catch (err) {
      setExportError(err instanceof Error ? err.message : String(err));
    } finally {
      setExportBusy(false);
    }
  }

  return (
    <section aria-labelledby="privacy-heading" className="grid gap-6">
      <PageHeader
        titleId="privacy-heading"
        title="Privacy & data governance"
        description="Privacy & GDPR controls: inventory the kinds of personal data you hold, honor erasure requests (right to be forgotten), and enforce data-retention schedules."
      />

      {loading ? (
        <LoadingState>Loading privacy posture…</LoadingState>
      ) : (
        <>
          <DashboardGrid>
            <StatTile label="Catalog entries" value={catalog.length} />
            <StatTile label="Subject erasures" value={erasures.length} />
            <StatTile label="Retention runs" value={runs.length} />
          </DashboardGrid>

          {error ? <ErrorState title="Privacy action failed">{error}</ErrorState> : null}

          <SectionCard title="Subject erasure" description="Right to be forgotten — erase every credential and record tied to a data subject.">
            <form onSubmit={submitErasure} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] md:items-end">
              <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-subject">
                Data subject
                <input
                  id="privacy-subject"
                  value={subject}
                  onChange={(event) => setSubject(event.target.value)}
                  placeholder="owner id, email, or subject ref"
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-reason">
                Reason
                <input
                  id="privacy-reason"
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder="optional — recorded on the erasure"
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <Button type="submit" disabled={busy === "erase" || !subject.trim()}>
                {busy === "erase" ? "Erasing…" : "Erase subject"}
              </Button>
            </form>
            {erasures.length === 0 ? (
              <p className="mt-3 text-caption text-muted-foreground">No subject erasures recorded yet.</p>
            ) : (
              <table className="mt-4 w-full text-sm" aria-label="Recent subject erasures">
                <thead>
                  <tr className="border-b border-border text-left text-caption text-muted-foreground">
                    <th className="py-2 font-medium">Subject</th>
                    <th className="py-2 font-medium">Records erased</th>
                    <th className="py-2 font-medium">Reason</th>
                    <th className="py-2 font-medium">Erased at</th>
                  </tr>
                </thead>
                <tbody>
                  {erasures.map((erasure, index) => (
                    <tr key={`${erasure.subject_ref}-${index}`} className="border-b border-border/60 align-top">
                      <td className="py-2 font-mono text-caption">{erasure.subject_ref}</td>
                      <td className="py-2 tabular-nums">{countTotal(erasure.counts)}</td>
                      <td className="py-2 text-muted-foreground">{erasure.reason || "—"}</td>
                      <td className="py-2 text-muted-foreground">{formatDateTimePolicy(erasure.erased_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </SectionCard>

          <SectionCard title="Subject export" description="Access and portability workflow for every cataloged record tied to a data subject.">
            <form onSubmit={submitExport} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
              <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-export-subject">
                Data subject
                <input
                  id="privacy-export-subject"
                  value={exportSubject}
                  onChange={(event) => setExportSubject(event.target.value)}
                  placeholder="owner id, email, or subject ref"
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <Button type="submit" variant="outline" disabled={exportBusy || !exportSubject.trim()}>
                {exportBusy ? "Exporting..." : "Export subject"}
              </Button>
            </form>
            {exportError ? <ErrorState title="Subject export failed">{exportError}</ErrorState> : null}
            {subjectExport ? (
              <div className="mt-4 grid gap-3">
                <dl className="grid gap-3 text-sm md:grid-cols-3">
                  <div>
                    <dt className="text-caption text-muted-foreground">Subject</dt>
                    <dd className="font-mono text-xs">{subjectExport.subject}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">Subject ref</dt>
                    <dd className="font-mono text-xs">{subjectExport.subject_ref}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">Generated</dt>
                    <dd className="text-sm">{formatDateTimePolicy(subjectExport.generated_at)}</dd>
                  </div>
                </dl>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm" aria-label="Subject export counts">
                    <thead>
                      <tr className="border-b border-border text-left text-caption text-muted-foreground">
                        <th className="py-2 font-medium">Record class</th>
                        <th className="py-2 font-medium">Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(subjectExport.counts).map(([name, value]) => (
                        <tr key={name} className="border-b border-border/60">
                          <td className="py-2 font-mono text-caption">{name}</td>
                          <td className="py-2 tabular-nums">{typeof value === "number" ? value : String(value)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="text-caption text-muted-foreground">
                  Exported {countTotal(subjectExport.counts)} cataloged record references. Secret values and token material are not rendered.
                </p>
              </div>
            ) : null}
          </SectionCard>

          <SectionCard
            title="Retention enforcement"
            description="Apply the retention policy across credentials, owners, agents, and evidence — each run records its cutoffs."
            actions={
              <Button type="button" variant="outline" onClick={() => void runRetention()} disabled={busy === "retention"}>
                {busy === "retention" ? "Enforcing…" : "Enforce retention now"}
              </Button>
            }
          >
            {runs.length === 0 ? (
              <p className="text-caption text-muted-foreground">No retention runs recorded yet.</p>
            ) : (
              <table className="w-full text-sm" aria-label="Retention runs">
                <thead>
                  <tr className="border-b border-border text-left text-caption text-muted-foreground">
                    <th className="py-2 font-medium">Run</th>
                    <th className="py-2 font-medium">Records affected</th>
                    <th className="py-2 font-medium">Requested by</th>
                    <th className="py-2 font-medium">Enforced at</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run) => (
                    <tr key={run.run_id} className="border-b border-border/60 align-top">
                      <td className="py-2 font-mono text-caption">{run.run_id}</td>
                      <td className="py-2 tabular-nums">{countTotal(run.counts)}</td>
                      <td className="py-2 text-muted-foreground">{run.requested_by_ref || "system"}</td>
                      <td className="py-2 text-muted-foreground">{formatDateTimePolicy(run.enforced_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </SectionCard>

          <SectionCard title="Personal-data catalog" description="What personal data lives where, who owns it, why it is held, and how it is erased.">
            {catalog.length === 0 ? (
              <p className="text-caption text-muted-foreground">No catalog entries returned.</p>
            ) : (
              <table className="w-full text-sm" aria-label="Personal-data catalog">
                <thead>
                  <tr className="border-b border-border text-left text-caption text-muted-foreground">
                    <th className="py-2 font-medium">Category</th>
                    <th className="py-2 font-medium">Location</th>
                    <th className="py-2 font-medium">Owner</th>
                    <th className="py-2 font-medium">Purpose</th>
                    <th className="py-2 font-medium">Retention</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.map((entry) => (
                    <tr key={entry.id} className="border-b border-border/60 align-top">
                      <td className="py-2">{entry.category}</td>
                      <td className="py-2 font-mono text-caption">{entry.location}</td>
                      <td className="py-2 text-muted-foreground">{entry.owner}</td>
                      <td className="py-2 text-muted-foreground">{entry.purpose}</td>
                      <td className="py-2 text-muted-foreground">{entry.retention_class}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </SectionCard>
        </>
      )}
    </section>
  );
}
