import { FormEvent, useEffect, useState } from "react";
import {
  api,
  type PrivacyArchiveErasureAttestation,
  type PrivacyArchiveErasureAttestationRequest,
  type PrivacyCatalog,
  type PrivacyRetentionRun,
  type PrivacySubjectErasure,
  type PrivacySubjectExport,
} from "@/lib/api";

type PrivacyCatalogEntry = PrivacyCatalog["items"][number];
import { PageHeader } from "@/components/PageHeader";
import { SectionCard, DashboardGrid } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { Button } from "@/components/ui/button";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

function countTotal(counts: Record<string, unknown>): number {
  return Object.values(counts).reduce<number>((sum, value) => sum + (typeof value === "number" ? value : 0), 0);
}

type ArchiveAttestationFormState = {
  action: PrivacyArchiveErasureAttestationRequest["action"];
  artifactType: PrivacyArchiveErasureAttestationRequest["artifact_type"];
  subject: string;
  artifactUri: string;
  heldUntil: string;
  reason: string;
  evidenceRefs: string;
};

const defaultArchiveAttestationForm: ArchiveAttestationFormState = {
  action: "deleted",
  artifactType: "backup",
  subject: "",
  artifactUri: "",
  heldUntil: "",
  reason: "",
  evidenceRefs: "",
};

const archiveActionExplanations: Record<PrivacyArchiveErasureAttestationRequest["action"], string> = {
  deleted: "The archived artifact was physically deleted for this subject.",
  legal_hold: "Erasure is deferred: the artifact stays retained under a legal hold until the date below.",
  cryptographic_shred: "The artifact's encryption keys were destroyed, leaving the subject's data unreadable.",
};

function attestationActionTone(action: PrivacyArchiveErasureAttestation["action"]): "success" | "warning" | "info" {
  if (action === "deleted") return "success";
  if (action === "legal_hold") return "warning";
  return "info";
}

const attestationColumns: DataGridColumn<PrivacyArchiveErasureAttestation>[] = [
  { id: "attested", header: "Attested", cell: (attestation) => formatDateTimePolicy(attestation.attested_at) },
  {
    id: "subject",
    header: "Subject",
    cell: (attestation) => (
      <span className="block max-w-[16rem] truncate font-mono text-xs" title={attestation.subject_ref}>
        {attestation.subject_ref}
      </span>
    ),
  },
  {
    id: "action",
    header: "Action",
    cell: (attestation) => (
      <StatusBadge value={attestation.action} label={attestation.action.replace(/_/g, " ")} tone={attestationActionTone(attestation.action)} />
    ),
  },
  { id: "artifactType", header: "Artifact type", cell: (attestation) => attestation.artifact_type.replace(/_/g, " ") },
  {
    id: "artifactUri",
    header: "Artifact URI",
    cell: (attestation) =>
      attestation.artifact_uri ? (
        <span className="block max-w-[16rem] truncate font-mono text-xs" title={attestation.artifact_uri}>
          {attestation.artifact_uri}
        </span>
      ) : (
        <span className="text-muted-foreground">-</span>
      ),
  },
];

/** Privacy is the GDPR/data-governance console over the served-but-previously
 * unsurfaced privacy stack: the data catalog, subject erasure (right to be
 * forgotten), and retention enforcement runs. Every panel reads or writes a
 * real /privacy endpoint; nothing here is a mock or a placeholder. */
export function Privacy() {
  const { t } = useTranslation();
  const { toast } = useToast();
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
  const [attestations, setAttestations] = useState<PrivacyArchiveErasureAttestation[] | null>(null);
  const [attestationCursor, setAttestationCursor] = useState<string | undefined>(undefined);
  const [attestationFilter, setAttestationFilter] = useState("");
  const [attestationBusy, setAttestationBusy] = useState<null | "filter" | "more">(null);
  const [attestationError, setAttestationError] = useState<string | null>(null);
  const [recordOpen, setRecordOpen] = useState(false);
  const [recordBusy, setRecordBusy] = useState(false);
  const [recordError, setRecordError] = useState<string | null>(null);
  const [recordForm, setRecordForm] = useState<ArchiveAttestationFormState>(defaultArchiveAttestationForm);

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

  useEffect(() => {
    let cancelled = false;
    Promise.resolve()
      .then(() => api.privacyArchiveAttestations({ limit: 20 }))
      .then((page) => {
        if (cancelled) return;
        setAttestations(page.items ?? []);
        setAttestationCursor(page.next_cursor);
      })
      .catch(() => null);
    return () => {
      cancelled = true;
    };
  }, []);

  async function applyAttestationFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAttestationBusy("filter");
    setAttestationError(null);
    try {
      const subjectRef = attestationFilter.trim();
      const page = await api.privacyArchiveAttestations({ limit: 20, ...(subjectRef ? { subjectRef } : {}) });
      setAttestations(page.items ?? []);
      setAttestationCursor(page.next_cursor);
    } catch (err) {
      setAttestationError(err instanceof Error ? err.message : String(err));
    } finally {
      setAttestationBusy(null);
    }
  }

  async function loadMoreAttestations() {
    if (!attestationCursor) return;
    setAttestationBusy("more");
    setAttestationError(null);
    try {
      const subjectRef = attestationFilter.trim();
      const page = await api.privacyArchiveAttestations({ limit: 20, cursor: attestationCursor, ...(subjectRef ? { subjectRef } : {}) });
      setAttestations((current) => [...(current ?? []), ...(page.items ?? [])]);
      setAttestationCursor(page.next_cursor);
    } catch (err) {
      setAttestationError(err instanceof Error ? err.message : String(err));
    } finally {
      setAttestationBusy(null);
    }
  }

  function closeRecordDialog() {
    setRecordOpen(false);
    setRecordError(null);
  }

  async function recordArchiveAttestation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!recordForm.subject.trim()) return;
    setRecordBusy(true);
    setRecordError(null);
    try {
      const heldUntilDate = recordForm.heldUntil ? new Date(recordForm.heldUntil) : null;
      const heldUntil = heldUntilDate && !Number.isNaN(heldUntilDate.getTime()) ? heldUntilDate.toISOString() : "";
      const evidenceRefs = recordForm.evidenceRefs
        .split("\n")
        .map((item) => item.trim())
        .filter(Boolean);
      const created = await api.recordPrivacyArchiveAttestation({
        action: recordForm.action,
        artifact_type: recordForm.artifactType,
        subject: recordForm.subject.trim(),
        ...(recordForm.artifactUri.trim() ? { artifact_uri: recordForm.artifactUri.trim() } : {}),
        ...(recordForm.action === "legal_hold" && heldUntil ? { held_until: heldUntil } : {}),
        ...(recordForm.reason.trim() ? { reason: recordForm.reason.trim() } : {}),
        ...(evidenceRefs.length > 0 ? { evidence_refs: evidenceRefs } : {}),
      });
      setAttestations((current) => [created, ...(current ?? [])]);
      setRecordForm(defaultArchiveAttestationForm);
      setRecordOpen(false);
      toast({ kind: "success", title: t("parity.archiveErasureAttestationRecorded_4e1490"), description: created.attestation_id });
    } catch (err) {
      setRecordError(err instanceof Error ? err.message : String(err));
    } finally {
      setRecordBusy(false);
    }
  }

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
        title={t("privacy.title")}
        description={t("privacy.description")}
      />

      {loading ? (
        <LoadingState>{t("privacy.loading")}</LoadingState>
      ) : (
        <>
          <DashboardGrid>
            <StatTile label={t("privacy.stats.catalogEntries")} value={catalog.length} />
            <StatTile label={t("privacy.stats.subjectErasures")} value={erasures.length} />
            <StatTile label={t("privacy.stats.retentionRuns")} value={runs.length} />
          </DashboardGrid>

          {error ? <ErrorState title={t("privacy.error.actionFailed")}>{error}</ErrorState> : null}

          <SectionCard title={t("privacy.erasure.title")} description={t("privacy.erasure.description")}>
            <form onSubmit={submitErasure} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] md:items-end">
              <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-subject">
                {t("privacy.erasure.subjectLabel")}
                <input
                  id="privacy-subject"
                  value={subject}
                  onChange={(event) => setSubject(event.target.value)}
                  placeholder={t("privacy.subjectPlaceholder")}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-reason">
                {t("privacy.erasure.reasonLabel")}
                <input
                  id="privacy-reason"
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder={t("privacy.erasure.reasonPlaceholder")}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <Button type="submit" disabled={busy === "erase" || !subject.trim()}>
                {busy === "erase" ? t("privacy.erasure.busy") : t("privacy.erasure.submit")}
              </Button>
            </form>
            {erasures.length === 0 ? (
              <p className="mt-3 text-caption text-muted-foreground">{t("privacy.erasure.empty")}</p>
            ) : (
              <table className="mt-4 w-full text-sm" aria-label={t("privacy.erasure.tableCaption")}>
                <thead>
                  <tr className="border-b border-border text-left text-caption text-muted-foreground">
                    <th className="py-2 font-medium">{t("privacy.subjectColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.erasure.recordsErasedColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.erasure.reasonLabel")}</th>
                    <th className="py-2 font-medium">{t("privacy.erasure.erasedAtColumn")}</th>
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

          {attestations ? (
            <SectionCard
              title={t("parity.archiveErasureEvidence_9a62ca")}
              description="Attestations that backups and signed audit archives honored a subject erasure: deleted, cryptographically shredded, or held for legal reasons."
              actions={
                <Button type="button" variant="outline" onClick={() => setRecordOpen(true)}>
                  Record attestation…
                </Button>
              }
            >
              <div className="grid gap-3">
                <form onSubmit={(event) => void applyAttestationFilter(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
                  <label className="grid gap-1 text-body font-medium" htmlFor="privacy-archive-subject-filter">
                    {t("parity.subjectFilter_ae9f99")}
                    <input
                      id="privacy-archive-subject-filter"
                      value={attestationFilter}
                      onChange={(event) => setAttestationFilter(event.target.value)}
                      placeholder={t("privacy.subjectPlaceholder")}
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    />
                  </label>
                  <Button type="submit" variant="outline" disabled={attestationBusy === "filter"}>
                    {attestationBusy === "filter" ? "Filtering..." : "Filter"}
                  </Button>
                </form>
                {attestationError ? <ErrorState title={t("parity.archiveAttestationRequestFailed_6179ba")}>{attestationError}</ErrorState> : null}
                <DataGrid
                  ariaLabel="Archive erasure attestations"
                  rows={attestations}
                  columns={attestationColumns}
                  getRowId={(attestation) => attestation.attestation_id}
                  pagination={
                    attestationCursor ? (
                      <div>
                        <Button type="button" size="sm" variant="outline" disabled={attestationBusy === "more"} onClick={() => void loadMoreAttestations()}>
                          {attestationBusy === "more" ? "Loading more attestations..." : "Load more attestations"}
                        </Button>
                      </div>
                    ) : undefined
                  }
                />
              </div>
            </SectionCard>
          ) : null}

          {recordOpen && (
            <Dialog
              open
              onClose={closeRecordDialog}
              titleId="archive-attestation-heading"
              descriptionId="archive-attestation-description"
              className="fixed inset-0 z-50 flex items-center justify-center p-4"
              overlayClassName="absolute inset-0 bg-black/55"
              panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
            >
              <header className="border-b border-border px-5 py-4">
                <h2 id="archive-attestation-heading" className="text-title font-semibold">
                  Record archive erasure attestation
                </h2>
                <p id="archive-attestation-description" className="mt-1 text-sm text-muted-foreground">
                  {t("parity.captureEvidenceOfHowABackup_f00d4e")}
                </p>
              </header>
              <form onSubmit={(event) => void recordArchiveAttestation(event)} className="grid gap-3 p-5">
                {recordError ? <ErrorState title={t("parity.couldNotRecordAttestation_204858")}>{recordError}</ErrorState> : null}
                <label className="grid gap-1 text-body font-medium">
                  Subject
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    value={recordForm.subject}
                    onChange={(event) => setRecordForm({ ...recordForm, subject: event.target.value })}
                    placeholder={t("privacy.subjectPlaceholder")}
                    required
                  />
                </label>
                <div className="grid gap-3 md:grid-cols-2">
                  <label className="grid gap-1 text-body font-medium">
                    Action
                    <select
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={recordForm.action}
                      onChange={(event) =>
                        setRecordForm({ ...recordForm, action: event.target.value as PrivacyArchiveErasureAttestationRequest["action"] })
                      }
                    >
                      <option value="deleted">{t("parity.deleted_b639f5")}</option>
                      <option value="legal_hold">{t("parity.legalHold_644327")}</option>
                      <option value="cryptographic_shred">{t("parity.cryptographicShred_caafb7")}</option>
                    </select>
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    Artifact type
                    <select
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={recordForm.artifactType}
                      onChange={(event) =>
                        setRecordForm({ ...recordForm, artifactType: event.target.value as PrivacyArchiveErasureAttestationRequest["artifact_type"] })
                      }
                    >
                      <option value="backup">{t("parity.backup_89121d")}</option>
                      <option value="signed_audit_archive">{t("parity.signedAuditArchive_753384")}</option>
                    </select>
                  </label>
                </div>
                <p className="text-sm text-muted-foreground">{archiveActionExplanations[recordForm.action]}</p>
                {recordForm.action === "legal_hold" && (
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.heldUntil_8cc7d7")}
                    <input
                      type="datetime-local"
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={recordForm.heldUntil}
                      onChange={(event) => setRecordForm({ ...recordForm, heldUntil: event.target.value })}
                      required
                    />
                  </label>
                )}
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.artifactUri_2088cf")}
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    value={recordForm.artifactUri}
                    onChange={(event) => setRecordForm({ ...recordForm, artifactUri: event.target.value })}
                    placeholder={t("parity.optionalEGS3Backups2026_891da1")}
                  />
                </label>
                <label className="grid gap-1 text-body font-medium">
                  Reason
                  <input
                    className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                    value={recordForm.reason}
                    onChange={(event) => setRecordForm({ ...recordForm, reason: event.target.value })}
                    placeholder="optional"
                  />
                </label>
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.evidenceReferencesOnePerLine_2bb536")}
                  <textarea
                    className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                    value={recordForm.evidenceRefs}
                    onChange={(event) => setRecordForm({ ...recordForm, evidenceRefs: event.target.value })}
                  />
                </label>
                <div className="flex justify-end gap-2">
                  <Button type="button" variant="ghost" onClick={closeRecordDialog}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={recordBusy || !recordForm.subject.trim()}>
                    {recordBusy ? "Recording..." : "Record attestation"}
                  </Button>
                </div>
              </form>
            </Dialog>
          )}

          <SectionCard title={t("privacy.export.title")} description={t("privacy.export.description")}>
            <form onSubmit={submitExport} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
              <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-export-subject">
                {t("privacy.export.subjectLabel")}
                <input
                  id="privacy-export-subject"
                  value={exportSubject}
                  onChange={(event) => setExportSubject(event.target.value)}
                  placeholder={t("privacy.subjectPlaceholder")}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
              <Button type="submit" variant="outline" disabled={exportBusy || !exportSubject.trim()}>
                {exportBusy ? t("privacy.export.busy") : t("privacy.export.submit")}
              </Button>
            </form>
            {exportError ? <ErrorState title={t("privacy.export.failed")}>{exportError}</ErrorState> : null}
            {subjectExport ? (
              <div className="mt-4 grid gap-3">
                <dl className="grid gap-3 text-sm md:grid-cols-3">
                  <div>
                    <dt className="text-caption text-muted-foreground">{t("privacy.subjectColumn")}</dt>
                    <dd className="font-mono text-xs">{subjectExport.subject}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{t("privacy.export.subjectRef")}</dt>
                    <dd className="font-mono text-xs">{subjectExport.subject_ref}</dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{t("privacy.export.generated")}</dt>
                    <dd className="text-sm">{formatDateTimePolicy(subjectExport.generated_at)}</dd>
                  </div>
                </dl>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm" aria-label={t("privacy.export.countsCaption")}>
                    <thead>
                      <tr className="border-b border-border text-left text-caption text-muted-foreground">
                        <th className="py-2 font-medium">{t("privacy.export.recordClassColumn")}</th>
                        <th className="py-2 font-medium">{t("privacy.export.countColumn")}</th>
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
                  {t("privacy.export.summary", { count: countTotal(subjectExport.counts) })}
                </p>
              </div>
            ) : null}
          </SectionCard>

          <SectionCard
            title={t("privacy.retention.title")}
            description={t("privacy.retention.description")}
            actions={
              <Button type="button" variant="outline" onClick={() => void runRetention()} disabled={busy === "retention"}>
                {busy === "retention" ? t("privacy.retention.busy") : t("privacy.retention.submit")}
              </Button>
            }
          >
            {runs.length === 0 ? (
              <p className="text-caption text-muted-foreground">{t("privacy.retention.empty")}</p>
            ) : (
              <table className="w-full text-sm" aria-label={t("privacy.retention.tableCaption")}>
                <thead>
                  <tr className="border-b border-border text-left text-caption text-muted-foreground">
                    <th className="py-2 font-medium">{t("privacy.retention.runColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.retention.recordsAffectedColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.retention.requestedByColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.retention.enforcedAtColumn")}</th>
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

          <SectionCard title={t("privacy.catalog.title")} description={t("privacy.catalog.description")}>
            {catalog.length === 0 ? (
              <p className="text-caption text-muted-foreground">{t("privacy.catalog.empty")}</p>
            ) : (
              <table className="w-full text-sm" aria-label={t("privacy.catalog.title")}>
                <thead>
                  <tr className="border-b border-border text-left text-caption text-muted-foreground">
                    <th className="py-2 font-medium">{t("privacy.catalog.categoryColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.catalog.locationColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.catalog.ownerColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.catalog.purposeColumn")}</th>
                    <th className="py-2 font-medium">{t("privacy.catalog.retentionColumn")}</th>
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
