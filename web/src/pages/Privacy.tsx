/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- Native-table overflow viewports must be focusable so keyboard users can reach and scroll clipped privacy columns. */
import { FormEvent, useRef, useState, type ReactNode, type RefObject } from "react";
import {
  api,
  type PrivacyArchiveErasureAttestation,
  type PrivacyArchiveErasureAttestationRequest,
  type PrivacyCatalog,
  type PrivacyRetentionPreview,
  type PrivacyRetentionRun,
  type PrivacySubjectErasure,
  type PrivacySubjectErasurePreview,
  type PrivacySubjectExport,
} from "@/lib/api";

type PrivacyCatalogEntry = PrivacyCatalog["items"][number];
import { PageHeader } from "@/components/PageHeader";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

function countTotal(counts: Record<string, unknown>): number {
  return Object.values(counts).reduce<number>((sum, value) => sum + (typeof value === "number" ? value : 0), 0);
}

const subjectAggregateClasses = [
  "owners",
  "identities",
  "certificates",
  "ssh_keys",
  "attestations",
  "approval_requests",
  "approvals",
  "profiles",
  "agents",
  "agent_offboard_actors",
  "agent_offboard_reasons",
  "api_tokens",
  "tenant_members",
  "code_signing_operations",
  "read_models",
] as const;

function countSubjectRecords(counts: Record<string, unknown>): number {
  return subjectAggregateClasses.reduce((sum, name) => {
    const value = counts[name];
    return sum + (typeof value === "number" ? value : 0);
  }, 0);
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

type PrivacyDisclosure = "policy" | "subjects" | "archives" | "retention";

const closedDisclosures: Record<PrivacyDisclosure, boolean> = {
  policy: false,
  subjects: false,
  archives: false,
  retention: false,
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

/** Privacy answers the evidence boundary first, then loads each exact policy or
 * subject-control surface only when the operator asks for it. Every disclosed
 * panel still reads or writes a real /privacy endpoint; nothing is a mock. */
export function Privacy() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [catalog, setCatalog] = useState<PrivacyCatalogEntry[]>([]);
  const [erasures, setErasures] = useState<PrivacySubjectErasure[]>([]);
  const [runs, setRuns] = useState<PrivacyRetentionRun[]>([]);
  const [open, setOpen] = useState<Record<PrivacyDisclosure, boolean>>(closedDisclosures);
  const [loaded, setLoaded] = useState<Record<PrivacyDisclosure, boolean>>(closedDisclosures);
  const [loading, setLoading] = useState<Record<PrivacyDisclosure, boolean>>(closedDisclosures);
  const [loadErrors, setLoadErrors] = useState<Partial<Record<PrivacyDisclosure, string>>>({});
  const requested = useRef(new Set<PrivacyDisclosure>());
  const policyDisclosureRef = useRef<HTMLDetailsElement>(null);
  const [subject, setSubject] = useState("");
  const [reason, setReason] = useState("");
  const [exportSubject, setExportSubject] = useState("");
  const [subjectExport, setSubjectExport] = useState<PrivacySubjectExport | null>(null);
  const [erasurePreview, setErasurePreview] = useState<PrivacySubjectErasurePreview | null>(null);
  const [retentionPreview, setRetentionPreview] = useState<PrivacyRetentionPreview | null>(null);
  const [reviewBusy, setReviewBusy] = useState<null | "erase" | "retention">(null);
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

  async function loadDisclosure(disclosure: PrivacyDisclosure) {
    if (requested.current.has(disclosure)) return;
    requested.current.add(disclosure);
    setLoading((current) => ({ ...current, [disclosure]: true }));
    setLoadErrors((current) => ({ ...current, [disclosure]: undefined }));
    try {
      if (disclosure === "policy") {
        const page = await api.privacyCatalog();
        setCatalog(page.items ?? []);
      } else if (disclosure === "subjects") {
        const page = await api.privacySubjectErasures({ limit: 50 });
        setErasures(page.items ?? []);
      } else if (disclosure === "archives") {
        const page = await api.privacyArchiveAttestations({ limit: 20 });
        setAttestations(page.items ?? []);
        setAttestationCursor(page.next_cursor);
      } else {
        const page = await api.privacyRetentionRuns({ limit: 50 });
        setRuns(page.items ?? []);
      }
      setLoaded((current) => ({ ...current, [disclosure]: true }));
    } catch (err) {
      requested.current.delete(disclosure);
      setLoadErrors((current) => ({ ...current, [disclosure]: err instanceof Error ? err.message : String(err) }));
    } finally {
      setLoading((current) => ({ ...current, [disclosure]: false }));
    }
  }

  function toggleDisclosure(disclosure: PrivacyDisclosure, value: boolean) {
    setOpen((current) => ({ ...current, [disclosure]: value }));
    if (value) void loadDisclosure(disclosure);
  }

  function reviewPolicy() {
    setOpen((current) => ({ ...current, policy: true }));
    void loadDisclosure("policy");
    requestAnimationFrame(() => policyDisclosureRef.current?.querySelector<HTMLElement>("summary")?.focus());
  }

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
    setReviewBusy("erase");
    setError(null);
    try {
      setErasurePreview(await api.previewPrivacySubjectErasure({ subject: subject.trim(), reason: reason.trim() || undefined }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setReviewBusy(null);
    }
  }

  async function executeErasure() {
    if (!erasurePreview?.ready) return;
    setBusy("erase");
    setError(null);
    try {
      const result = await api.erasePrivacySubject(erasurePreview.normalized_request);
      setErasures((current) => [result, ...current]);
      setSubject("");
      setReason("");
      setErasurePreview(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function runRetention() {
    setReviewBusy("retention");
    setError(null);
    try {
      setRetentionPreview(await api.previewPrivacyRetention());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setReviewBusy(null);
    }
  }

  async function executeRetention() {
    if (!retentionPreview?.ready) return;
    setBusy("retention");
    setError(null);
    try {
      const run = await api.enforcePrivacyRetention();
      setRuns((current) => [run, ...current]);
      setRetentionPreview(null);
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
    <section aria-labelledby="privacy-heading" className="grid min-w-0 gap-6">
      <PageHeader
        titleId="privacy-heading"
        title={t("privacy.title")}
        description={t("privacy.description")}
        technicalDetails={t("privacy.design.technicalDetails")}
        actions={
          <Button type="button" onClick={reviewPolicy}>
            {t("privacy.design.primaryAction")}
          </Button>
        }
      />

      <section aria-labelledby="privacy-boundary-heading" className="ui-panel grid gap-4 p-comfortable">
        <div className="grid gap-1">
          <h2 id="privacy-boundary-heading" className="text-title font-semibold">
            {t("privacy.design.summaryTitle")}
          </h2>
          <p className="max-w-3xl text-body text-muted-foreground">{t("privacy.design.summaryDescription")}</p>
        </div>
        <dl className="grid gap-3 sm:grid-cols-3">
          <PrivacyFact label={t("privacy.design.accessLabel")} value="privacy:read" />
          <PrivacyFact label={t("privacy.design.retentionLabel")} value={t("privacy.design.retentionValue")} />
          <PrivacyFact label={t("privacy.design.removalLabel")} value={t("privacy.design.removalValue")} />
        </dl>
      </section>

      {error ? <ErrorState title={t("privacy.error.actionFailed")}>{error}</ErrorState> : null}

      <PrivacyDisclosurePanel
        detailsRef={policyDisclosureRef}
        title={t("privacy.design.disclosure.policy")}
        open={open.policy}
        onToggle={(value) => toggleDisclosure("policy", value)}
      >
        {loading.policy ? <LoadingState>{t("privacy.loading")}</LoadingState> : null}
        {loadErrors.policy ? <ErrorState title={t("privacy.error.actionFailed")}>{loadErrors.policy}</ErrorState> : null}
        {loaded.policy ? (
          <SectionCard title={t("privacy.catalog.title")} description={t("privacy.catalog.description")}>
            {catalog.length === 0 ? (
              <p className="text-caption text-muted-foreground">{t("privacy.catalog.empty")}</p>
            ) : (
              <div className="overflow-x-auto" role="region" aria-label={t("privacy.design.catalogScrollArea")} tabIndex={0}>
                <table className="w-full min-w-[56rem] text-sm" aria-label={t("privacy.catalog.title")}>
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
              </div>
            )}
          </SectionCard>
        ) : null}
      </PrivacyDisclosurePanel>

      <PrivacyDisclosurePanel title={t("privacy.design.disclosure.subjects")} open={open.subjects} onToggle={(value) => toggleDisclosure("subjects", value)}>
        {loading.subjects ? <LoadingState>{t("privacy.loading")}</LoadingState> : null}
        {loadErrors.subjects ? <ErrorState title={t("privacy.error.actionFailed")}>{loadErrors.subjects}</ErrorState> : null}
        {loaded.subjects ? (
          <div className="grid gap-4">
            <SectionCard title={t("privacy.erasure.title")} description={t("privacy.erasure.description")}>
              <form onSubmit={submitErasure} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] md:items-end">
                <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-subject">
                  {t("privacy.erasure.subjectLabel")}
                  <input
                    id="privacy-subject"
                    value={subject}
                    onChange={(event) => {
                      setSubject(event.target.value);
                      setErasurePreview(null);
                    }}
                    placeholder={t("privacy.subjectPlaceholder")}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </label>
                <label className="grid gap-1 text-sm font-medium" htmlFor="privacy-reason">
                  {t("privacy.erasure.reasonLabel")}
                  <input
                    id="privacy-reason"
                    value={reason}
                    onChange={(event) => {
                      setReason(event.target.value);
                      setErasurePreview(null);
                    }}
                    placeholder={t("privacy.erasure.reasonPlaceholder")}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </label>
                <Button type="submit" disabled={reviewBusy === "erase" || busy === "erase" || !subject.trim()}>
                  {reviewBusy === "erase" ? t("privacy.review.reviewing") : t("privacy.review.erasureAction")}
                </Button>
              </form>
              {erasures.length === 0 ? (
                <p className="mt-3 text-caption text-muted-foreground">{t("privacy.erasure.empty")}</p>
              ) : (
                <div className="mt-4 overflow-x-auto" role="region" aria-label={t("privacy.design.erasureScrollArea")} tabIndex={0}>
                  <table className="w-full min-w-[42rem] text-sm" aria-label={t("privacy.erasure.tableCaption")}>
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
                          <td className="py-2 tabular-nums">{countSubjectRecords(erasure.counts)}</td>
                          <td className="py-2 text-muted-foreground">{erasure.reason || "—"}</td>
                          <td className="py-2 text-muted-foreground">{formatDateTimePolicy(erasure.erased_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </SectionCard>
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
                  <div className="overflow-x-auto" role="region" aria-label={t("privacy.design.exportScrollArea")} tabIndex={0}>
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
                  <p className="text-caption text-muted-foreground">{t("privacy.export.summary", { count: countSubjectRecords(subjectExport.counts) })}</p>
                </div>
              ) : null}
            </SectionCard>
          </div>
        ) : null}
      </PrivacyDisclosurePanel>

      <PrivacyDisclosurePanel title={t("privacy.design.disclosure.archives")} open={open.archives} onToggle={(value) => toggleDisclosure("archives", value)}>
        {loading.archives ? <LoadingState>{t("privacy.loading")}</LoadingState> : null}
        {loadErrors.archives ? <ErrorState title={t("privacy.error.actionFailed")}>{loadErrors.archives}</ErrorState> : null}
        {loaded.archives && attestations ? (
          <SectionCard
            title={t("parity.archiveErasureEvidence_9a62ca")}
            description={t("privacy.design.archiveDescription")}
            actions={
              <Button type="button" variant="outline" onClick={() => setRecordOpen(true)}>
                {t("privacy.design.recordAttestation")}
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
                  {attestationBusy === "filter" ? translateNow("source.filtering.5bdc12007f") : translateNow("source.filter.638e249f4a")}
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
                        {attestationBusy === "more"
                          ? translateNow("source.loading.more.attestations.c82824a63c")
                          : translateNow("source.load.more.attestations.fa509be818")}
                      </Button>
                    </div>
                  ) : undefined
                }
              />
            </div>
          </SectionCard>
        ) : null}
      </PrivacyDisclosurePanel>

      <PrivacyDisclosurePanel title={t("privacy.design.disclosure.retention")} open={open.retention} onToggle={(value) => toggleDisclosure("retention", value)}>
        {loading.retention ? <LoadingState>{t("privacy.loading")}</LoadingState> : null}
        {loadErrors.retention ? <ErrorState title={t("privacy.error.actionFailed")}>{loadErrors.retention}</ErrorState> : null}
        {loaded.retention ? (
          <SectionCard
            title={t("privacy.retention.title")}
            description={t("privacy.retention.description")}
            actions={
              <Button type="button" variant="outline" onClick={() => void runRetention()} disabled={reviewBusy === "retention" || busy === "retention"}>
                {reviewBusy === "retention" ? t("privacy.review.reviewing") : t("privacy.review.retentionAction")}
              </Button>
            }
          >
            {runs.length === 0 ? (
              <p className="text-caption text-muted-foreground">{t("privacy.retention.empty")}</p>
            ) : (
              <div className="overflow-x-auto" role="region" aria-label={t("privacy.design.retentionScrollArea")} tabIndex={0}>
                <table className="w-full min-w-[42rem] text-sm" aria-label={t("privacy.retention.tableCaption")}>
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
                        <td className="py-2 text-muted-foreground">{run.requested_by_ref || translateNow("source.system.bbc5e661e1")}</td>
                        <td className="py-2 text-muted-foreground">{formatDateTimePolicy(run.enforced_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>
        ) : null}
      </PrivacyDisclosurePanel>

      {erasurePreview ? (
        <PrivacyReviewDialog
          preview={erasurePreview}
          title={t("privacy.review.erasureHeading")}
          titleId="privacy-erasure-review-heading"
          executeLabel={busy === "erase" ? t("privacy.erasure.busy") : t("privacy.review.executeErasure")}
          executing={busy === "erase"}
          onClose={() => setErasurePreview(null)}
          onExecute={() => void executeErasure()}
        />
      ) : null}

      {retentionPreview ? (
        <PrivacyReviewDialog
          preview={retentionPreview}
          title={t("privacy.review.retentionHeading")}
          titleId="privacy-retention-review-heading"
          executeLabel={busy === "retention" ? t("privacy.retention.busy") : t("privacy.review.executeRetention")}
          executing={busy === "retention"}
          onClose={() => setRetentionPreview(null)}
          onExecute={() => void executeRetention()}
        />
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
              {t("privacy.design.recordDialogTitle")}
            </h2>
            <p id="archive-attestation-description" className="mt-1 text-sm text-muted-foreground">
              {t("parity.captureEvidenceOfHowABackup_f00d4e")}
            </p>
          </header>
          <form onSubmit={(event) => void recordArchiveAttestation(event)} className="grid gap-3 p-5">
            {recordError ? <ErrorState title={t("parity.couldNotRecordAttestation_204858")}>{recordError}</ErrorState> : null}
            <label className="grid gap-1 text-body font-medium">
              {translateNow("source.subject.6897128384")}
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
                {translateNow("source.action.64cff1319d")}
                <select
                  className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                  value={recordForm.action}
                  onChange={(event) => setRecordForm({ ...recordForm, action: event.target.value as PrivacyArchiveErasureAttestationRequest["action"] })}
                >
                  <option value="deleted">{t("parity.deleted_b639f5")}</option>
                  <option value="legal_hold">{t("parity.legalHold_644327")}</option>
                  <option value="cryptographic_shred">{t("parity.cryptographicShred_caafb7")}</option>
                </select>
              </label>
              <label className="grid gap-1 text-body font-medium">
                {translateNow("source.artifact.type.c4984fa09a")}
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
              {translateNow("source.reason.f81ab834de")}
              <input
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                value={recordForm.reason}
                onChange={(event) => setRecordForm({ ...recordForm, reason: event.target.value })}
                placeholder={translateNow("source.optional.ec91fdd925")}
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
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={recordBusy || !recordForm.subject.trim()}>
                {recordBusy ? translateNow("source.recording.9974b98e8b") : t("privacy.design.recordAttestation")}
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </section>
  );
}

type PrivacyActionPreview = PrivacySubjectErasurePreview | PrivacyRetentionPreview;

function PrivacyReviewDialog({
  executeLabel,
  executing,
  onClose,
  onExecute,
  preview,
  title,
  titleId,
}: {
  executeLabel: string;
  executing: boolean;
  onClose: () => void;
  onExecute: () => void;
  preview: PrivacyActionPreview;
  title: string;
  titleId: string;
}) {
  const { t } = useTranslation();
  const countEntries = Object.entries(preview.counts).filter(([, count]) => typeof count === "number" && count > 0);
  const isErasure = "subject_ref" in preview;
  const cutoffEntries = "cutoffs" in preview ? Object.entries(preview.cutoffs) : [];
  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      descriptionId={`${titleId}-description`}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 id={titleId} className="text-title font-semibold">{title}</h2>
          <StatusBadge value={preview.ready ? "ready" : "blocked"} label={preview.ready ? t("policy.reporting.ready") : t("policy.reporting.setupNeeded")} tone={preview.ready ? "success" : "warning"} />
        </div>
        <p id={`${titleId}-description`} className="mt-1 text-sm text-muted-foreground">
          {t("policy.reporting.noStateChanged")} {preview.preview_writes.length === 0 && preview.preview_external_effects.length === 0 ? "" : preview.blockers.join(" ")}
        </p>
      </header>
      <div className="grid gap-5 p-5">
        <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <PrivacyFact label={t("privacy.review.recordsMatched")} value={`${preview.total_records} ${t("privacy.review.recordsMatched")}`} />
          {isErasure ? <PrivacyFact label={t("privacy.review.archiveAttestations")} value={`${preview.archive_attestations} ${t("privacy.review.archiveAttestations")}`} /> : null}
          {isErasure ? <PrivacyFact label={t("privacy.review.activeLegalHolds")} value={`${preview.active_legal_holds} ${t("privacy.review.activeLegalHolds")}`} /> : null}
          {"reviewed_at" in preview ? <PrivacyFact label={t("privacy.review.reviewedAt")} value={formatDateTimePolicy(preview.reviewed_at)} /> : null}
          <PrivacyFact label={t("policy.reporting.permission")} value={preview.required_permission} />
        </dl>

        <section className="grid gap-2" aria-labelledby={`${titleId}-counts`}>
          <h3 id={`${titleId}-counts`} className="text-sm font-semibold">{t("privacy.review.recordsMatched")}</h3>
          {countEntries.length ? (
            <div className="grid gap-2 sm:grid-cols-2">
              {countEntries.map(([name, count]) => (
                <div key={name} className="flex items-center justify-between gap-4 rounded-control border border-border px-3 py-2 text-sm">
                  <span>{name.replace(/_/g, " ")}</span><span className="font-mono tabular-nums">{String(count)}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">0 {t("privacy.review.recordsMatched")}</p>}
        </section>

        {cutoffEntries.length ? (
          <details className="rounded-control border border-border px-3 py-2">
            <summary className="cursor-pointer text-sm font-semibold">{t("privacy.review.cutoffs")}</summary>
            <dl className="mt-3 grid gap-2 sm:grid-cols-2">
              {cutoffEntries.map(([name, value]) => (
                <div key={name} className="min-w-0 text-xs">
                  <dt className="text-muted-foreground">{name.replace(/_/g, " ")}</dt>
                  <dd className="break-all font-mono">{typeof value === "string" ? formatDateTimePolicy(value) : String(value)}</dd>
                </div>
              ))}
            </dl>
          </details>
        ) : null}

        {preview.blockers.length ? <ErrorState title={t("policy.reporting.setupNeeded")}>{preview.blockers.join(" ")}</ErrorState> : null}
        {preview.warnings.map((warning) => <p key={warning} className="rounded-control border border-warning/40 bg-warning/10 px-3 py-2 text-sm">{warning}</p>)}

        <PrivacyReviewList title={t("privacy.review.prerequisites")} items={preview.prerequisites} />
        <PrivacyReviewList title={t("privacy.review.effects")} items={[...preview.execute_writes, ...preview.execute_external_effects]} />
        <PrivacyReviewList title={t("policy.reporting.recovery")} items={preview.recovery_steps} />
        <PrivacyReviewList title={t("policy.reporting.verify")} items={preview.verification_steps} />

        <section className="rounded-control border border-border bg-muted/20 p-3 text-sm">
          <h3 className="font-semibold">{t("privacy.review.dataHandling")}</h3>
          <p className="mt-1 text-muted-foreground">{preview.secret_data_handling}</p>
        </section>

        <details className="rounded-control border border-border px-3 py-2">
          <summary className="cursor-pointer text-sm font-semibold">{t("policy.reporting.fingerprint")}</summary>
          <p className="mt-2 break-all font-mono text-xs">{preview.request_fingerprint}</p>
        </details>
      </div>
      <footer className="flex justify-end gap-2 border-t border-border px-5 py-4">
        <Button type="button" variant="ghost" onClick={onClose}>{translateNow("source.cancel.19766ed6cc")}</Button>
        <Button type="button" disabled={!preview.ready || executing} onClick={onExecute}>{executeLabel}</Button>
      </footer>
    </Dialog>
  );
}

function PrivacyReviewList({ items, title }: { items: string[]; title: string }) {
  return (
    <section className="grid gap-2">
      <h3 className="text-sm font-semibold">{title}</h3>
      <ul className="grid list-disc gap-1 ps-5 text-sm text-muted-foreground">
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </section>
  );
}

function PrivacyDisclosurePanel({
  children,
  detailsRef,
  onToggle,
  open,
  title,
}: {
  children: ReactNode;
  detailsRef?: RefObject<HTMLDetailsElement>;
  onToggle: (open: boolean) => void;
  open: boolean;
  title: string;
}) {
  return (
    <details
      ref={detailsRef}
      className="min-w-0 rounded-panel border border-border bg-card shadow-elevation1"
      open={open}
      onToggle={(event) => onToggle(event.currentTarget.open)}
    >
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      {open ? <div className="border-t border-border p-4">{children}</div> : null}
    </details>
  );
}

function PrivacyFact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-control border border-border bg-muted/20 p-3">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-words font-medium text-foreground">{value}</dd>
    </div>
  );
}
