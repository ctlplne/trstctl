import { FormEvent, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, UnauthorizedError, api, type Certificate } from "@/lib/api";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { PageHeader } from "@/components/PageHeader";
import { expiryBandForDate } from "@/lib/statusVocab";
import { formatDate as formatDatePolicy } from "@/i18n/format";

type ExpiryFilter = "all" | "7d" | "30d" | "90d";

const expiryFilters: Array<{ value: ExpiryFilter; label: string; days?: number }> = [
  { value: "all", label: "All" },
  { value: "7d", label: "<7d", days: 7 },
  { value: "30d", label: "7-30d", days: 30 },
  { value: "90d", label: "30-90d", days: 90 },
];

function expiringBefore(filter: ExpiryFilter): string | undefined {
  const days = expiryFilters.find((f) => f.value === filter)?.days;
  if (!days) return undefined;
  const cutoff = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return cutoff.toISOString();
}

function expiryFromSearchParam(value: string | null): ExpiryFilter {
  return expiryFilters.some((filter) => filter.value === value) ? (value as ExpiryFilter) : "all";
}

type Notice = { kind: "permission" | "error"; message: string };

function noticeForError(err: unknown, action: string): Notice {
  if (err instanceof UnauthorizedError) {
    return { kind: "permission", message: `Your session cannot ${action}.` };
  }
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return { kind: "error", message: problem.detail || problem.title || err.message };
    } catch {
      return { kind: "error", message: err.body || err.message };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : String(err) };
}

function formatDate(value?: string): string {
  return formatDatePolicy(value);
}

export function Certificates() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<Notice | null>(null);
  const [query, setQuery] = useState("");
  const [expiry, setExpiry] = useState<ExpiryFilter>(() => expiryFromSearchParam(searchParams.get("expiry")));
  const [limit, setLimit] = useState(20);
  const [detailID, setDetailID] = useState<string | null>(null);
  const [detail, setDetail] = useState<Certificate | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<Notice | null>(null);
  const [showIngest, setShowIngest] = useState(false);
  const [pem, setPem] = useState("");
  const [ownerID, setOwnerID] = useState("");
  const [source, setSource] = useState("manual-ui");
  const [deploymentLocation, setDeploymentLocation] = useState("");
  const [ingestLoading, setIngestLoading] = useState(false);
  const [ingestError, setIngestError] = useState<Notice | null>(null);
  const [ingestSuccess, setIngestSuccess] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .certificatePage({ limit, expiringBefore: expiringBefore(expiry) })
      .then((page) => {
        if (cancelled) return;
        setCertificates(page.items ?? []);
        setNextCursor(page.next_cursor || undefined);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(noticeForError(err, "read certificate inventory"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [expiry, limit]);

  async function loadNextPage() {
    if (!nextCursor) return;
    setLoadingMore(true);
    setError(null);
    try {
      const page = await api.certificatePage({
        limit,
        cursor: nextCursor,
        expiringBefore: expiringBefore(expiry),
      });
      setCertificates((current) => [...current, ...(page.items ?? [])]);
      setNextCursor(page.next_cursor || undefined);
    } catch (err) {
      setError(noticeForError(err, "page certificate inventory"));
    } finally {
      setLoadingMore(false);
    }
  }

  function selectExpiry(nextExpiry: ExpiryFilter) {
    setExpiry(nextExpiry);
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (nextExpiry === "all") {
          next.delete("expiry");
        } else {
          next.set("expiry", nextExpiry);
        }
        return next;
      },
      { replace: true },
    );
  }

  async function openDetail(c: Certificate) {
    setDetailID(c.id);
    setDetail(null);
    setDetailLoading(true);
    setDetailError(null);
    try {
      setDetail(await api.getCertificate(c.id));
    } catch (err) {
      setDetailError(noticeForError(err, "read certificate detail"));
    } finally {
      setDetailLoading(false);
    }
  }

  async function submitIngest(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setIngestError(null);
    setIngestSuccess(null);
    if (!pem.trim()) {
      setIngestError({ kind: "error", message: "PEM is required." });
      return;
    }
    setIngestLoading(true);
    try {
      const cert = await api.ingestCertificate({
        pem,
        owner_id: ownerID.trim() || undefined,
        source: source.trim() || undefined,
        deployment_location: deploymentLocation.trim() || undefined,
      });
      setCertificates((current) => [cert, ...current.filter((c) => c.id !== cert.id)]);
      setPem("");
      setOwnerID("");
      setDeploymentLocation("");
      setSource("manual-ui");
      setIngestSuccess(`Ingested ${cert.subject}.`);
    } catch (err) {
      setIngestError(noticeForError(err, "ingest a certificate"));
    } finally {
      setIngestLoading(false);
    }
  }

  const filtered = useMemo(() => {
    const all = certificates;
    const q = query.trim().toLowerCase();
    if (!q) return all;
    return all.filter((c) =>
      [c.subject, c.issuer, c.status, c.fingerprint, c.serial, c.deployment_location].filter(Boolean).some((v) => v!.toLowerCase().includes(q)),
    );
  }, [certificates, query]);

  return (
    <section aria-labelledby="certs-heading">
      <PageHeader
        titleId="certs-heading"
        title="Certificates"
        description="Inventory is loaded from the served certificate API with tenant-scoped pagination, expiry filtering, detail fetches, and explicit ingest."
        actions={
          <button
            type="button"
            onClick={() => setShowIngest((v) => !v)}
            className="inline-flex min-h-10 items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground"
          >
            {showIngest ? "Close ingest" : "Add certificate"}
          </button>
        }
      />

      {showIngest && (
        <form onSubmit={submitIngest} aria-labelledby="ingest-heading" className="mb-6 grid gap-4 border-y border-border py-4">
          <div>
            <h2 id="ingest-heading" className="text-title font-semibold">
              Add certificate
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">Paste a public certificate PEM. Private keys do not belong in this form.</p>
          </div>
          <label className="grid gap-1 text-sm font-medium" htmlFor="cert-pem">
            Certificate PEM
            <textarea
              id="cert-pem"
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              rows={8}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </label>
          <div className="grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-owner">
              Owner ID
              <input
                id="cert-owner"
                value={ownerID}
                onChange={(e) => setOwnerID(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                placeholder="optional"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-source">
              Source
              <input
                id="cert-source"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-location">
              Deployment location
              <input
                id="cert-location"
                value={deploymentLocation}
                onChange={(e) => setDeploymentLocation(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                placeholder="cluster/service/path"
              />
            </label>
          </div>
          {ingestError?.kind === "permission" && <PermissionDeniedState>{ingestError.message}</PermissionDeniedState>}
          {ingestError?.kind === "error" && <ErrorState title="Could not ingest certificate">{ingestError.message}</ErrorState>}
          {ingestSuccess && (
            <p role="status" className="text-sm text-status-success">
              {ingestSuccess}
            </p>
          )}
          <div>
            <button
              type="submit"
              disabled={ingestLoading}
              className="inline-flex min-h-10 items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-60"
            >
              {ingestLoading ? "Ingesting..." : "Ingest certificate"}
            </button>
          </div>
        </form>
      )}

      {loading && <LoadingState>Loading certificates...</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Could not load certificates">{error.message}</ErrorState>}

      {!loading && certificates.length === 0 && !error && (
        <EmptyState title="No certificates yet" ctaTo="/wizard" ctaLabel="Set up your first certificate">
          Run the setup wizard to connect a CA, install an agent, and issue your first certificate.
        </EmptyState>
      )}

      {certificates.length > 0 && (
        <>
          <div className="mb-4 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-end">
            <div>
              <label htmlFor="cert-search" className="mb-1 block text-sm font-medium">
                Search loaded rows
              </label>
              <input
                id="cert-search"
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Subject, issuer, serial, fingerprint…"
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
            </div>
            <fieldset>
              <legend className="mb-1 text-sm font-medium">Server expiry filter</legend>
              <div className="flex flex-wrap gap-2">
                {expiryFilters.map((f) => (
                  <button
                    key={f.value}
                    type="button"
                    onClick={() => selectExpiry(f.value)}
                    aria-pressed={expiry === f.value}
                    className={`min-h-9 rounded-md border px-2.5 text-sm ${
                      expiry === f.value ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background"
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </fieldset>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cert-limit">
              Page size
              <select
                id="cert-limit"
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="min-h-9 rounded-md border border-border bg-background px-2 text-sm"
              >
                <option value={5}>5</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
              </select>
            </label>
          </div>

          {filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground">No certificates match your search.</p>
          ) : (
            <DataGrid
              ariaLabel="Inventoried certificates"
              rows={filtered}
              columns={certificateColumns}
              getRowId={(c) => c.id}
              onRowOpen={(c) => void openDetail(c)}
              rowActionLabel={() => "View details"}
            />
          )}

          <div className="mt-4 flex items-center gap-3">
            {nextCursor ? (
              <button
                type="button"
                onClick={() => void loadNextPage()}
                disabled={loadingMore}
                className="inline-flex min-h-10 items-center rounded-md border border-border px-3 py-2 text-sm disabled:opacity-60"
              >
                {loadingMore ? "Loading next page..." : "Load next page"}
              </button>
            ) : (
              <p className="text-sm text-muted-foreground">No more certificate pages.</p>
            )}
          </div>
        </>
      )}

      <DetailDrawer
        open={!!detailID}
        title="Certificate details"
        description={detailID ? `Fetched from GET /api/v1/certificates/${detailID}.` : undefined}
        onClose={() => setDetailID(null)}
      >
        {detailLoading && <LoadingState>Loading certificate details...</LoadingState>}
        {detailError?.kind === "permission" && <PermissionDeniedState>{detailError.message}</PermissionDeniedState>}
        {detailError?.kind === "error" && <ErrorState title="Could not load certificate details">{detailError.message}</ErrorState>}
        {detail && (
          <dl className="grid gap-3 text-sm md:grid-cols-2">
            <div>
              <dt className="font-medium text-muted-foreground">Subject</dt>
              <dd>{detail.subject}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Issuer</dt>
              <dd>{detail.issuer || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">SANs</dt>
              <dd>{detail.sans?.length ? detail.sans.join(", ") : "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Key algorithm</dt>
              <dd>{detail.key_algorithm || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Serial</dt>
              <dd className="break-all font-mono text-xs">{detail.serial || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Fingerprint</dt>
              <dd className="break-all font-mono text-xs">{detail.fingerprint}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Validity</dt>
              <dd>
                {formatDate(detail.not_before)} to {formatDate(detail.not_after)}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Status</dt>
              <dd>{detail.status}</dd>
            </div>
            {detail.status === "revoked" && (
              <>
                <div>
                  <dt className="font-medium text-muted-foreground">Revoked at</dt>
                  <dd>{formatDate(detail.revoked_at)}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Revocation reason</dt>
                  <dd>{detail.revocation_reason || "-"}</dd>
                </div>
              </>
            )}
            <div>
              <dt className="font-medium text-muted-foreground">Source</dt>
              <dd>{detail.source || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Deployment location</dt>
              <dd>{detail.deployment_location || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Owner</dt>
              <dd>
                {detail.owner_id ? (
                  <a className="text-primary underline" href={`/owners?owner=${encodeURIComponent(detail.owner_id)}`}>
                    {detail.owner_id}
                  </a>
                ) : (
                  "-"
                )}
              </dd>
            </div>
            <div className="md:col-span-2">
              <dt className="font-medium text-muted-foreground">Certificate chain</dt>
              <dd>
                <UnavailableState title="Certificate chain not served yet">
                  The current detail contract returns certificate metadata, not chain bytes. Use issuer evidence until a chain field is served.
                </UnavailableState>
              </dd>
            </div>
            <div className="md:col-span-2">
              <CredentialActivityTimeline credentialLabel={detail.subject} />
            </div>
          </dl>
        )}
      </DetailDrawer>
    </section>
  );
}

const certificateColumns: Array<DataGridColumn<Certificate>> = [
  {
    id: "subject",
    header: "Subject",
    sortable: true,
    cell: (c) => <span className="font-medium">{c.subject}</span>,
  },
  {
    id: "issuer",
    header: "Issuer",
    cell: (c) => c.issuer ?? "—",
  },
  {
    id: "profile",
    header: "Profile",
    cell: () => <span className="text-muted-foreground">Not served</span>,
  },
  {
    id: "algorithm",
    header: "Algorithm",
    cell: (c) => c.key_algorithm || "—",
  },
  {
    id: "expires",
    header: "Expires",
    sortable: true,
    cell: (c) => formatDate(c.not_after),
  },
  {
    id: "expiry-band",
    header: "Band",
    cell: (c) => <StatusBadge vocabulary="expiry" value={expiryBandForDate(c.not_after)} />,
  },
  {
    id: "status",
    header: "Status",
    cell: (c) => (
      <div className="grid gap-1">
        <StatusBadge vocabulary="certificate" value={c.status} />
        {c.status === "revoked" && c.revocation_reason && <span className="text-xs text-muted-foreground">{c.revocation_reason}</span>}
      </div>
    ),
  },
];
