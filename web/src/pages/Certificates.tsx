import { FormEvent, useEffect, useMemo, useState } from "react";
import { ApiError, UnauthorizedError, api, type Certificate } from "@/lib/api";
import { EmptyState } from "@/components/EmptyState";
import {
  ErrorState,
  LoadingState,
  PermissionDeniedState,
  UnavailableState,
} from "@/components/StatePrimitives";

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
  if (!value) return "-";
  return new Date(value).toLocaleDateString();
}

function expiryBand(c: Certificate): { label: string; className: string } {
  if (!c.not_after) return { label: "No expiry", className: "bg-muted text-muted-foreground" };
  const days = Math.ceil((new Date(c.not_after).getTime() - Date.now()) / (24 * 60 * 60 * 1000));
  if (days < 0) return { label: "Expired", className: "bg-red-100 text-red-800" };
  if (days < 7) return { label: "<7d critical", className: "bg-red-100 text-red-800" };
  if (days <= 30) return { label: "7-30d watch", className: "bg-amber-100 text-amber-800" };
  if (days <= 90) return { label: "30-90d planned", className: "bg-blue-100 text-blue-800" };
  return { label: ">90d healthy", className: "bg-emerald-100 text-emerald-800" };
}

function statusChip(c: Certificate): { label: string; className: string } {
  switch (c.status) {
    case "revoked":
      return { label: "revoked", className: "bg-red-100 text-red-800" };
    case "superseded":
      return { label: "superseded", className: "bg-slate-200 text-slate-800" };
    default:
      return { label: "active", className: "bg-emerald-100 text-emerald-800" };
  }
}

function Chip({ label, className }: { label: string; className: string }) {
  return (
    <span className={`inline-flex min-h-7 items-center rounded-md px-2 py-1 text-xs font-medium ${className}`}>
      {label}
    </span>
  );
}

export function Certificates() {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<Notice | null>(null);
  const [query, setQuery] = useState("");
  const [expiry, setExpiry] = useState<ExpiryFilter>("all");
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
      [c.subject, c.issuer, c.status, c.fingerprint, c.serial, c.deployment_location]
        .filter(Boolean)
        .some((v) => v!.toLowerCase().includes(q)),
    );
  }, [certificates, query]);

  return (
    <section aria-labelledby="certs-heading">
      <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <h1 id="certs-heading" className="text-2xl font-semibold">
            Certificates
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Inventory is loaded from the served certificate API with tenant-scoped
            pagination, expiry filtering, detail fetches, and explicit ingest.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowIngest((v) => !v)}
          className="inline-flex min-h-10 items-center justify-center rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground"
        >
          {showIngest ? "Close ingest" : "Add certificate"}
        </button>
      </div>

      {showIngest && (
        <form
          onSubmit={submitIngest}
          aria-labelledby="ingest-heading"
          className="mb-6 grid gap-4 border-y border-border py-4"
        >
          <div>
            <h2 id="ingest-heading" className="text-lg font-semibold">
              Add certificate
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Paste a public certificate PEM. Private keys do not belong in this form.
            </p>
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
          {ingestError?.kind === "permission" && (
            <PermissionDeniedState>{ingestError.message}</PermissionDeniedState>
          )}
          {ingestError?.kind === "error" && (
            <ErrorState title="Could not ingest certificate">{ingestError.message}</ErrorState>
          )}
          {ingestSuccess && <p role="status" className="text-sm text-emerald-700">{ingestSuccess}</p>}
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
      {error?.kind === "error" && (
        <ErrorState title="Could not load certificates">{error.message}</ErrorState>
      )}

      {!loading && certificates.length === 0 && !error && (
        <EmptyState
          title="No certificates yet"
          ctaTo="/wizard"
          ctaLabel="Set up your first certificate"
        >
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
                    onClick={() => setExpiry(f.value)}
                    aria-pressed={expiry === f.value}
                    className={`min-h-9 rounded-md border px-2.5 text-sm ${
                      expiry === f.value
                        ? "border-primary bg-primary text-primary-foreground"
                        : "border-border bg-background"
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
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Inventoried certificates</caption>
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th scope="col" className="py-2 pr-4 font-medium">Subject</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Issuer</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Expires</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Band</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Status</th>
                  <th scope="col" className="py-2 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => {
                  const band = expiryBand(c);
                  const status = statusChip(c);
                  return (
                  <tr key={c.id} className="border-b border-border align-top">
                    <td className="py-2 pr-4">{c.subject}</td>
                    <td className="py-2 pr-4">{c.issuer ?? "—"}</td>
                    <td className="py-2 pr-4">
                      {formatDate(c.not_after)}
                    </td>
                    <td className="py-2 pr-4"><Chip label={band.label} className={band.className} /></td>
                    <td className="py-2 pr-4">
                      <div className="grid gap-1">
                        <Chip label={status.label} className={status.className} />
                        {c.status === "revoked" && c.revocation_reason && (
                          <span className="text-xs text-muted-foreground">{c.revocation_reason}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-2">
                      <button
                        type="button"
                        onClick={() => void openDetail(c)}
                        className="min-h-9 rounded-md border border-border px-2.5 text-sm"
                      >
                        View details
                      </button>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
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

      {detailID && (
        <aside
          role="dialog"
          aria-labelledby="cert-detail-heading"
          className="mt-6 border-y border-border py-4"
        >
          <div className="mb-3 flex items-start justify-between gap-3">
            <div>
              <h2 id="cert-detail-heading" className="text-lg font-semibold">
                Certificate details
              </h2>
              <p className="text-sm text-muted-foreground">Fetched from GET /api/v1/certificates/{detailID}.</p>
            </div>
            <button
              type="button"
              onClick={() => setDetailID(null)}
              className="min-h-9 rounded-md border border-border px-2.5 text-sm"
            >
              Close
            </button>
          </div>
          {detailLoading && <LoadingState>Loading certificate details...</LoadingState>}
          {detailError?.kind === "permission" && (
            <PermissionDeniedState>{detailError.message}</PermissionDeniedState>
          )}
          {detailError?.kind === "error" && (
            <ErrorState title="Could not load certificate details">{detailError.message}</ErrorState>
          )}
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
                <dd>{formatDate(detail.not_before)} to {formatDate(detail.not_after)}</dd>
              </div>
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
                  ) : "-"}
                </dd>
              </div>
              <div className="md:col-span-2">
                <dt className="font-medium text-muted-foreground">Certificate chain</dt>
                <dd>
                  <UnavailableState title="Certificate chain not served yet">
                    The current detail contract returns certificate metadata, not chain bytes. Use
                    issuer evidence until a chain field is served.
                  </UnavailableState>
                </dd>
              </div>
            </dl>
          )}
        </aside>
      )}
    </section>
  );
}
