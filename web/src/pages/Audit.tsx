import { useEffect, useState } from "react";
import { api, ApiError, type AuditBundle, type AuditEvent, type AuditQuery } from "@/lib/api";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";

type Notice = { kind: "permission" | "error"; message: string };

interface FilterState {
  type: string;
  since: string;
  until: string;
  asOf: string;
  q: string;
  limit: string;
}

const defaultFilters: FilterState = {
  type: "",
  since: "",
  until: "",
  asOf: "",
  q: "",
  limit: "50",
};

export function Audit() {
  const [filters, setFilters] = useState<FilterState>(defaultFilters);
  const [applied, setApplied] = useState<AuditQuery>(toAuditQuery(defaultFilters));
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Notice | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [bundle, setBundle] = useState<AuditBundle | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void loadEvents(toAuditQuery(defaultFilters));
  }, []);

  async function loadEvents(query: AuditQuery) {
    setLoading(true);
    setError(null);
    setSelected(null);
    try {
      setEvents(await api.auditEvents(query));
      setApplied(query);
    } catch (err) {
      setEvents(null);
      setError(noticeFor(err, "Could not load audit events"));
    } finally {
      setLoading(false);
    }
  }

  async function exportEvidence() {
    setBusy(true);
    setExportError(null);
    setBundle(null);
    try {
      setBundle(await api.exportAudit(applied));
    } catch (err) {
      setExportError(apiProblemMessage(err, "Could not export evidence"));
    } finally {
      setBusy(false);
    }
  }

  function updateFilter(key: keyof FilterState, value: string) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  return (
    <section aria-labelledby="audit-heading" className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 id="audit-heading" className="text-2xl font-semibold">
            Audit
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Tenant-scoped immutable event evidence from the served audit API.
          </p>
        </div>
        <Button type="button" onClick={() => void exportEvidence()} disabled={busy || loading}>
          Export evidence
        </Button>
      </div>

      <form
        className="rounded-md border border-border p-4"
        onSubmit={(event) => {
          event.preventDefault();
          void loadEvents(toAuditQuery(filters));
        }}
      >
        <div className="grid gap-3 lg:grid-cols-6">
          <label className="grid gap-1 text-sm font-medium" htmlFor="audit-type">
            Type
            <input
              id="audit-type"
              value={filters.type}
              onChange={(event) => updateFilter("type", event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2"
              placeholder="identity.issued"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="audit-q">
            Search
            <input
              id="audit-q"
              value={filters.q}
              onChange={(event) => updateFilter("q", event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2"
              placeholder="resource, actor, reason"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="audit-since">
            Since
            <input
              id="audit-since"
              value={filters.since}
              onChange={(event) => updateFilter("since", event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2"
              placeholder="2026-06-17T00:00:00Z"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="audit-until">
            Until
            <input
              id="audit-until"
              value={filters.until}
              onChange={(event) => updateFilter("until", event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2"
              placeholder="2026-06-18T00:00:00Z"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="audit-as-of">
            As of sequence
            <input
              id="audit-as-of"
              type="number"
              min="1"
              value={filters.asOf}
              onChange={(event) => updateFilter("asOf", event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium" htmlFor="audit-limit">
            Limit
            <input
              id="audit-limit"
              type="number"
              min="1"
              max="100"
              value={filters.limit}
              onChange={(event) => updateFilter("limit", event.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="submit" disabled={loading}>
            Apply filters
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setFilters(defaultFilters);
              void loadEvents(toAuditQuery(defaultFilters));
            }}
          >
            Reset
          </Button>
        </div>
      </form>

      {loading && <LoadingState>Loading audit events...</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Audit unavailable">{error.message}</ErrorState>}
      {exportError && <ErrorState title="Evidence export unavailable">{exportError}</ErrorState>}
      {bundle && <EvidenceBundle bundle={bundle} />}

      {events && (
        <>
          <HashChainPanel events={events} />
          {events.length === 0 ? (
            <EmptyState title="No audit events match these filters">
              The served audit API returned an empty window. Widen the time range, remove the type filter, or lower the as-of sequence.
            </EmptyState>
          ) : (
            <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_24rem]">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Tenant audit events</caption>
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th scope="col" className="py-2 pr-4 font-medium">Sequence</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Type</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Actor</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Tenant</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Resource</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Time</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Hash</th>
                    <th scope="col" className="py-2 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={eventKey(event)} className="border-b border-border align-top">
                      <td className="py-2 pr-4 font-mono text-xs">{event.sequence}</td>
                      <td className="py-2 pr-4">{event.type}</td>
                      <td className="py-2 pr-4">{actorLabel(event.actor)}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{event.tenant_id}</td>
                      <td className="py-2 pr-4">{resourceLabel(event)}</td>
                      <td className="py-2 pr-4">{event.time}</td>
                      <td className="py-2 pr-4 font-mono text-xs">{shortHash(event.hash)}</td>
                      <td className="py-2">
                        <Button type="button" size="sm" variant="outline" onClick={() => setSelected(event)}>
                          View event {event.sequence}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <EventDetail event={selected} />
            </div>
          )}
        </>
      )}
    </section>
  );
}

function EvidenceBundle({ bundle }: { bundle: AuditBundle }) {
  const payload = `${bundle.format}: ${bundle.bundle}`;
  return (
    <section aria-labelledby="evidence-bundle-heading" className="rounded-md border border-border p-4 text-sm">
      <h2 id="evidence-bundle-heading" className="font-semibold">
        Signed evidence bundle ready
      </h2>
      <dl className="mt-3 grid gap-2 sm:grid-cols-3">
        <div>
          <dt className="font-medium text-muted-foreground">Format</dt>
          <dd>{bundle.format}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Bundle bytes</dt>
          <dd>{bundle.bundle.length}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Scope</dt>
          <dd>Current filters</dd>
        </div>
      </dl>
      <p className="mt-3 break-all rounded-md bg-muted p-3 font-mono text-xs">{payload}</p>
      <a
        className="mt-3 inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
        download={`audit-evidence.${bundle.format}.txt`}
        href={`data:application/octet-stream;charset=utf-8,${encodeURIComponent(payload)}`}
      >
        Download signed bundle
      </a>
    </section>
  );
}

function HashChainPanel({ events }: { events: AuditEvent[] }) {
  const hashed = events.filter((event) => event.hash).length;
  const message =
    events.length === 0
      ? "No events in the current audit window."
      : hashed === events.length
        ? "Every listed event includes a hash, so this window has tamper-evident links back to the append-only log projection."
        : `${hashed} of ${events.length} listed events include a hash; export the evidence bundle for server-signed verification.`;
  return (
    <section aria-labelledby="hash-chain-heading" className="rounded-md border border-border p-4 text-sm">
      <h2 id="hash-chain-heading" className="font-semibold">
        Hash-chain status
      </h2>
      <p className="mt-1 text-muted-foreground">{message}</p>
    </section>
  );
}

function EventDetail({ event }: { event: AuditEvent | null }) {
  if (!event) {
    return (
      <aside className="rounded-md border border-border p-4 text-sm text-muted-foreground">
        Select an audit event to inspect its immutable sequence, hash, actor, and data payload.
      </aside>
    );
  }
  return (
    <aside aria-labelledby="audit-event-detail-heading" className="rounded-md border border-border p-4 text-sm">
      <h2 id="audit-event-detail-heading" className="text-lg font-semibold">
        Event detail
      </h2>
      <dl className="mt-3 grid gap-2">
        <div>
          <dt className="font-medium text-muted-foreground">Sequence</dt>
          <dd className="font-mono text-xs">{event.sequence}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Hash</dt>
          <dd className="break-all font-mono text-xs">{event.hash ?? "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Type</dt>
          <dd>{event.type}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Tenant</dt>
          <dd className="break-all font-mono text-xs">{event.tenant_id}</dd>
        </div>
      </dl>
      <h3 className="mt-4 font-semibold">Actor</h3>
      <pre className="mt-2 max-h-40 overflow-auto rounded-md bg-muted p-3 text-xs">{formatJSON(event.actor ?? {})}</pre>
      <h3 className="mt-4 font-semibold">Data</h3>
      <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{formatJSON(event.data ?? {})}</pre>
    </aside>
  );
}

function toAuditQuery(state: FilterState): AuditQuery {
  const query: AuditQuery = { limit: clampLimit(state.limit) };
  if (state.type.trim()) query.type = state.type.trim();
  if (state.since.trim()) query.since = state.since.trim();
  if (state.until.trim()) query.until = state.until.trim();
  if (state.q.trim()) query.q = state.q.trim();
  const asOf = Number(state.asOf);
  if (Number.isInteger(asOf) && asOf > 0) query.asOf = asOf;
  return query;
}

function clampLimit(raw: string): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return 50;
  return Math.max(1, Math.min(100, Math.round(n)));
}

function eventKey(event: AuditEvent): string {
  return event.id ?? `${event.sequence}:${event.type}:${event.time}`;
}

function actorLabel(actor: AuditEvent["actor"]): string {
  if (!actor) return "-";
  for (const key of ["email", "subject", "sub", "id", "name"]) {
    const value = actor[key];
    if (typeof value === "string" && value) return value;
  }
  return displayValue(actor);
}

function resourceLabel(event: AuditEvent): string {
  const data = event.data ?? {};
  for (const key of ["resource", "resource_id", "credential_id", "identity_id", "certificate_id", "owner_id", "name"]) {
    const value = data[key];
    if (typeof value === "string" && value) return value;
  }
  return "-";
}

function shortHash(hash?: string): string {
  if (!hash) return "-";
  return hash.length > 18 ? `${hash.slice(0, 18)}...` : hash;
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return formatJSON(value);
}

function formatJSON(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function noticeFor(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError && err.status === 403) {
    return { kind: "permission", message: "Your session cannot read tenant audit evidence." };
  }
  return { kind: "error", message: apiProblemMessage(err, fallback) };
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s.`;
    const body = err.body.trim();
    if (body) {
      try {
        const problem = JSON.parse(body) as { detail?: string; title?: string };
        const message = problem.detail || problem.title;
        if (message) return `${fallback}: ${message}`;
      } catch {
        return `${fallback}: ${body}`;
      }
    }
    return `${fallback}: ${err.message}`;
  }
  return `${fallback}: ${err instanceof Error ? err.message : String(err)}`;
}
