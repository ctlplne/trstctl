import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, ApiError, type AuditBundle, type AuditEvent, type AuditQuery } from "@/lib/api";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { moduleLabelKey, moduleScopeTerm } from "@/lib/navigation";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

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
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const initialFilters = filtersFromSearchParams(searchParams);
  const [filters, setFilters] = useState<FilterState>(initialFilters);
  // S-B4: the module scope is a lens over the one shared stream; surfaced as a
  // clearable chip so it never becomes an invisible, sticky filter.
  const [moduleScope, setModuleScope] = useState<string>(() => searchParams.get("module") ?? "");
  const moduleScopeLabelKey = moduleScope ? moduleLabelKey(moduleScope) : undefined;

  function clearModuleScope() {
    setModuleScope("");
    const cleared = { ...filters, q: "" };
    setFilters(cleared);
    void loadEvents(toAuditQuery(cleared));
  }
  const [applied, setApplied] = useState<AuditQuery>(toAuditQuery(initialFilters));
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Notice | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [bundle, setBundle] = useState<AuditBundle | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void loadEvents(toAuditQuery(initialFilters));
    // The initial URL query seeds the audit view once for deep links.
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  function applyTypePreset(type: string) {
    const next = { ...filters, type };
    setFilters(next);
    void loadEvents(toAuditQuery(next));
  }

  const auditColumns = useMemo<Array<DataGridColumn<AuditEvent>>>(
    () => [
      {
        id: "sequence",
        header: "Sequence",
        sortable: true,
        className: "font-mono text-xs",
        cell: (event) => event.sequence,
      },
      {
        id: "type",
        header: "Type",
        sortable: true,
        cell: (event) => event.type,
      },
      {
        id: "actor",
        header: "Actor",
        cell: (event) => actorLabel(event.actor),
      },
      {
        id: "tenant",
        header: "Tenant",
        className: "font-mono text-xs",
        cell: (event) => event.tenant_id,
      },
      {
        id: "resource",
        header: "Resource",
        cell: (event) => resourceLabel(event),
      },
      {
        id: "time",
        header: "Time",
        sortable: true,
        cell: (event) => event.time,
      },
      {
        id: "hash",
        header: "Hash",
        className: "font-mono text-xs",
        cell: (event) => shortHash(event.hash),
      },
    ],
    [],
  );

  return (
    <section aria-labelledby="audit-heading" className="space-y-6">
      <PageHeader
        titleId="audit-heading"
        title={translateNow("source.audit.bb6aea2873")}
        description="Tenant-scoped immutable event evidence."
        actions={
          <Button type="button" onClick={() => void exportEvidence()} disabled={busy || loading}>
            {translateNow("source.export.evidence.caab91492e")}</Button>
        }
      />

      {moduleScope && moduleScopeLabelKey && (
        <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="audit-module-scope">
          <span className="inline-flex items-center gap-2 rounded-control border border-brand-accent/40 bg-brand-accent/10 px-2.5 py-1 font-medium text-brand-accent">
            {t("audit.moduleScope.label", { module: t(moduleScopeLabelKey) })}
            <button
              type="button"
              onClick={clearModuleScope}
              className="rounded-control px-1 text-brand-accent/80 hover:text-brand-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
              aria-label={t("audit.moduleScope.clear")}
            >
              ✕
            </button>
          </span>
          <span className="text-muted-foreground">{t("audit.moduleScope.note")}</span>
        </div>
      )}

      {exportError && <ErrorState title={translateNow("source.evidence.export.unavailable.9cb4129ff9")}>{exportError}</ErrorState>}
      {bundle && <EvidenceBundle bundle={bundle} />}

      {events && <HashChainPanel events={events} />}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_24rem]">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void loadEvents(toAuditQuery(filters));
          }}
        >
          <DataGrid
            ariaLabel="Tenant audit events"
            rows={events ?? []}
            columns={auditColumns}
            getRowId={eventKey}
            state={
              loading
                ? "loading"
                : error?.kind === "permission"
                  ? "permission-denied"
                  : error?.kind === "error"
                    ? "error"
                    : events && events.length === 0
                      ? "empty"
                      : "ready"
            }
            stateTitle={error?.kind === "error" ? "Audit unavailable" : events && events.length === 0 ? "No audit events match these filters" : undefined}
            stateMessage={
              error?.message ??
              (events && events.length === 0
                ? "No events matched this window. Widen the time range, remove the type filter, or lower the as-of sequence."
                : undefined)
            }
            showColumnChooser
            toolbar={({ columnChooser }) => (
              <DataGridToolbar
                searchLabel="Search"
                searchPlaceholder="resource, actor, reason"
                searchValue={filters.q}
                onSearchChange={(value) => updateFilter("q", value)}
                filters={
                  <>
                    <AuditFilterInput
                      id="audit-type"
                      label="Type"
                      value={filters.type}
                      onChange={(value) => updateFilter("type", value)}
                      placeholder={translateNow("source.identity.issued.08c478fa05")}
                    />
                    <AuditFilterInput
                      id="audit-since"
                      label="Since"
                      value={filters.since}
                      onChange={(value) => updateFilter("since", value)}
                      placeholder={translateNow("source.2026.06.17t00.00.00z.f4debbb70c")}
                    />
                    <AuditFilterInput
                      id="audit-until"
                      label="Until"
                      value={filters.until}
                      onChange={(value) => updateFilter("until", value)}
                      placeholder={translateNow("source.2026.06.18t00.00.00z.b4c7e74181")}
                    />
                    <AuditFilterInput
                      id="audit-as-of"
                      label="As of sequence"
                      type="number"
                      value={filters.asOf}
                      onChange={(value) => updateFilter("asOf", value)}
                    />
                    <AuditFilterInput
                      id="audit-limit"
                      label="Limit"
                      type="number"
                      value={filters.limit}
                      onChange={(value) => updateFilter("limit", value)}
                      min="1"
                      max="100"
                    />
                  </>
                }
                columnChooser={columnChooser}
                actions={
                  <>
                    <Button type="button" variant="outline" onClick={() => applyTypePreset("policy.decision")}>
                      {translateNow("source.policy.decisions.988b13232e")}</Button>
                    <Button type="button" variant="outline" onClick={() => applyTypePreset("issuance.profile_evaluated")}>
                      {translateNow("source.profile.evaluations.fc73272085")}</Button>
                    <Button type="submit" disabled={loading}>
                      {translateNow("source.apply.filters.d80ab19b7e")}</Button>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setFilters(defaultFilters);
                        void loadEvents(toAuditQuery(defaultFilters));
                      }}
                    >
                      {translateNow("source.reset.daee7606b3")}</Button>
                  </>
                }
              />
            )}
            onRowOpen={setSelected}
            rowActionLabel={(event) => `View event ${event.sequence}`}
          />
        </form>
        <EventDetail event={selected} />
      </div>
    </section>
  );
}

function AuditFilterInput({
  id,
  label,
  max,
  min,
  onChange,
  placeholder,
  type = "text",
  value,
}: {
  id: string;
  label: string;
  max?: string;
  min?: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: "number" | "text";
  value: string;
}) {
  return (
    <label className="grid gap-1 text-sm font-medium" htmlFor={id}>
      {label}
      <input
        id={id}
        type={type}
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-sm"
        placeholder={placeholder}
      />
    </label>
  );
}

function EvidenceBundle({ bundle }: { bundle: AuditBundle }) {
  const payload = `${bundle.format}: ${bundle.bundle}`;
  return (
    <section aria-labelledby="evidence-bundle-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="evidence-bundle-heading" className="text-title font-semibold">
        {translateNow("source.signed.evidence.bundle.ready.9ce177ede7")}</h2>
      <dl className="mt-3 grid gap-2 sm:grid-cols-3">
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.format.2f343666aa")}</dt>
          <dd>{bundle.format}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.bundle.bytes.842399751d")}</dt>
          <dd>{bundle.bundle.length}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.scope.b073f6c68e")}</dt>
          <dd>{translateNow("source.current.filters.4e3b0ba1cb")}</dd>
        </div>
      </dl>
      <p className="mt-3 break-all rounded-md bg-muted p-3 font-mono text-xs">{payload}</p>
      <a
        className="mt-3 inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
        download={`audit-evidence.${bundle.format}.txt`}
        href={`data:application/octet-stream;charset=utf-8,${encodeURIComponent(payload)}`}
      >
        {translateNow("source.download.signed.bundle.c6373a92cb")}</a>
    </section>
  );
}

function filtersFromSearchParams(searchParams: URLSearchParams): FilterState {
  // S-B4: ?module=<id> scopes the shared audit stream to one module by seeding
  // the free-text query with the module's scope term (unless an explicit q is
  // already present, which wins).
  const moduleParam = searchParams.get("module") ?? "";
  const moduleTerm = moduleParam ? moduleScopeTerm(moduleParam) : undefined;
  return {
    type: searchParams.get("type") ?? "",
    since: searchParams.get("since") ?? "",
    until: searchParams.get("until") ?? "",
    asOf: searchParams.get("as_of") ?? "",
    q: searchParams.get("q") ?? moduleTerm ?? "",
    limit: searchParams.get("limit") ?? "50",
  };
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
    <section aria-labelledby="hash-chain-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="hash-chain-heading" className="text-title font-semibold">
        {translateNow("source.hash.chain.status.f5491b14e9")}</h2>
      <p className="mt-1 text-muted-foreground">{message}</p>
    </section>
  );
}

function EventDetail({ event }: { event: AuditEvent | null }) {
  if (!event) {
    return (
      <div role="note" className="ui-panel p-comfortable text-sm text-muted-foreground">
        {translateNow("source.select.an.audit.event.to.inspect.its.immut.b522affee1")}</div>
    );
  }
  return (
    <section aria-labelledby="audit-event-detail-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="audit-event-detail-heading" className="text-title font-semibold">
        {translateNow("source.event.detail.097e77abc2")}</h2>
      <dl className="mt-3 grid gap-2">
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.sequence.0740f4bade")}</dt>
          <dd className="font-mono text-xs">{event.sequence}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.hash.a91069147f")}</dt>
          <dd className="break-all font-mono text-xs">{event.hash ?? "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.type.baaddf70fb")}</dt>
          <dd>{event.type}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.tenant.e23969d284")}</dt>
          <dd className="break-all font-mono text-xs">{event.tenant_id}</dd>
        </div>
      </dl>
      <h3 className="mt-4 font-semibold">{translateNow("source.actor.449995c4fe")}</h3>
      <pre className="mt-2 max-h-40 overflow-auto rounded-md bg-muted p-3 text-xs">{formatJSON(event.actor ?? {})}</pre>
      <h3 className="mt-4 font-semibold">{translateNow("source.data.cec3a9b89b")}</h3>
      <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{formatJSON(event.data ?? {})}</pre>
    </section>
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
    return { kind: "permission", message: translateNow("source.your.session.cannot.read.tenant.audit.evid.6c0890fb54") };
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
