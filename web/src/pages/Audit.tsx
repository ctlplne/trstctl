import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, type AuditBundle, type AuditEvent, type AuditQuery } from "@/lib/api";
// This page renders errors in the fallback-prefixed shape ("Could not export
// evidence: <detail>"), pinned by __tests__/operations_surface.test.tsx.
import { apiProblemContext as apiProblemMessage } from "@/lib/apiProblem";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { moduleLabelKey, moduleScopeTerm } from "@/lib/navigation";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { AuditFeedPanel } from "@/pages/audit/AuditFeedPanel";

type Notice = { kind: "permission" | "error"; message: string };
type Disclosure = "search" | "evidence" | "collectors";

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
  const { t, formatDateTime } = useTranslation();
  const [searchParams] = useSearchParams();
  const initialFilters = filtersFromSearchParams(searchParams);
  const explicitlyScoped = hasExplicitAuditScope(searchParams);
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
  // J1: the export encoding. The signed bundle stays the default because it is
  // the only format that is itself verifiable; the rest exist so a SOC can
  // ingest the trail into tooling that would notice something at the time,
  // rather than it being exported once for an audit and never read.
  const [exportFormat, setExportFormat] = useState<string>("jws");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<Record<Disclosure, boolean>>({ search: explicitlyScoped, evidence: false, collectors: false });
  const searchInputRef = useRef<HTMLInputElement>(null);

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
      if (exportFormat !== "jws") {
        // A record stream is a file, not something to render: a year of audit
        // events pasted into the page would hang the browser and help nobody.
        await api.downloadAuditExport(applied, exportFormat);
        return;
      }
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

  function openSearch() {
    setOpen((current) => ({ ...current, search: true }));
    window.setTimeout(() => searchInputRef.current?.focus(), 0);
  }

  const lastShown = lastAuditEventShown(events);
  const summaryTitle = loading
    ? t("audit.design.summaryCheckingTitle")
    : error
      ? t("audit.design.summaryUnavailableTitle")
      : events?.length === 0
        ? t("audit.design.summaryEmptyTitle")
        : events?.length === 1
          ? t("audit.design.summaryOne")
          : t("audit.design.summaryMany", { count: String(events?.length ?? 0) });
  const summaryBody = loading
    ? t("audit.design.summaryCheckingBody")
    : error
      ? t("audit.design.summaryUnavailableBody")
      : events?.length === 0
        ? t("audit.design.summaryEmptyBody")
        : t("audit.design.summaryWindowBoundary", { count: String(events?.length ?? 0) });

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
    <section aria-labelledby="audit-heading" className="space-y-4">
      <PageHeader
        titleId="audit-heading"
        title={t("nav.item.audit")}
        description={t("audit.design.answer")}
        technicalDetails={t("audit.design.technicalDetails")}
        actions={
          <Button type="button" onClick={openSearch}>
            {t("audit.design.searchAction")}
          </Button>
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

      <section aria-labelledby="audit-summary-heading" className="ui-panel grid gap-4 p-comfortable" aria-live="polite">
        <div className="grid gap-1">
          <h2 id="audit-summary-heading" className="text-title font-semibold">
            {summaryTitle}
          </h2>
          <p className="max-w-3xl text-body text-muted-foreground">{summaryBody}</p>
        </div>
        {!loading && !error && lastShown ? (
          <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <SummaryFact label={t("audit.design.lastChangeShown")} value={readableEventType(lastShown.type)} />
            <SummaryFact label={t("audit.design.changedBy")} value={actorLabel(lastShown.actor)} />
            <SummaryFact label={t("audit.design.when")} value={formatDateTime(lastShown.time)} />
            <SummaryFact label={t("audit.design.result")} value={t(eventResultKey(lastShown))} />
          </dl>
        ) : null}
      </section>

      <AuditDisclosure
        title={t("audit.design.disclosure.search")}
        open={open.search}
        onToggle={(value) => setOpen((current) => ({ ...current, search: value }))}
      >
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
                  searchLabel={t("audit.design.searchAction")}
                  searchInputId="audit-search"
                  searchInputRef={searchInputRef}
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
                        {translateNow("source.policy.decisions.988b13232e")}
                      </Button>
                      <Button type="button" variant="outline" onClick={() => applyTypePreset("issuance.profile_evaluated")}>
                        {translateNow("source.profile.evaluations.fc73272085")}
                      </Button>
                      <Button type="submit" disabled={loading}>
                        {translateNow("source.apply.filters.d80ab19b7e")}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          setFilters(defaultFilters);
                          void loadEvents(toAuditQuery(defaultFilters));
                        }}
                      >
                        {translateNow("source.reset.daee7606b3")}
                      </Button>
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
      </AuditDisclosure>

      <AuditDisclosure
        title={t("audit.design.disclosure.evidence")}
        open={open.evidence}
        onToggle={(value) => setOpen((current) => ({ ...current, evidence: value }))}
      >
        <div className="grid gap-4">
          <div className="flex flex-wrap items-end gap-2">
            <label htmlFor="audit-export-format" className="grid gap-1 text-sm font-medium">
              {translateNow("source.export.format.j1exp00001")}
              <Select
                id="audit-export-format"
                className="h-9 w-52"
                value={exportFormat}
                onChange={(event) => setExportFormat(event.target.value)}
                disabled={busy || loading}
              >
                <option value="jws">{translateNow("source.format.jws.j1exp00002")}</option>
                <option value="ndjson">{translateNow("source.format.ndjson.j1exp00003")}</option>
                <option value="csv">{translateNow("source.format.csv.j1exp00004")}</option>
                <option value="splunk-hec">{translateNow("source.format.splunk.j1exp00005")}</option>
                <option value="sentinel">{translateNow("source.format.sentinel.j1exp00006")}</option>
              </Select>
            </label>
            <Button type="button" onClick={() => void exportEvidence()} disabled={busy || loading}>
              {translateNow("source.export.evidence.caab91492e")}
            </Button>
          </div>
          <p className="max-w-3xl text-sm text-muted-foreground">
            {t("audit.design.retentionBoundary")}{" "}
            <Link className="font-medium text-link underline" to="/privacy">
              {t("audit.design.reviewRetention")}
            </Link>
          </p>
          {exportError && <ErrorState title={translateNow("source.evidence.export.unavailable.9cb4129ff9")}>{exportError}</ErrorState>}
          {bundle && <EvidenceBundle bundle={bundle} />}
          {events && <HashChainPanel events={events} />}
        </div>
      </AuditDisclosure>

      <AuditDisclosure
        title={t("audit.design.disclosure.collectors")}
        open={open.collectors}
        onToggle={(value) => setOpen((current) => ({ ...current, collectors: value }))}
      >
        <AuditFeedPanel />
      </AuditDisclosure>
    </section>
  );
}

function AuditDisclosure({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      {open ? <div className="border-t border-border p-4">{children}</div> : null}
    </details>
  );
}

function SummaryFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-control border border-border bg-muted/20 p-3">
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-words font-medium text-foreground">{value}</dd>
    </div>
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
  const { t } = useTranslation();
  const payload = `${bundle.format}: ${bundle.bundle}`;
  const artifact = `${JSON.stringify(bundle, null, 2)}\n`;
  const anchored = bundle.anchor?.kind === "rfc3161" && Boolean(bundle.anchor.token?.der) && bundle.anchor.chain_head === bundle.chain_head;
  const authorityTime = bundle.anchor?.token?.info?.gen_time || bundle.anchor?.anchored_at;
  return (
    <section aria-labelledby="evidence-bundle-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="evidence-bundle-heading" className="text-title font-semibold">
        {translateNow("source.signed.evidence.bundle.ready.9ce177ede7")}
      </h2>
      <dl className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.format.2f343666aa")}</dt>
          <dd>{bundle.format}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.bundle.bytes.842399751d")}</dt>
          <dd>{artifact.length}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.scope.b073f6c68e")}</dt>
          <dd>{translateNow("source.current.filters.4e3b0ba1cb")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("audit.export.anchorStatus")}</dt>
          <dd>{anchored ? t("audit.export.anchored") : t("audit.export.unanchored")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("audit.export.anchorKind")}</dt>
          <dd>{bundle.anchor?.kind || t("audit.export.unanchored")}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{t("audit.export.anchoredAt")}</dt>
          <dd>{authorityTime || "—"}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="font-medium text-muted-foreground">{t("audit.export.chainHead")}</dt>
          <dd className="break-all font-mono text-xs">{bundle.chain_head || "—"}</dd>
        </div>
      </dl>
      <p className="mt-3 text-sm text-muted-foreground">
        {anchored ? t("audit.export.offlineReady") : bundle.anchor?.detail || t("audit.export.offlineMissing")}
      </p>
      <p className="mt-3 break-all rounded-md bg-muted p-3 font-mono text-xs">{payload}</p>
      <a
        className="mt-3 inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
        download={`audit-evidence.${bundle.format}.json`}
        href={`data:application/json;charset=utf-8,${encodeURIComponent(artifact)}`}
      >
        {translateNow("source.download.signed.bundle.c6373a92cb")}
      </a>
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

function hasExplicitAuditScope(searchParams: URLSearchParams): boolean {
  return ["module", "type", "since", "until", "as_of", "q", "limit"].some((key) => searchParams.has(key));
}

function lastAuditEventShown(events: AuditEvent[] | null): AuditEvent | null {
  if (!events || events.length === 0) return null;
  return events.reduce((latest, event) => (event.sequence > latest.sequence ? event : latest));
}

function readableEventType(type: string): string {
  const words = type
    .trim()
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ");
  return words ? `${words.charAt(0).toUpperCase()}${words.slice(1)}` : "—";
}

function eventResultKey(event: AuditEvent): MessageKey {
  const data = event.data ?? {};
  const raw = [data.result, data.status, data.outcome, data.decision].find((value) => typeof value === "string") as string | undefined;
  const normalized = raw?.trim().toLowerCase();
  if (normalized === "succeeded" || normalized === "success" || normalized === "completed" || normalized === "ok") return "audit.design.result.succeeded";
  if (normalized === "failed" || normalized === "failure" || normalized === "error") return "audit.design.result.failed";
  if (normalized === "denied" || normalized === "deny" || normalized === "rejected") return "audit.design.result.denied";
  if (normalized === "allowed" || normalized === "allow" || normalized === "approved") return "audit.design.result.allowed";
  if (/\.(failed|failure|rejected|denied)$/.test(event.type)) return "audit.design.result.failed";
  if (/\.(succeeded|completed|approved|issued|created|updated|recorded|deployed)$/.test(event.type)) return "audit.design.result.succeeded";
  return "audit.design.result.recorded";
}

function HashChainPanel({ events }: { events: AuditEvent[] }) {
  const { t } = useTranslation();
  const hashed = events.filter((event) => event.hash).length;
  const message =
    events.length === 0
      ? t("audit.hash.empty")
      : hashed === events.length
        ? t("audit.hash.complete", { count: String(events.length) })
        : t("audit.hash.partial", { hashed: String(hashed), total: String(events.length) });
  return (
    <section aria-labelledby="hash-chain-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="hash-chain-heading" className="text-title font-semibold">
        {t("audit.hash.heading")}
      </h2>
      <p className="mt-1 text-muted-foreground">{message}</p>
      <p className="mt-2 text-muted-foreground">{t("audit.hash.boundary")}</p>
    </section>
  );
}

function EventDetail({ event }: { event: AuditEvent | null }) {
  const { t } = useTranslation();
  if (!event) {
    return (
      <div role="note" className="ui-panel p-comfortable text-sm text-muted-foreground">
        {translateNow("source.select.an.audit.event.to.inspect.its.immut.b522affee1")}
      </div>
    );
  }
  const resources = affectedResourceLinks(event);
  return (
    <section aria-labelledby="audit-event-detail-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="audit-event-detail-heading" className="text-title font-semibold">
        {translateNow("source.event.detail.097e77abc2")}
      </h2>
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
      {resources.length ? (
        <div className="mt-4">
          <h3 className="font-semibold">{t("audit.event.affectedResources")}</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {resources.map((resource) => (
              <Link key={resource.to} className="rounded-control border border-border px-3 py-2 text-sm font-medium text-link underline" to={resource.to}>
                {t(resource.label)}
              </Link>
            ))}
          </div>
        </div>
      ) : null}
      <h3 className="mt-4 font-semibold">{translateNow("source.actor.449995c4fe")}</h3>
      <pre className="mt-2 max-h-40 overflow-auto rounded-md bg-muted p-3 text-xs">{formatJSON(event.actor ?? {})}</pre>
      <h3 className="mt-4 font-semibold">{translateNow("source.data.cec3a9b89b")}</h3>
      <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{formatJSON(event.data ?? {})}</pre>
    </section>
  );
}

function affectedResourceLinks(event: AuditEvent): Array<{ label: MessageKey; to: string }> {
  const data = event.data ?? {};
  const links: Array<{ label: MessageKey; to: string }> = [];
  const seen = new Set<string>();
  const add = (label: MessageKey, to: string) => {
    if (!seen.has(to)) {
      seen.add(to);
      links.push({ label, to });
    }
  };
  const value = (key: string): string => {
    const candidate = data[key];
    return typeof candidate === "string" ? candidate.trim() : "";
  };

  const identityID = value("identity_id") || value("credential_id") || (event.type.startsWith("identity.") ? value("id") : "");
  if (identityID) add("audit.event.openIdentity", `/identities?identity=${encodeURIComponent(identityID)}`);
  const ownerID = value("owner_id") || (event.type.startsWith("owner.") ? value("id") : "");
  if (ownerID) add("audit.event.openOwner", `/owners?owner=${encodeURIComponent(ownerID)}`);
  const issuerID = value("issuer_id") || (event.type.startsWith("issuer.") ? value("id") : "");
  if (issuerID) add("audit.event.openIssuer", `/protocols?issuer=${encodeURIComponent(issuerID)}`);
  return links;
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
