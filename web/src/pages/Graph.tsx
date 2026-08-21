import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { api, ApiError, type GraphImpact, type GraphQueryResult, type GraphReachable, type GraphResponse, type GraphTrustStores } from "@/lib/api";
import { apiProblemContext as apiProblemMessage } from "@/lib/apiProblem";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { GraphView, canonicalGraphEdgeTypes, canonicalGraphNodeKinds, graphNodeKindLabel } from "@/components/GraphView";
import { PageHeader } from "@/components/PageHeader";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { EdgeEvidenceTable, GraphLegend, GraphQuery, NodeDetail, NodeInventory, ReachablePanel } from "@/pages/GraphExpert";

type Notice = { kind: "permission" | "error"; message: string };
type Disclosure = "map" | "evidence" | "inventory";

export function Graph() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const requestedNode = searchParams.get("node") ?? "";
  const [graph, setGraph] = useState<{ data: GraphResponse | null; loading: boolean; error: Notice | null }>({
    data: null,
    loading: true,
    error: null,
  });
  const [selected, setSelected] = useState("");
  const [inspected, setInspected] = useState(requestedNode);
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const [hiddenNodeKinds, setHiddenNodeKinds] = useState<Set<string>>(() => new Set());
  const [hiddenEdgeTypes, setHiddenEdgeTypes] = useState<Set<string>>(() => new Set());
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [reachable, setReachable] = useState<GraphReachable | null>(null);
  const [trustStores, setTrustStores] = useState<GraphTrustStores | null>(null);
  const [queryText, setQueryText] = useState("MATCH (a)-[e]->(b) RETURN a,b");
  const [queryResult, setQueryResult] = useState<GraphQueryResult | null>(null);
  const [blastError, setBlastError] = useState<string | null>(null);
  const [reachableError, setReachableError] = useState<string | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"analysis" | "query" | null>(null);
  const [open, setOpen] = useState<Record<Disclosure, boolean>>({ map: false, evidence: false, inventory: false });
  const resultRef = useRef<HTMLDivElement>(null);
  const { data, loading, error } = graph;

  const nodeByID = useMemo(() => new Map((data?.nodes ?? []).map((node) => [node.id, node])), [data]);
  const credentialNodes = useMemo(() => (data?.nodes ?? []).filter((node) => node.kind === "credential"), [data]);
  const kinds = useMemo(() => Array.from(new Set((data?.nodes ?? []).map((node) => node.kind))).sort(), [data]);
  const edgeTypes = useMemo(() => Array.from(new Set((data?.edges ?? []).map((edge) => edge.type))).sort(), [data]);
  const legendNodeKinds = useMemo(() => mergeCanonical(canonicalGraphNodeKinds, kinds), [kinds]);
  const legendEdgeTypes = useMemo(() => mergeCanonical(canonicalGraphEdgeTypes, edgeTypes), [edgeTypes]);
  const filteredNodes = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (data?.nodes ?? []).filter((node) => {
      const kindMatches = kindFilter === "all" || node.kind === kindFilter;
      const textMatches =
        !query ||
        node.id.toLowerCase().includes(query) ||
        node.name.toLowerCase().includes(query) ||
        node.kind.toLowerCase().includes(query) ||
        JSON.stringify(node.attrs ?? {})
          .toLowerCase()
          .includes(query);
      return kindMatches && textMatches;
    });
  }, [data, kindFilter, search]);
  const visibleNodes = useMemo(() => filteredNodes.filter((node) => !hiddenNodeKinds.has(node.kind)), [filteredNodes, hiddenNodeKinds]);
  const visibleNodeIDs = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () => (data?.edges ?? []).filter((edge) => !hiddenEdgeTypes.has(edge.type) && visibleNodeIDs.has(edge.from) && visibleNodeIDs.has(edge.to)),
    [data, hiddenEdgeTypes, visibleNodeIDs],
  );
  const inspectedNode = inspected ? (nodeByID.get(inspected) ?? null) : null;
  const impactIDs = useMemo(() => (impact ? new Set([impact.node.id, ...impact.affected.map((node) => node.id)]) : undefined), [impact]);
  const evidenceEdges = useMemo(() => {
    if (!data || !impact) return data?.edges ?? [];
    const relevant = new Set([impact.node.id, ...impact.affected.map((node) => node.id)]);
    return data.edges.filter((edge) => relevant.has(edge.from) || relevant.has(edge.to));
  }, [data, impact]);
  const emptyGraph = data != null && data.nodes.length === 0 && data.edges.length === 0;

  useEffect(() => {
    let active = true;
    api
      .graph()
      .then((result) => active && setGraph({ data: result, loading: false, error: null }))
      .catch((reason) => active && setGraph({ data: null, loading: false, error: noticeFor(reason, "Could not load graph") }));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!data || credentialNodes.length === 0 || nodeByID.get(selected)?.kind === "credential") return;
    const outgoing = new Set(data.edges.map((edge) => edge.from));
    const usefulDefault = credentialNodes.find((node) => outgoing.has(node.id)) ?? credentialNodes[0];
    setSelected(usefulDefault.id);
  }, [credentialNodes, data, nodeByID, selected]);

  useEffect(() => {
    if (!data || data.nodes.length === 0 || (inspected && nodeByID.has(inspected))) return;
    setInspected(selected || data.nodes[0].id);
  }, [data, inspected, nodeByID, selected]);

  useEffect(() => {
    let active = true;
    setTrustStores(null);
    if (!inspectedNode || inspectedNode.kind !== "issuer" || typeof api.graphTrustStores !== "function") return;
    api
      .graphTrustStores(inspectedNode.id)
      .then((result) => active && setTrustStores(result))
      .catch(() => active && setTrustStores(null));
    return () => {
      active = false;
    };
  }, [inspectedNode]);

  useEffect(() => {
    if (impact || blastError || reachableError) resultRef.current?.scrollIntoView?.({ behavior: "smooth", block: "nearest" });
  }, [blastError, impact, reachableError]);

  function selectNode(id: string) {
    setSelected(id);
    setInspected(id);
    setImpact(null);
    setReachable(null);
    setBlastError(null);
    setReachableError(null);
  }

  async function runNodeAnalysis() {
    if (!selected) return;
    setBusy("analysis");
    setBlastError(null);
    setReachableError(null);
    setImpact(null);
    setReachable(null);
    const [impactResult, reachableResult] = await Promise.allSettled([api.graphBlastRadius(selected), api.graphReachable(selected)]);
    if (impactResult.status === "fulfilled") setImpact(impactResult.value);
    else setBlastError(apiProblemMessage(impactResult.reason, "Could not compute blast radius"));
    if (reachableResult.status === "fulfilled") setReachable(reachableResult.value);
    else setReachableError(apiProblemMessage(reachableResult.reason, "Could not compute reachability"));
    setBusy(null);
  }

  async function runGraphQuery() {
    const query = queryText.trim();
    if (!query) return;
    setBusy("query");
    setQueryError(null);
    try {
      setQueryResult(await api.graphQuery(query));
    } catch (reason) {
      setQueryError(apiProblemMessage(reason, "Could not run graph query"));
    } finally {
      setBusy(null);
    }
  }

  function toggleHidden(setter: (value: Set<string>) => void, current: Set<string>, value: string) {
    const next = new Set(current);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    setter(next);
  }

  function clearGraphFilters() {
    setHiddenNodeKinds(new Set());
    setHiddenEdgeTypes(new Set());
    setKindFilter("all");
    setSearch("");
  }

  const exportEvidence = impact
    ? {
        selected_credential: impact.node,
        known_affected_systems: impact.affected,
        affected_by_kind: impact.by_kind,
        reachable_nodes: reachable?.nodes ?? [],
        relationships: evidenceEdges,
        coverage_note: t("graph.design.coverage"),
      }
    : null;

  return (
    <section aria-labelledby="graph-heading" className="grid min-w-0 w-full max-w-full gap-4">
      <PageHeader
        titleId="graph-heading"
        title={t("nav.item.graph")}
        description={t("graph.design.answer")}
        technicalDetails={t("graph.design.technicalDetails")}
        actions={
          <Button type="button" loading={busy === "analysis"} disabled={!selected} onClick={() => void runNodeAnalysis()}>
            {t("graph.design.exploreImpact")}
          </Button>
        }
      />

      {loading && <LoadingState>{translateNow("source.loading.graph.083d9e4f63")}</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title={translateNow("source.graph.unavailable.ef2233a071")}>{error.message}</ErrorState>}

      {data && (
        <>
          <div className="ui-panel grid gap-4 p-comfortable">
            <div className="grid gap-3 md:grid-cols-[minmax(16rem,32rem)]">
              <label className="grid gap-1 text-sm font-medium" htmlFor="impact-credential">
                {t("graph.design.credentialLabel")}
                <Select id="impact-credential" value={selected} disabled={credentialNodes.length === 0} onChange={(event) => selectNode(event.target.value)}>
                  {credentialNodes.length === 0 ? <option value="">{translateNow("operations.jobs.redemptions.none")}</option> : null}
                  {credentialNodes.map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.name || graphNodeKindLabel(node.kind)} · {graphNodeKindLabel(node.kind)}
                    </option>
                  ))}
                </Select>
              </label>
            </div>

            {emptyGraph ? (
              <EmptyState title={translateNow("source.no.graph.nodes.yet.a1d126571e")} ctaTo="/certificates" ctaLabel="Open certificate inventory">
                {translateNow("source.no.nodes.or.edges.exist.for.this.tenant.ye.1643ac2e72")}
              </EmptyState>
            ) : (
              <div ref={resultRef} className="rounded-panel border border-border bg-muted/30 p-4" aria-live="polite">
                {!impact && !blastError ? <h2 className="text-title font-semibold">{translateNow("source.not.checked.d3tri00006")}</h2> : null}
                {impact ? <ImpactAnswer impact={impact} /> : null}
                <p className="mt-3 max-w-3xl text-caption text-muted-foreground">{t("graph.design.coverage")}</p>
              </div>
            )}
          </div>

          {blastError && <ErrorState title={translateNow("source.blast.radius.unavailable.8114fa5306")}>{blastError}</ErrorState>}
          {reachableError && <ErrorState title={translateNow("source.reachability.unavailable.526510e61e")}>{reachableError}</ErrorState>}

          <DecisionDisclosure title={t("graph.design.disclosure.map")} open={open.map} onToggle={(value) => setOpen((current) => ({ ...current, map: value }))}>
            {emptyGraph ? null : (
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
                <GraphView
                  nodes={visibleNodes}
                  edges={visibleEdges}
                  selectedId={inspected}
                  onSelect={setInspected}
                  impactIds={impactIDs}
                  focusId={impact?.node.id}
                />
                <GraphLegend
                  nodeKinds={legendNodeKinds}
                  edgeTypes={legendEdgeTypes}
                  hiddenNodeKinds={hiddenNodeKinds}
                  hiddenEdgeTypes={hiddenEdgeTypes}
                  onToggleNodeKind={(kind) => toggleHidden(setHiddenNodeKinds, hiddenNodeKinds, kind)}
                  onToggleEdgeType={(type) => toggleHidden(setHiddenEdgeTypes, hiddenEdgeTypes, type)}
                  onClear={clearGraphFilters}
                />
              </div>
            )}
          </DecisionDisclosure>

          <DecisionDisclosure
            title={t("graph.design.disclosure.evidence")}
            open={open.evidence}
            onToggle={(value) => setOpen((current) => ({ ...current, evidence: value }))}
          >
            <div className="grid gap-5">
              <div className="flex flex-wrap items-center justify-end gap-3">
                {exportEvidence ? (
                  <a
                    className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm font-medium underline"
                    download={`blast-radius-${downloadSlug(impact?.node.name || impact?.node.id || "selected")}.json`}
                    href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(exportEvidence, null, 2))}`}
                  >
                    {t("graph.design.export")}
                  </a>
                ) : null}
              </div>
              <EdgeEvidenceTable edges={evidenceEdges} nodeByID={nodeByID} />
              {reachable ? <ReachablePanel reachable={reachable} /> : null}
            </div>
          </DecisionDisclosure>

          <DecisionDisclosure
            title={t("graph.design.disclosure.inventory")}
            open={open.inventory}
            onToggle={(value) => setOpen((current) => ({ ...current, inventory: value }))}
          >
            <div className="grid gap-5">
              <section aria-labelledby="graph-controls" className="grid gap-3">
                <h2 id="graph-controls" className="text-title font-semibold">
                  {translateNow("source.explore.nodes.4171237dea")}
                </h2>
                <div className="grid gap-3 md:grid-cols-2">
                  <label className="grid gap-1 text-sm font-medium" htmlFor="graph-search">
                    {translateNow("source.search.49c266baaa")}
                    <Input
                      id="graph-search"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder={translateNow("source.name.id.kind.attribute.7d242f4e80")}
                    />
                  </label>
                  <label className="grid gap-1 text-sm font-medium" htmlFor="graph-kind">
                    {translateNow("source.kind.f5387f9bb6")}
                    <Select id="graph-kind" value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}>
                      <option value="all">{translateNow("source.all.kinds.ddd0c2108e")}</option>
                      {kinds.map((kind) => (
                        <option key={kind} value={kind}>
                          {graphNodeKindLabel(kind)}
                        </option>
                      ))}
                    </Select>
                  </label>
                </div>
                <NodeInventory nodes={filteredNodes} selected={inspected} onSelect={setInspected} />
              </section>

              <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
                <GraphQuery
                  queryText={queryText}
                  queryResult={queryResult}
                  queryError={queryError}
                  busy={busy === "query"}
                  onChange={setQueryText}
                  onRun={() => void runGraphQuery()}
                />
                <NodeDetail node={inspectedNode} trustStores={trustStores} />
              </div>
            </div>
          </DecisionDisclosure>
        </>
      )}
    </section>
  );
}

function DecisionDisclosure({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      <div className="border-t border-border p-4" hidden={!open}>
        {open ? children : null}
      </div>
    </details>
  );
}

function ImpactAnswer({ impact }: { impact: GraphImpact }) {
  const count = impact.affected.length;
  return (
    <>
      <h2 className="text-title font-semibold">
        {count === 1 ? translateNow("graph.design.resultOne") : translateNow("graph.design.resultMany", { count: String(count) })}
      </h2>
      {count === 0 ? null : (
        <ul className="mt-3 grid gap-2 sm:grid-cols-2">
          {impact.affected.map((node) => (
            <li key={node.id} className="rounded-md border border-border bg-background px-3 py-2">
              <p className="font-medium">{node.name || graphNodeKindLabel(node.kind)}</p>
              <p className="text-caption text-muted-foreground">{graphNodeKindLabel(node.kind)}</p>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function mergeCanonical(canonical: string[], served: string[]): string[] {
  return Array.from(new Set([...canonical, ...served]));
}

function downloadSlug(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "selected"
  );
}

function noticeFor(reason: unknown, fallback: string): Notice {
  if (reason instanceof ApiError && reason.status === 403) {
    return { kind: "permission", message: translateNow("source.your.session.cannot.read.the.credential.gr.556ee31338") };
  }
  return { kind: "error", message: apiProblemMessage(reason, fallback) };
}
