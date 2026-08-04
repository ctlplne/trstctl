import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  api,
  ApiError,
  type GraphImpact,
  type GraphTrustStores,
  type GraphNode,
  type GraphQueryResult,
  type GraphReachable,
  type GraphResponse,
} from "@/lib/api";
// This page renders errors in the fallback-prefixed shape ("Could not compute
// reachability: <detail>"), pinned by __tests__/operations_surface.test.tsx.
import { apiProblemContext as apiProblemMessage } from "@/lib/apiProblem";
import { CredentialChip } from "@/components/CredentialChip";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import {
  GraphView,
  canonicalGraphEdgeTypes,
  canonicalGraphNodeKinds,
  graphEdgeTypeLabel,
  graphNodeKindLabel,
  graphNodeKindStyle,
} from "@/components/GraphView";
import { PageHeader } from "@/components/PageHeader";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { BlastRadiusExplorer } from "@/components/graph";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Notice = { kind: "permission" | "error"; message: string };

export function Graph() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const [graph, setGraph] = useState<{ data: GraphResponse | null; loading: boolean; error: Notice | null }>({
    data: null,
    loading: true,
    error: null,
  });
  const [selected, setSelected] = useState(searchParams.get("node") ?? "");
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const [hiddenNodeKinds, setHiddenNodeKinds] = useState<Set<string>>(() => new Set());
  const [hiddenEdgeTypes, setHiddenEdgeTypes] = useState<Set<string>>(() => new Set());
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [reachable, setReachable] = useState<GraphReachable | null>(null);
  const [queryText, setQueryText] = useState("MATCH (a)-[e]->(b) RETURN a,b");
  const [queryResult, setQueryResult] = useState<GraphQueryResult | null>(null);
  const [activeTab, setActiveTab] = useState<"map" | "query">("map");
  const [blastError, setBlastError] = useState<string | null>(null);
  // H1: who trusts a CA. Loaded only for issuer nodes, because the question is
  // only meaningful for one — asking it of a credential and rendering an empty
  // list would read as "nothing trusts this".
  const [trustStores, setTrustStores] = useState<GraphTrustStores | null>(null);
  const [reachableError, setReachableError] = useState<string | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"analysis" | "query" | null>(null);
  const { data, loading, error } = graph;

  const nodeByID = useMemo(() => new Map((data?.nodes ?? []).map((node) => [node.id, node])), [data]);
  const kinds = useMemo(() => Array.from(new Set((data?.nodes ?? []).map((node) => node.kind))).sort(), [data]);
  const edgeTypes = useMemo(() => Array.from(new Set((data?.edges ?? []).map((edge) => edge.type))).sort(), [data]);
  const legendNodeKinds = useMemo(() => mergeCanonical(canonicalGraphNodeKinds, kinds), [kinds]);
  const legendEdgeTypes = useMemo(() => mergeCanonical(canonicalGraphEdgeTypes, edgeTypes), [edgeTypes]);
  const filteredNodes = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data?.nodes ?? []).filter((node) => {
      const kindOK = kindFilter === "all" || node.kind === kindFilter;
      const searchOK =
        !q ||
        node.id.toLowerCase().includes(q) ||
        node.name.toLowerCase().includes(q) ||
        node.kind.toLowerCase().includes(q) ||
        JSON.stringify(node.attrs ?? {})
          .toLowerCase()
          .includes(q);
      return kindOK && searchOK;
    });
  }, [data, kindFilter, search]);
  const visibleNodes = useMemo(() => filteredNodes.filter((node) => !hiddenNodeKinds.has(node.kind)), [filteredNodes, hiddenNodeKinds]);
  const visibleNodeIDs = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () => (data?.edges ?? []).filter((edge) => !hiddenEdgeTypes.has(edge.type) && visibleNodeIDs.has(edge.from) && visibleNodeIDs.has(edge.to)),
    [data, hiddenEdgeTypes, visibleNodeIDs],
  );
  const selectedNode = selected ? (nodeByID.get(selected) ?? null) : null;

  useEffect(() => {
    let active = true;
    setTrustStores(null);
    if (!selectedNode || selectedNode.kind !== "issuer") return;
    if (typeof api.graphTrustStores !== "function") return;
    api
      .graphTrustStores(selectedNode.id)
      .then((res) => {
        if (active) setTrustStores(res);
      })
      .catch(() => {
        // A failure leaves the panel absent rather than showing zero. "We could
        // not ask" and "nothing trusts this CA" are opposite answers during a
        // rollover, and a zero would be the dangerous one to show.
        if (active) setTrustStores(null);
      });
    return () => {
      active = false;
    };
  }, [selectedNode]);
  const emptyGraph = data != null && data.nodes.length === 0 && data.edges.length === 0;
  const analysisRef = useRef<HTMLDivElement>(null);
  const impactIds = useMemo(() => {
    if (!impact) return undefined;
    return new Set([impact.node.id, ...impact.affected.map((node) => node.id)]);
  }, [impact]);

  // Analysis results render in the rail next to the map; make sure they enter
  // the viewport when they arrive so the Analyze button visibly "did something".
  // (Optional call: scrollIntoView is absent in some environments, e.g. jsdom.)
  useEffect(() => {
    if (impact || reachable) analysisRef.current?.scrollIntoView?.({ behavior: "smooth", block: "nearest" });
  }, [impact, reachable]);

  useEffect(() => {
    let active = true;
    api
      .graph()
      .then((result) => active && setGraph({ data: result, loading: false, error: null }))
      .catch((err) => active && setGraph({ data: null, loading: false, error: noticeFor(err, "Could not load graph") }));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (data?.nodes?.[0] && (!selected || !nodeByID.has(selected))) setSelected(data.nodes[0].id);
  }, [data, nodeByID, selected]);

  async function runNodeAnalysisFor(id: string) {
    if (!id) return;
    setBusy("analysis");
    setBlastError(null);
    setReachableError(null);
    setImpact(null);
    setReachable(null);
    const [impactResult, reachableResult] = await Promise.allSettled([api.graphBlastRadius(id), api.graphReachable(id)]);
    if (impactResult.status === "fulfilled") {
      setImpact(impactResult.value);
    } else {
      setBlastError(apiProblemMessage(impactResult.reason, "Could not compute blast radius"));
    }
    if (reachableResult.status === "fulfilled") {
      setReachable(reachableResult.value);
    } else {
      setReachableError(apiProblemMessage(reachableResult.reason, "Could not compute reachability"));
    }
    setBusy(null);
  }

  async function runGraphQuery() {
    const query = queryText.trim();
    if (!query) return;
    setBusy("query");
    setQueryError(null);
    try {
      setQueryResult(await api.graphQuery(query));
    } catch (err) {
      setQueryError(apiProblemMessage(err, "Could not run graph query"));
    } finally {
      setBusy(null);
    }
  }

  function toggleHidden(setter: (value: Set<string>) => void, current: Set<string>, value: string) {
    const next = new Set(current);
    if (next.has(value)) {
      next.delete(value);
    } else {
      next.add(value);
    }
    setter(next);
  }

  function clearGraphFilters() {
    setHiddenNodeKinds(new Set());
    setHiddenEdgeTypes(new Set());
    setKindFilter("all");
    setSearch("");
  }

  return (
    <section aria-labelledby="graph-heading">
      <PageHeader
        titleId="graph-heading"
        title={t("nav.item.graph")}
        description="Tenant-scoped credential graph: explore nodes and edges, compute blast radius and reachability, and run read-only graph queries."
      />

      <BlastRadiusExplorer
        nodes={graph.data?.nodes ?? []}
        selectedId={selected}
        onAnalyze={(id) => {
          setSelected(id);
          void runNodeAnalysisFor(id);
        }}
      />

      {loading && <LoadingState>{translateNow("source.loading.graph.083d9e4f63")}</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title={translateNow("source.graph.unavailable.ef2233a071")}>{error.message}</ErrorState>}

      {data && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle>{translateNow("source.nodes.7ac362063b")}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold tabular-nums">{data.nodes.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>{translateNow("source.edges.658b158af9")}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold tabular-nums">{data.edges.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>{translateNow("source.blast.radius.8638fdf109")}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold tabular-nums" data-testid="blast-radius-count">
                  {impact?.affected.length ?? "-"}
                </p>
              </CardContent>
            </Card>
          </div>

          <div role="tablist" aria-label={translateNow("source.graph.workspace.9a09dc9bbf")} className="mb-5 flex flex-wrap gap-2 border-b border-border">
            <Button
              id="graph-map-tab"
              type="button"
              role="tab"
              aria-selected={activeTab === "map"}
              aria-controls="graph-map-panel"
              variant={activeTab === "map" ? "default" : "outline"}
              onClick={() => setActiveTab("map")}
            >
              {translateNow("source.map.and.analysis.12782f32f8")}
            </Button>
            <Button
              id="graph-query-tab"
              type="button"
              role="tab"
              aria-selected={activeTab === "query"}
              aria-controls="graph-query-panel"
              variant={activeTab === "query" ? "default" : "outline"}
              onClick={() => setActiveTab("query")}
            >
              {translateNow("source.advanced.query.fd7300e32b")}
            </Button>
          </div>

          {activeTab === "map" && (
            <div id="graph-map-panel" role="tabpanel" aria-labelledby="graph-map-tab">
              {emptyGraph && (
                <EmptyState title={translateNow("source.no.graph.nodes.yet.a1d126571e")} ctaTo="/certificates" ctaLabel="Open certificate inventory">
                  {translateNow("source.no.nodes.or.edges.exist.for.this.tenant.ye.1643ac2e72")}
                </EmptyState>
              )}

              {!emptyGraph && (
                <div className="my-5 grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
                  <GraphView
                    nodes={visibleNodes}
                    edges={visibleEdges}
                    selectedId={selected}
                    onSelect={setSelected}
                    impactIds={impactIds}
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

              <section aria-labelledby="graph-controls" className="ui-panel my-5 p-comfortable">
                <h2 id="graph-controls" className="mb-3 text-title font-semibold">
                  {translateNow("source.explore.nodes.4171237dea")}
                </h2>
                <div className="grid gap-3 md:grid-cols-3">
                  <label className="grid gap-1 text-sm font-medium" htmlFor="graph-search">
                    {translateNow("source.search.49c266baaa")}
                    <input
                      id="graph-search"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="rounded-md border border-border bg-background px-3 py-2"
                      placeholder={translateNow("source.name.id.kind.attribute.7d242f4e80")}
                    />
                  </label>
                  <label className="grid gap-1 text-sm font-medium" htmlFor="graph-kind">
                    {translateNow("source.kind.f5387f9bb6")}
                    <select
                      id="graph-kind"
                      value={kindFilter}
                      onChange={(e) => setKindFilter(e.target.value)}
                      className="rounded-md border border-border bg-background px-3 py-2"
                    >
                      <option value="all">{translateNow("source.all.kinds.ddd0c2108e")}</option>
                      {kinds.map((kind) => (
                        <option key={kind} value={kind}>
                          {kind}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="grid gap-1 text-sm">
                    {translateNow("source.selected.node.f8716e2fce")}
                    <p className="min-h-10 rounded-md border border-border bg-muted px-3 py-2 font-medium">
                      {selectedNode?.name || translateNow("source.no.node.selected.5eaea81a7b")}
                    </p>
                    {/* S-C11: the graph is where blast radius becomes obvious,
                        so it is where responding should start — hand the node
                        to the incident form instead of making the operator
                        copy an id across pages. */}
                    {selectedNode ? (
                      <Link className="text-brand-accent underline" to={`/incidents?identity=${encodeURIComponent(selectedNode.id)}`}>
                        {translateNow("graph.respondToNode")}
                      </Link>
                    ) : null}
                  </div>
                </div>
                <div className="mt-3">
                  {filteredNodes.length === 0 ? (
                    <p className="text-sm text-muted-foreground">{translateNow("source.no.graph.nodes.match.the.current.filters.d6f91b2251")}</p>
                  ) : (
                    <ul
                      aria-label={translateNow("source.node.search.results.7531f516c1")}
                      className="max-h-72 divide-y divide-border overflow-auto rounded-md border border-border bg-background"
                    >
                      {filteredNodes.map((node) => (
                        <li key={node.id}>
                          <button
                            type="button"
                            aria-label={translateNow("source.select.graph.node.value1.05310572fd", { value1: node.name || node.id })}
                            aria-current={selected === node.id ? "true" : undefined}
                            className={`grid w-full gap-1 px-3 py-2 text-left text-sm transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                              selected === node.id ? "bg-muted" : ""
                            }`}
                            onClick={() => setSelected(node.id)}
                          >
                            <span className="font-medium">{node.name || graphNodeKindLabel(node.kind)}</span>
                            <span className="break-all font-mono text-xs text-muted-foreground">
                              {node.kind} · {node.id}
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button type="button" loading={busy === "analysis"} disabled={!selected} onClick={() => void runNodeAnalysisFor(selected)}>
                    {translateNow("source.analyze.selected.node.9d2c6d8829")}
                  </Button>
                </div>
              </section>

              {blastError && <ErrorState title={translateNow("source.blast.radius.unavailable.8114fa5306")}>{blastError}</ErrorState>}
              {reachableError && <ErrorState title={translateNow("source.reachability.unavailable.526510e61e")}>{reachableError}</ErrorState>}

              <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
                <div className="space-y-5">
                  <table className="ui-table">
                    <caption className="sr-only">{translateNow("source.credential.graph.nodes.4c10852dfc")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{translateNow("source.name.dcd1d5223f")}</th>
                        <th scope="col">{translateNow("source.kind.f5387f9bb6")}</th>
                        <th scope="col">{translateNow("source.id.3843971dcf")}</th>
                        <th scope="col">{translateNow("source.action.64cff1319d")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredNodes.length === 0 && (
                        <tr>
                          <td colSpan={4} className="text-muted-foreground">
                            {translateNow("source.no.graph.nodes.match.the.current.filters.d6f91b2251")}
                          </td>
                        </tr>
                      )}
                      {filteredNodes.map((node) => (
                        <tr key={node.id}>
                          <td data-testid="graph-node-name">{node.name || "-"}</td>
                          <td>{node.kind}</td>
                          <td>
                            <CredentialChip value={node.id} label="node ID" />
                          </td>
                          <td>
                            <Button type="button" size="sm" variant="outline" onClick={() => setSelected(node.id)}>
                              {translateNow("source.select.2a78025de6")} {node.name || node.id}
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                  <section aria-labelledby="graph-edges-heading">
                    <h2 id="graph-edges-heading" className="mb-2 text-title font-semibold">
                      {translateNow("source.edges.658b158af9")}
                    </h2>
                    <table className="ui-table">
                      <caption className="sr-only">{translateNow("source.credential.graph.edges.3f0fea5e6d")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{translateNow("source.from.2181976934")}</th>
                          <th scope="col">{translateNow("source.type.baaddf70fb")}</th>
                          <th scope="col">{translateNow("source.to.f4b06ef6d3")}</th>
                          <th scope="col">{translateNow("source.explanation.16ee4625bc")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleEdges.length === 0 && (
                          <tr>
                            <td colSpan={4} className="text-muted-foreground">
                              {translateNow("source.no.graph.edges.match.the.current.filters.421adc32b8")}
                            </td>
                          </tr>
                        )}
                        {visibleEdges.map((edge) => (
                          <tr key={`${edge.from}-${edge.type}-${edge.to}`}>
                            <td>{nodeByID.get(edge.from)?.name ?? edge.from}</td>
                            <td className="font-mono text-xs">{edge.type}</td>
                            <td>{nodeByID.get(edge.to)?.name ?? edge.to}</td>
                            <td className="text-muted-foreground">{edgeExplanation(edge.type)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </section>
                </div>

                <div className="space-y-5">
                  <NodeDetail node={selectedNode} />
                  {trustStores && <TrustStorePanel trust={trustStores} />}
                  <div ref={analysisRef} className="space-y-5">
                    {impact && <ImpactPanel impact={impact} />}
                    {reachable && <ReachablePanel reachable={reachable} />}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "query" && (
            <section id="graph-query-panel" role="tabpanel" aria-labelledby="graph-query-tab" className="ui-panel mt-6 p-comfortable">
              <h2 id="graph-query-heading" className="text-title font-semibold">
                {translateNow("source.graph.query.e11ba75b6e")}
              </h2>
              <form
                className="mt-3 grid gap-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  void runGraphQuery();
                }}
              >
                <label className="grid gap-1 text-sm font-medium" htmlFor="graph-query">
                  {translateNow("source.cypher.style.query.9e70f5d770")}
                  <textarea
                    id="graph-query"
                    value={queryText}
                    onChange={(e) => setQueryText(e.target.value)}
                    className="min-h-24 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                  />
                </label>
                <div className="flex flex-wrap gap-2">
                  <Button type="submit" disabled={busy === "query" || !queryText.trim()}>
                    {translateNow("source.run.graph.query.3e99f2000a")}
                  </Button>
                  {queryResult && (
                    <a
                      className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
                      download="graph-query-results.json"
                      href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(queryResult.rows, null, 2))}`}
                    >
                      {translateNow("source.export.query.rows.b38bb9ef0b")}
                    </a>
                  )}
                </div>
              </form>
              {queryError && (
                <div className="mt-3">
                  <ErrorState title={translateNow("source.graph.query.unavailable.18971b61f4")}>{queryError}</ErrorState>
                </div>
              )}
              {queryResult && <pre className="mt-3 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(queryResult.rows, null, 2)}</pre>}
            </section>
          )}
        </>
      )}
    </section>
  );
}

// TrustStorePanel answers "who trusts this CA" on a selected issuer (epic H1).
function TrustStorePanel({ trust }: { trust: GraphTrustStores }) {
  return (
    <section aria-labelledby="trust-stores-heading" className="ui-panel space-y-3 p-comfortable">
      <h3 id="trust-stores-heading" className="text-title font-semibold">
        {translateNow("source.trusted.by.h1trust0001")}
      </h3>
      {/* The headline is a sentence, and it is served rather than derived here:
          two surfaces computing the same number from array lengths is how they
          come to disagree. */}
      <p className="text-sm">
        {translateNow("source.trusted.by.count.h1trust0002", {
          value1: String(trust.store_count),
          value2: String(trust.host_count),
        })}
      </p>
      {trust.store_count === 0 ? (
        <p className="text-caption text-muted-foreground">{translateNow("source.trusted.by.none.h1trust0003")}</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {trust.stores.map((store) => (
            <li key={store.id} className="flex justify-between gap-3">
              <span>{store.name}</span>
              <span className="font-mono text-xs text-muted-foreground">{String((store.attrs as Record<string, string> | undefined)?.host ?? "")}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="text-caption text-muted-foreground">{trust.guidance}</p>
    </section>
  );
}

function NodeDetail({ node }: { node: GraphNode | null }) {
  if (!node) {
    return (
      <div role="note" className="ui-panel p-comfortable text-sm text-muted-foreground">
        {translateNow("source.select.a.graph.node.to.inspect.its.attribu.fcb3894777")}
      </div>
    );
  }
  const attrRows = Object.entries(node.attrs ?? {});
  return (
    <section aria-labelledby="graph-node-detail-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="graph-node-detail-heading" className="text-title font-semibold">
        {translateNow("source.node.detail.79e07cc412")}
      </h2>
      <dl className="mt-3 grid gap-2">
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.name.dcd1d5223f")}</dt>
          <dd>{node.name || "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.kind.f5387f9bb6")}</dt>
          <dd>{node.kind}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.opaque.node.id.660e5de3ee")}</dt>
          <dd className="mt-0.5">
            <CredentialChip value={node.id} label="node ID" />
          </dd>
        </div>
      </dl>
      <h3 className="mt-4 font-semibold">{translateNow("source.attributes.4b0ed88f7d")}</h3>
      {attrRows.length > 0 ? (
        <dl className="mt-2 grid gap-2">
          {attrRows.map(([key, value]) => (
            <div key={key}>
              <dt className="font-medium text-muted-foreground">{key}</dt>
              <dd className="break-all font-mono text-xs">{displayValue(value)}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="mt-1 text-muted-foreground">{translateNow("source.no.attributes.returned.for.this.node.5b22b96afd")}</p>
      )}
      <h3 className="mt-4 font-semibold">{translateNow("source.drilldown.links.66ec8eb823")}</h3>
      <ul className="mt-2 space-y-1">
        {node.id.startsWith("cert:") && (
          <li>
            <Link className="text-brand-accent underline" to={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
              {translateNow("source.certificate.detail.8537d4ad03")}
            </Link>
          </li>
        )}
        <li>
          <Link className="text-brand-accent underline" to={`/risk?node=${encodeURIComponent(node.id)}`}>
            {translateNow("source.risk.row.992824cf5e")}
          </Link>
        </li>
        <li>
          <Link className="text-brand-accent underline" to={`/identities?node=${encodeURIComponent(node.id)}`}>
            {translateNow("source.lifecycle.identity.b788cc9a64")}
          </Link>
        </li>
        <li>
          <Link className="text-brand-accent underline" to={`/audit?node=${encodeURIComponent(node.id)}`}>
            {translateNow("source.audit.evidence.74dbcfd2a3")}
          </Link>
        </li>
      </ul>
    </section>
  );
}

function ImpactPanel({ impact }: { impact: GraphImpact }) {
  return (
    <section aria-labelledby="blast-radius-heading" className="ui-panel p-comfortable">
      <h2 id="blast-radius-heading" className="text-title font-semibold">
        {translateNow("source.blast.radius.paths.and.by.kind.summary.d6a5526110")}
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        {translateNow("source.compromising.6baa2b0ea9")} {impact.node.name || impact.node.id} {translateNow("source.affects.e3e4b7e9f8")}{" "}
        {impact.affected.length} {translateNow("source.node.545ea53846")}
        {impact.affected.length === 1 ? "" : "s"}.
      </p>
      <dl className="mt-3 grid gap-2 sm:grid-cols-3">
        {Object.entries(impact.by_kind ?? {}).map(([kind, value]) => (
          <div key={kind} className="rounded-md border border-border p-2">
            <dt className="font-medium">{kind}</dt>
            <dd>{displayValue(value)}</dd>
          </div>
        ))}
      </dl>
      <AffectedNodes nodes={impact.affected} />
    </section>
  );
}

function ReachablePanel({ reachable }: { reachable: GraphReachable }) {
  return (
    <section aria-labelledby="reachable-heading" className="ui-panel p-comfortable">
      <h2 id="reachable-heading" className="text-title font-semibold">
        {translateNow("source.reachable.nodes.ebf8d10fa5")}
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        {reachable.nodes.length} {translateNow("source.node.545ea53846")}
        {reachable.nodes.length === 1 ? "" : "s"} {translateNow("source.reachable.from.ea74f7acc4")} {reachable.from}.
      </p>
      <AffectedNodes nodes={reachable.nodes} />
    </section>
  );
}

function AffectedNodes({ nodes }: { nodes: GraphNode[] }) {
  return (
    <ul className="mt-3 grid gap-2">
      {nodes.map((node) => (
        <li key={node.id} className="rounded-md border border-border p-2">
          <p className="font-medium">{node.name || node.id}</p>
          <p className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
            <span>{node.kind}</span>
            <CredentialChip value={node.id} label="node ID" />
          </p>
          <div className="mt-1 flex flex-wrap gap-2 text-xs">
            <Link className="text-brand-accent underline" to={`/risk?node=${encodeURIComponent(node.id)}`}>
              {translateNow("source.risk.0711a8d636")}
            </Link>
            <Link className="text-brand-accent underline" to={`/audit?node=${encodeURIComponent(node.id)}`}>
              {translateNow("source.audit.bb6aea2873")}
            </Link>
            {node.id.startsWith("cert:") && (
              <Link className="text-brand-accent underline" to={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
                {translateNow("source.certificate.2a93a8a442")}
              </Link>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

function GraphLegend({
  nodeKinds,
  edgeTypes,
  hiddenNodeKinds,
  hiddenEdgeTypes,
  onToggleNodeKind,
  onToggleEdgeType,
  onClear,
}: {
  nodeKinds: string[];
  edgeTypes: string[];
  hiddenNodeKinds: Set<string>;
  hiddenEdgeTypes: Set<string>;
  onToggleNodeKind: (kind: string) => void;
  onToggleEdgeType: (type: string) => void;
  onClear: () => void;
}) {
  return (
    <section aria-labelledby="graph-legend-heading" className="rounded-panel border border-border bg-card p-4 text-sm shadow-elevation1">
      <div className="flex items-center justify-between gap-3">
        <h2 id="graph-legend-heading" className="font-semibold">
          {translateNow("source.graph.legend.f23f97006d")}
        </h2>
        <Button type="button" size="sm" variant="outline" onClick={onClear}>
          {translateNow("source.clear.filters.7179ea0035")}
        </Button>
      </div>
      <fieldset className="mt-4 grid gap-2">
        <legend className="text-xs font-semibold uppercase text-muted-foreground">{translateNow("source.node.kinds.ee50ba00ef")}</legend>
        {nodeKinds.map((kind) => {
          const style = graphNodeKindStyle(kind);
          return (
            <label key={kind} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={!hiddenNodeKinds.has(kind)}
                onChange={() => onToggleNodeKind(kind)}
                aria-label={translateNow("source.show.value1.nodes.b6e7a8266b", { value1: graphNodeKindLabel(kind) })}
              />
              <span
                className="inline-block h-3 w-3 rounded-full border"
                style={{ backgroundColor: style.fill, borderColor: style.stroke }}
                aria-hidden="true"
              />
              <span>{graphNodeKindLabel(kind)}</span>
            </label>
          );
        })}
      </fieldset>
      <fieldset className="mt-4 grid gap-2">
        <legend className="text-xs font-semibold uppercase text-muted-foreground">{translateNow("source.edge.types.396a236285")}</legend>
        {edgeTypes.map((type) => (
          <label key={type} className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={!hiddenEdgeTypes.has(type)}
              onChange={() => onToggleEdgeType(type)}
              aria-label={translateNow("source.show.value1.edges.2189dce744", { value1: graphEdgeTypeLabel(type) })}
            />
            <span className="font-mono text-xs">{type}</span>
            <span className="text-muted-foreground">{graphEdgeTypeLabel(type)}</span>
          </label>
        ))}
      </fieldset>
    </section>
  );
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function mergeCanonical(canonical: string[], served: string[]): string[] {
  return Array.from(new Set([...canonical, ...served]));
}

function edgeExplanation(type: string): string {
  switch (type) {
    case "ISSUED":
      return "The source issued or signed the target credential.";
    case "OWNS":
      return "The source owner controls or is accountable for the target.";
    case "DEPLOYED_TO":
      return "The credential is deployed to that workload or resource.";
    case "GRANTS_ACCESS":
      return "The source grants access to the target resource.";
    case "CONNECTS_TO":
      return "The source can connect to the target.";
    case "EXHIBITS":
      return "The source exhibits the target crypto asset or finding.";
    default:
      return "Served graph relationship from the backend.";
  }
}

function noticeFor(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError && err.status === 403) {
    return { kind: "permission", message: translateNow("source.your.session.cannot.read.the.credential.gr.556ee31338") };
  }
  return { kind: "error", message: apiProblemMessage(err, fallback) };
}
