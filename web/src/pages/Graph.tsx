import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, ApiError, type GraphImpact, type GraphNode, type GraphQueryResult, type GraphReachable, type GraphResponse } from "@/lib/api";
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
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Notice = { kind: "permission" | "error"; message: string };

export function Graph() {
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
  const emptyGraph = data != null && data.nodes.length === 0 && data.edges.length === 0;

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

  async function runNodeAnalysis() {
    if (!selected) return;
    setBusy("analysis");
    setBlastError(null);
    setReachableError(null);
    setImpact(null);
    setReachable(null);
    const [impactResult, reachableResult] = await Promise.allSettled([api.graphBlastRadius(selected), api.graphReachable(selected)]);
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
        title="Graph"
        description="Tenant-scoped credential graph: explore nodes and edges, compute blast radius and reachability, and run read-only graph queries."
      />

      {loading && <LoadingState>Loading graph...</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Graph unavailable">{error.message}</ErrorState>}

      {data && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle>Nodes</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold">{data.nodes.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Edges</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold">{data.edges.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Blast radius</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold" data-testid="blast-radius-count">
                  {impact?.affected.length ?? "-"}
                </p>
              </CardContent>
            </Card>
          </div>

          <div role="tablist" aria-label="Graph workspace" className="mb-5 flex flex-wrap gap-2 border-b border-border">
            <Button
              id="graph-map-tab"
              type="button"
              role="tab"
              aria-selected={activeTab === "map"}
              aria-controls="graph-map-panel"
              variant={activeTab === "map" ? "default" : "outline"}
              onClick={() => setActiveTab("map")}
            >
              Map and analysis
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
              Advanced query
            </Button>
          </div>

          {activeTab === "map" && (
            <div id="graph-map-panel" role="tabpanel" aria-labelledby="graph-map-tab">
              {emptyGraph && (
                <EmptyState title="No graph nodes yet" ctaTo="/certificates" ctaLabel="Open certificate inventory">
                  No nodes or edges exist for this tenant yet. Ingest certificates or issue identities first.
                </EmptyState>
              )}

              {!emptyGraph && (
                <div className="my-5 grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
                  <GraphView nodes={visibleNodes} edges={visibleEdges} selectedId={selected} onSelect={setSelected} />
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
              Explore nodes
            </h2>
            <div className="grid gap-3 md:grid-cols-3">
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-search">
                Search
                <input
                  id="graph-search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2"
                  placeholder="name, id, kind, attribute"
                />
              </label>
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-kind">
                Kind
                <select
                  id="graph-kind"
                  value={kindFilter}
                  onChange={(e) => setKindFilter(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2"
                >
                  <option value="all">All kinds</option>
                  {kinds.map((kind) => (
                    <option key={kind} value={kind}>
                      {kind}
                    </option>
                  ))}
                </select>
              </label>
              <div className="grid gap-1 text-sm">
                Selected node
                <p className="min-h-10 rounded-md border border-border bg-muted px-3 py-2 font-medium">{selectedNode?.name || "No node selected"}</p>
              </div>
            </div>
            <div className="mt-3">
              {filteredNodes.length === 0 ? (
                <p className="text-sm text-muted-foreground">No graph nodes match the current filters.</p>
              ) : (
                <ul aria-label="Node search results" className="max-h-72 divide-y divide-border overflow-auto rounded-md border border-border bg-background">
                  {filteredNodes.map((node) => (
                    <li key={node.id}>
                      <button
                        type="button"
                        aria-label={`Select graph node ${node.name || node.id}`}
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
              <Button type="button" disabled={busy === "analysis" || !selected} onClick={() => void runNodeAnalysis()}>
                Analyze selected node
              </Button>
            </div>
          </section>

          {blastError && <ErrorState title="Blast radius unavailable">{blastError}</ErrorState>}
          {reachableError && <ErrorState title="Reachability unavailable">{reachableError}</ErrorState>}

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
            <div className="space-y-5">
              <table className="ui-table">
                <caption className="sr-only">Credential graph nodes</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Kind</th>
                    <th scope="col">ID</th>
                    <th scope="col">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredNodes.length === 0 && (
                    <tr>
                      <td colSpan={4} className="text-muted-foreground">
                        No graph nodes match the current filters.
                      </td>
                    </tr>
                  )}
                  {filteredNodes.map((node) => (
                    <tr key={node.id}>
                      <td data-testid="graph-node-name">{node.name || "-"}</td>
                      <td>{node.kind}</td>
                      <td className="font-mono text-xs">{node.id}</td>
                      <td>
                        <Button type="button" size="sm" variant="outline" onClick={() => setSelected(node.id)}>
                          Select {node.name || node.id}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <section aria-labelledby="graph-edges-heading">
                <h2 id="graph-edges-heading" className="mb-2 text-title font-semibold">
                  Edges
                </h2>
                <table className="ui-table">
                  <caption className="sr-only">Credential graph edges</caption>
                  <thead>
                    <tr>
                      <th scope="col">From</th>
                      <th scope="col">Type</th>
                      <th scope="col">To</th>
                      <th scope="col">Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.edges.length === 0 && (
                      <tr>
                        <td colSpan={4} className="text-muted-foreground">
                          No graph edges returned.
                        </td>
                      </tr>
                    )}
                    {data.edges.map((edge) => (
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

            <NodeDetail node={selectedNode} />
          </div>

          {impact && <ImpactPanel impact={impact} />}
          {reachable && <ReachablePanel reachable={reachable} />}
            </div>
          )}

          {activeTab === "query" && (
          <section id="graph-query-panel" role="tabpanel" aria-labelledby="graph-query-tab" className="ui-panel mt-6 p-comfortable">
            <h2 id="graph-query-heading" className="text-title font-semibold">
              Graph query
            </h2>
            <form
              className="mt-3 grid gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                void runGraphQuery();
              }}
            >
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-query">
                Cypher-style query
                <textarea
                  id="graph-query"
                  value={queryText}
                  onChange={(e) => setQueryText(e.target.value)}
                  className="min-h-24 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                />
              </label>
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={busy === "query" || !queryText.trim()}>
                  Run graph query
                </Button>
                {queryResult && (
                  <a
                    className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
                    download="graph-query-results.json"
                    href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(queryResult.rows, null, 2))}`}
                  >
                    Export query rows
                  </a>
                )}
              </div>
            </form>
            {queryError && (
              <div className="mt-3">
                <ErrorState title="Graph query unavailable">{queryError}</ErrorState>
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

function NodeDetail({ node }: { node: GraphNode | null }) {
  if (!node) {
    return <aside className="ui-panel p-comfortable text-sm text-muted-foreground">Select a graph node to inspect its attributes and drilldown links.</aside>;
  }
  const attrRows = Object.entries(node.attrs ?? {});
  return (
    <aside aria-labelledby="graph-node-detail-heading" className="ui-panel p-comfortable text-sm">
      <h2 id="graph-node-detail-heading" className="text-title font-semibold">
        Node detail
      </h2>
      <dl className="mt-3 grid gap-2">
        <div>
          <dt className="font-medium text-muted-foreground">Name</dt>
          <dd>{node.name || "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Kind</dt>
          <dd>{node.kind}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Opaque node ID</dt>
          <dd className="break-all font-mono text-xs">{node.id}</dd>
        </div>
      </dl>
      <h3 className="mt-4 font-semibold">Attributes</h3>
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
        <p className="mt-1 text-muted-foreground">No attributes returned for this node.</p>
      )}
      <h3 className="mt-4 font-semibold">Drilldown links</h3>
      <ul className="mt-2 space-y-1">
        {node.id.startsWith("cert:") && (
          <li>
            <a className="text-primary underline" href={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
              Certificate detail
            </a>
          </li>
        )}
        <li>
          <a className="text-primary underline" href={`/risk?node=${encodeURIComponent(node.id)}`}>
            Risk row
          </a>
        </li>
        <li>
          <a className="text-primary underline" href={`/identities?node=${encodeURIComponent(node.id)}`}>
            Lifecycle identity
          </a>
        </li>
        <li>
          <a className="text-primary underline" href={`/audit?node=${encodeURIComponent(node.id)}`}>
            Audit evidence
          </a>
        </li>
      </ul>
    </aside>
  );
}

function ImpactPanel({ impact }: { impact: GraphImpact }) {
  return (
    <section aria-labelledby="blast-radius-heading" className="ui-panel mt-6 p-comfortable">
      <h2 id="blast-radius-heading" className="text-title font-semibold">
        Blast-radius paths and by-kind summary
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        Compromising {impact.node.name || impact.node.id} affects {impact.affected.length} node{impact.affected.length === 1 ? "" : "s"}.
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
    <section aria-labelledby="reachable-heading" className="ui-panel mt-6 p-comfortable">
      <h2 id="reachable-heading" className="text-title font-semibold">
        Reachable nodes
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        {reachable.nodes.length} node{reachable.nodes.length === 1 ? "" : "s"} reachable from {reachable.from}.
      </p>
      <AffectedNodes nodes={reachable.nodes} />
    </section>
  );
}

function AffectedNodes({ nodes }: { nodes: GraphNode[] }) {
  return (
    <ul className="mt-3 grid gap-2 md:grid-cols-2">
      {nodes.map((node) => (
        <li key={node.id} className="rounded-md border border-border p-2">
          <p className="font-medium">{node.name || node.id}</p>
          <p className="font-mono text-xs text-muted-foreground">
            {node.kind} · {node.id}
          </p>
          <div className="mt-1 flex flex-wrap gap-2 text-xs">
            <a className="text-primary underline" href={`/risk?node=${encodeURIComponent(node.id)}`}>
              Risk
            </a>
            <a className="text-primary underline" href={`/audit?node=${encodeURIComponent(node.id)}`}>
              Audit
            </a>
            {node.id.startsWith("cert:") && (
              <a className="text-primary underline" href={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
                Certificate
              </a>
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
    <aside aria-labelledby="graph-legend-heading" className="rounded-panel border border-border bg-card p-4 text-sm shadow-elevation1">
      <div className="flex items-center justify-between gap-3">
        <h2 id="graph-legend-heading" className="font-semibold">
          Graph legend
        </h2>
        <Button type="button" size="sm" variant="outline" onClick={onClear}>
          Clear filters
        </Button>
      </div>
      <fieldset className="mt-4 grid gap-2">
        <legend className="text-xs font-semibold uppercase text-muted-foreground">Node kinds</legend>
        {nodeKinds.map((kind) => {
          const style = graphNodeKindStyle(kind);
          return (
            <label key={kind} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={!hiddenNodeKinds.has(kind)}
                onChange={() => onToggleNodeKind(kind)}
                aria-label={`Show ${graphNodeKindLabel(kind)} nodes`}
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
        <legend className="text-xs font-semibold uppercase text-muted-foreground">Edge types</legend>
        {edgeTypes.map((type) => (
          <label key={type} className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={!hiddenEdgeTypes.has(type)}
              onChange={() => onToggleEdgeType(type)}
              aria-label={`Show ${graphEdgeTypeLabel(type)} edges`}
            />
            <span className="font-mono text-xs">{type}</span>
            <span className="text-muted-foreground">{graphEdgeTypeLabel(type)}</span>
          </label>
        ))}
      </fieldset>
    </aside>
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
    return { kind: "permission", message: "Your session cannot read the credential graph for this tenant." };
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
