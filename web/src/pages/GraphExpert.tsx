import { Link } from "react-router-dom";
import type { GraphNode, GraphQueryResult, GraphReachable, GraphResponse, GraphTrustStores } from "@/lib/api";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState } from "@/components/StatePrimitives";
import { graphEdgeTypeLabel, graphNodeKindLabel, graphNodeKindStyle } from "@/components/GraphView";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { translateNow } from "@/i18n/I18nProvider";

export function EdgeEvidenceTable({ edges, nodeByID }: { edges: GraphResponse["edges"]; nodeByID: Map<string, GraphNode> }) {
  return (
    <div className="min-w-0 max-w-full overflow-x-auto">
      <table className="ui-table">
        <caption className="sr-only">{translateNow("source.credential.graph.edges.3f0fea5e6d")}</caption>
        <thead>
          <tr>
            <th scope="col">{translateNow("source.from.2181976934")}</th>
            <th scope="col">{translateNow("source.type.baaddf70fb")}</th>
            <th scope="col">{translateNow("source.to.f4b06ef6d3")}</th>
            <th scope="col">{translateNow("source.source.0e570ca6fa")}</th>
            <th scope="col">{translateNow("graph.design.confidence")}</th>
            <th scope="col">{translateNow("source.explanation.16ee4625bc")}</th>
          </tr>
        </thead>
        <tbody>
          {edges.length === 0 ? (
            <tr>
              <td colSpan={6} className="text-muted-foreground">
                {translateNow("source.no.graph.edges.match.the.current.filters.421adc32b8")}
              </td>
            </tr>
          ) : null}
          {edges.map((edge) => (
            <tr key={`${edge.from}-${edge.type}-${edge.to}`}>
              <td>{nodeByID.get(edge.from)?.name ?? edge.from}</td>
              <td className="font-mono text-xs">{edge.type}</td>
              <td>{nodeByID.get(edge.to)?.name ?? edge.to}</td>
              <td>{edge.source || translateNow("source.workload.api.unreported.b3wla0009")}</td>
              <td>{confidenceLabel(edge.confidence)}</td>
              <td className="text-muted-foreground">{edgeExplanation(edge.type)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function NodeInventory({ nodes, selected, onSelect }: { nodes: GraphNode[]; selected: string; onSelect: (id: string) => void }) {
  return (
    <div className="min-w-0 max-w-full overflow-x-auto">
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
          {nodes.length === 0 ? (
            <tr>
              <td colSpan={4} className="text-muted-foreground">
                {translateNow("source.no.graph.nodes.match.the.current.filters.d6f91b2251")}
              </td>
            </tr>
          ) : null}
          {nodes.map((node) => (
            <tr key={node.id} aria-current={selected === node.id ? "true" : undefined}>
              <td data-testid="graph-node-name">{node.name || "-"}</td>
              <td>{graphNodeKindLabel(node.kind)}</td>
              <td>
                <CredentialChip value={node.id} label="node ID" />
              </td>
              <td>
                <Button type="button" size="sm" variant="outline" onClick={() => onSelect(node.id)}>
                  {translateNow("source.select.2a78025de6")} {node.name || node.id}
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function GraphQuery({
  queryText,
  queryResult,
  queryError,
  busy,
  onChange,
  onRun,
}: {
  queryText: string;
  queryResult: GraphQueryResult | null;
  queryError: string | null;
  busy: boolean;
  onChange: (value: string) => void;
  onRun: () => void;
}) {
  return (
    <section aria-labelledby="graph-query-heading" className="ui-panel p-comfortable">
      <h2 id="graph-query-heading" className="text-title font-semibold">
        {translateNow("source.graph.query.e11ba75b6e")}
      </h2>
      <form
        className="mt-3 grid gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          onRun();
        }}
      >
        <label className="grid gap-1 text-sm font-medium" htmlFor="graph-query">
          {translateNow("source.cypher.style.query.9e70f5d770")}
          <Textarea id="graph-query" value={queryText} onChange={(event) => onChange(event.target.value)} className="min-h-24 font-mono text-xs" />
        </label>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={busy || !queryText.trim()}>
            {translateNow("source.run.graph.query.3e99f2000a")}
          </Button>
          {queryResult ? (
            <a
              className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
              download="graph-query-results.json"
              href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(queryResult.rows, null, 2))}`}
            >
              {translateNow("source.export.query.rows.b38bb9ef0b")}
            </a>
          ) : null}
        </div>
      </form>
      {queryError ? (
        <div className="mt-3">
          <ErrorState title={translateNow("source.graph.query.unavailable.18971b61f4")}>{queryError}</ErrorState>
        </div>
      ) : null}
      {queryResult ? <pre className="mt-3 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(queryResult.rows, null, 2)}</pre> : null}
    </section>
  );
}

export function NodeDetail({ node, trustStores }: { node: GraphNode | null; trustStores: GraphTrustStores | null }) {
  if (!node)
    return (
      <div className="ui-panel p-comfortable text-sm text-muted-foreground">{translateNow("source.select.a.graph.node.to.inspect.its.attribu.fcb3894777")}</div>
    );
  const attrRows = Object.entries(node.attrs ?? {});
  return (
    <div className="grid content-start gap-5">
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
            <dd>{graphNodeKindLabel(node.kind)}</dd>
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
          {node.id.startsWith("cert:") ? (
            <li>
              <Link className="text-brand-accent underline" to={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
                {translateNow("source.certificate.detail.8537d4ad03")}
              </Link>
            </li>
          ) : null}
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
          <li>
            <Link className="text-brand-accent underline" to={`/incidents?identity=${encodeURIComponent(node.id)}`}>
              {translateNow("graph.respondToNode")}
            </Link>
          </li>
        </ul>
      </section>
      {trustStores ? <TrustStorePanel trust={trustStores} /> : null}
    </div>
  );
}

function TrustStorePanel({ trust }: { trust: GraphTrustStores }) {
  return (
    <section aria-labelledby="trust-stores-heading" className="ui-panel space-y-3 p-comfortable">
      <h3 id="trust-stores-heading" className="text-title font-semibold">
        {translateNow("source.trusted.by.h1trust0001")}
      </h3>
      <p className="text-sm">{translateNow("source.trusted.by.count.h1trust0002", { value1: String(trust.store_count), value2: String(trust.host_count) })}</p>
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

export function ReachablePanel({ reachable }: { reachable: GraphReachable }) {
  return (
    <section aria-labelledby="reachable-heading" className="ui-panel p-comfortable">
      <h2 id="reachable-heading" className="text-title font-semibold">
        {translateNow("source.reachable.nodes.ebf8d10fa5")}
      </h2>
      <AffectedNodes nodes={reachable.nodes} />
    </section>
  );
}

function AffectedNodes({ nodes }: { nodes: GraphNode[] }) {
  if (nodes.length === 0) return null;
  return (
    <ul className="mt-3 grid gap-2">
      {nodes.map((node) => (
        <li key={node.id} className="rounded-md border border-border p-2">
          <p className="font-medium">{node.name || node.id}</p>
          <p className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
            <span>{graphNodeKindLabel(node.kind)}</span>
            <CredentialChip value={node.id} label="node ID" />
          </p>
        </li>
      ))}
    </ul>
  );
}

export function GraphLegend({
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
        <legend className="text-xs font-semibold text-muted-foreground">{translateNow("source.node.kinds.ee50ba00ef")}</legend>
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
        <legend className="text-xs font-semibold text-muted-foreground">{translateNow("source.edge.types.396a236285")}</legend>
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

function confidenceLabel(value?: string): string {
  if (!value) return translateNow("source.workload.api.unreported.b3wla0009");
  return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
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

function edgeExplanation(type: string): string {
  switch (type) {
    case "ISSUED":
      return "The source issued or signed the target credential.";
    case "OWNS":
      return "The source owner controls or is accountable for the target.";
    case "DEPLOYED_TO":
      return "The credential is deployed to that workload or resource.";
    case "GRANTS_ACCESS":
      return "The credential can authenticate to the target resource.";
    case "CONNECTS_TO":
      return "The source relies on or connects to the target.";
    case "EXHIBITS":
      return "The source exhibits the target cryptographic asset.";
    case "TRUSTS":
      return "The trust store contains this exact authority or anchor.";
    case "UNVERIFIED_TRUST_CANDIDATE":
      return "The subject matched, but exact public identity was not verified.";
    case "HOSTS":
      return "The resource hosts this trust store.";
    default:
      return "Served graph relationship from the backend.";
  }
}
