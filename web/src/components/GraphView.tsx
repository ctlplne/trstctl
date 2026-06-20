import type { KeyboardEvent } from "react";
import type { GraphNode, GraphResponse } from "@/lib/api";
import { cn } from "@/lib/utils";

type GraphEdge = GraphResponse["edges"][number];

type PositionedNode = GraphNode & {
  x: number;
  y: number;
};

export type GraphViewProps = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId?: string;
  onSelect: (nodeId: string) => void;
  className?: string;
};

const nodeKindTokens: Record<string, { label: string; fill: string; stroke: string }> = {
  workload: { label: "Workload", fill: "hsl(var(--operate) / 0.14)", stroke: "hsl(var(--operate))" },
  credential: { label: "Credential", fill: "hsl(var(--risk-high) / 0.14)", stroke: "hsl(var(--risk-high))" },
  resource: { label: "Resource", fill: "hsl(var(--observe) / 0.14)", stroke: "hsl(var(--observe))" },
  issuer: { label: "Issuer", fill: "hsl(var(--status-info) / 0.14)", stroke: "hsl(var(--status-info))" },
  "crypto-asset": { label: "Crypto asset", fill: "hsl(var(--disclose) / 0.14)", stroke: "hsl(var(--disclose))" },
  attestation: { label: "Attestation", fill: "hsl(var(--status-success) / 0.14)", stroke: "hsl(var(--status-success))" },
};

const edgeLabels: Record<string, string> = {
  ISSUED: "Issued",
  OWNS: "Owns",
  DEPLOYED_TO: "Deployed to",
  GRANTS_ACCESS: "Grants access",
  CONNECTS_TO: "Connects to",
  EXHIBITS: "Exhibits",
};

export const canonicalGraphNodeKinds = ["workload", "credential", "resource", "issuer", "crypto-asset", "attestation"];
export const canonicalGraphEdgeTypes = ["ISSUED", "OWNS", "DEPLOYED_TO", "GRANTS_ACCESS", "CONNECTS_TO", "EXHIBITS"];

export function graphNodeKindLabel(kind: string): string {
  return nodeKindTokens[kind]?.label ?? humanize(kind);
}

export function graphNodeKindStyle(kind: string) {
  return nodeKindTokens[kind] ?? {
    label: humanize(kind),
    fill: "hsl(var(--muted))",
    stroke: "hsl(var(--muted-foreground))",
  };
}

export function graphEdgeTypeLabel(type: string): string {
  return edgeLabels[type] ?? humanize(type);
}

export function GraphView({ nodes, edges, selectedId, onSelect, className }: GraphViewProps) {
  const positioned = layoutNodes(nodes);
  const nodeByID = new Map(positioned.map((node) => [node.id, node]));
  const visibleEdges = edges.filter((edge) => nodeByID.has(edge.from) && nodeByID.has(edge.to));

  if (nodes.length === 0) {
    return (
      <div className={cn("rounded-panel border border-border p-4 text-sm text-muted-foreground", className)}>
        No graph nodes to draw.
      </div>
    );
  }

  function selectWithKeyboard(event: KeyboardEvent<SVGGElement>, nodeId: string) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(nodeId);
    }
  }

  return (
    <section className={cn("grid gap-3", className)} aria-labelledby="graph-visual-heading">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="graph-visual-heading" className="text-sm font-semibold">
          Node-link graph
        </h2>
        <p className="text-sm text-muted-foreground">
          {nodes.length} nodes, {visibleEdges.length} edges shown
        </p>
      </div>
      <div className="overflow-hidden rounded-panel border border-border bg-card shadow-elevation1">
        <svg
          role="img"
          aria-labelledby="graph-visual-heading"
          viewBox="0 0 720 360"
          className="h-[24rem] w-full"
          data-testid="graph-visualization"
        >
          <defs>
            <marker id="graph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--muted-foreground))" />
            </marker>
          </defs>
          {visibleEdges.map((edge) => {
            const from = nodeByID.get(edge.from)!;
            const to = nodeByID.get(edge.to)!;
            const midX = (from.x + to.x) / 2;
            const midY = (from.y + to.y) / 2;
            return (
              <g key={`${edge.from}-${edge.type}-${edge.to}`} data-testid="graph-edge" data-edge-type={edge.type}>
                <line
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke="hsl(var(--muted-foreground) / 0.55)"
                  strokeWidth={2}
                  markerEnd="url(#graph-arrow)"
                />
                <text x={midX} y={midY - 8} textAnchor="middle" className="fill-muted-foreground text-[10px]">
                  {graphEdgeTypeLabel(edge.type)}
                </text>
              </g>
            );
          })}
          {positioned.map((node) => {
            const style = graphNodeKindStyle(node.kind);
            const selected = node.id === selectedId;
            return (
              <g
                key={node.id}
                role="button"
                tabIndex={0}
                aria-label={`Graph node ${node.name || node.id}`}
                data-testid="graph-node"
                data-node-kind={node.kind}
                data-node-id={node.id}
                onClick={() => onSelect(node.id)}
                onKeyDown={(event) => selectWithKeyboard(event, node.id)}
                className="cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={selected ? 28 : 24}
                  fill={style.fill}
                  stroke={style.stroke}
                  strokeWidth={selected ? 4 : 2}
                />
                <text x={node.x} y={node.y + 4} textAnchor="middle" className="pointer-events-none fill-foreground text-[11px] font-semibold">
                  {nodeInitial(node)}
                </text>
                <text x={node.x} y={node.y + 42} textAnchor="middle" className="pointer-events-none fill-foreground text-[11px]">
                  {node.name || node.id}
                </text>
                <title>{`${node.name || node.id} (${graphNodeKindLabel(node.kind)})`}</title>
              </g>
            );
          })}
        </svg>
      </div>
      <div data-testid="graph-text-fallback" className="rounded-panel border border-border p-3 text-sm">
        <h3 className="font-semibold">Graph text fallback</h3>
        <ul className="mt-2 grid gap-1 md:grid-cols-2">
          {nodes.map((node) => (
            <li key={node.id}>
              <button type="button" className="text-left text-primary underline" onClick={() => onSelect(node.id)}>
                {node.name || node.id} ({graphNodeKindLabel(node.kind)})
              </button>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function layoutNodes(nodes: GraphNode[]): PositionedNode[] {
  if (nodes.length === 1) return [{ ...nodes[0], x: 360, y: 180 }];
  const centerX = 360;
  const centerY = 180;
  const radius = nodes.length <= 4 ? 110 : 135;
  return nodes.map((node, index) => {
    const angle = (2 * Math.PI * index) / nodes.length - Math.PI / 2;
    return {
      ...node,
      x: Math.round(centerX + radius * Math.cos(angle)),
      y: Math.round(centerY + radius * Math.sin(angle)),
    };
  });
}

function nodeInitial(node: GraphNode): string {
  const source = node.name || graphNodeKindLabel(node.kind) || node.id;
  return source.slice(0, 2).toUpperCase();
}

function humanize(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}
