import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent as ReactPointerEvent } from "react";
import { RotateCcw, ZoomIn, ZoomOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
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
  /** Node ids affected by the last blast-radius/reachability analysis; when
   * present the map paints them and dims everything else. */
  impactIds?: Set<string>;
  /** The analyzed node (blast-radius origin) — gets the strongest emphasis. */
  focusId?: string;
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
  return (
    nodeKindTokens[kind] ?? {
      label: humanize(kind),
      fill: "hsl(var(--muted))",
      stroke: "hsl(var(--muted-foreground))",
    }
  );
}

export function graphEdgeTypeLabel(type: string): string {
  return edgeLabels[type] ?? humanize(type);
}

const MIN_SCALE = 0.35;
const MAX_SCALE = 3;

export function GraphView({ nodes, edges, selectedId, onSelect, impactIds, focusId, className }: GraphViewProps) {
  const { t } = useTranslation();
  const svgRef = useRef<SVGSVGElement>(null);
  const dragRef = useRef<{ pointerId: number; startX: number; startY: number; tx: number; ty: number } | null>(null);
  const [view, setView] = useState({ scale: 1, tx: 0, ty: 0 });

  const { positioned, width, height } = useMemo(() => layoutNodes(nodes, edges), [nodes, edges]);
  const nodeByID = useMemo(() => new Map(positioned.map((node) => [node.id, node])), [positioned]);
  const visibleEdges = useMemo(() => edges.filter((edge) => nodeByID.has(edge.from) && nodeByID.has(edge.to)), [edges, nodeByID]);

  // Wheel zoom needs a non-passive listener (React's synthetic wheel handler
  // is passive, so preventDefault would be ignored and the page would scroll).
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    function onWheel(event: WheelEvent) {
      event.preventDefault();
      const factor = event.deltaY < 0 ? 1.12 : 1 / 1.12;
      setView((current) => ({ ...current, scale: clamp(current.scale * factor, MIN_SCALE, MAX_SCALE) }));
    }
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  if (nodes.length === 0) {
    return <div className={cn("rounded-panel border border-border p-4 text-sm text-muted-foreground", className)}>No graph nodes to draw.</div>;
  }

  const impactActive = Boolean(impactIds && impactIds.size > 0);

  function selectWithKeyboard(event: KeyboardEvent<SVGGElement>, nodeId: string) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(nodeId);
    }
  }

  function zoomBy(factor: number) {
    setView((current) => ({ ...current, scale: clamp(current.scale * factor, MIN_SCALE, MAX_SCALE) }));
  }

  function resetView() {
    setView({ scale: 1, tx: 0, ty: 0 });
  }

  function onPointerDown(event: ReactPointerEvent<SVGSVGElement>) {
    // Nodes handle their own clicks; drags anywhere else pan the map.
    if ((event.target as Element).closest("[data-testid='graph-node']")) return;
    const svg = svgRef.current;
    if (!svg) return;
    dragRef.current = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, tx: view.tx, ty: view.ty };
    svg.setPointerCapture(event.pointerId);
  }

  function onPointerMove(event: ReactPointerEvent<SVGSVGElement>) {
    const drag = dragRef.current;
    const svg = svgRef.current;
    if (!drag || !svg || drag.pointerId !== event.pointerId) return;
    const rect = svg.getBoundingClientRect();
    const unit = rect.width > 0 ? width / rect.width : 1;
    setView((current) => ({
      ...current,
      tx: drag.tx + (event.clientX - drag.startX) * unit,
      ty: drag.ty + (event.clientY - drag.startY) * unit,
    }));
  }

  function onPointerUp(event: ReactPointerEvent<SVGSVGElement>) {
    if (dragRef.current?.pointerId === event.pointerId) {
      dragRef.current = null;
      svgRef.current?.releasePointerCapture(event.pointerId);
    }
  }

  function edgeAppearance(edge: GraphEdge): { stroke: string; strokeWidth: number; opacity: number } {
    const inImpact = impactActive && (impactIds!.has(edge.from) || edge.from === focusId) && (impactIds!.has(edge.to) || edge.to === focusId);
    if (impactActive) {
      if (inImpact) return { stroke: "hsl(var(--risk-critical) / 0.8)", strokeWidth: 2.4, opacity: 1 };
      return { stroke: "hsl(var(--muted-foreground) / 0.55)", strokeWidth: 1.5, opacity: 0.15 };
    }
    if (selectedId && (edge.from === selectedId || edge.to === selectedId)) {
      return { stroke: "hsl(var(--brand-accent) / 0.9)", strokeWidth: 2.4, opacity: 1 };
    }
    return { stroke: "hsl(var(--muted-foreground) / 0.45)", strokeWidth: 1.5, opacity: 1 };
  }

  return (
    <section className={cn("grid gap-3", className)} aria-labelledby="graph-visual-heading">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="graph-visual-heading" className="text-sm font-semibold">
          Node-link graph
        </h2>
        <div className="flex items-center gap-2">
          <p className="text-sm text-muted-foreground">
            {nodes.length} nodes, {visibleEdges.length} edges shown
          </p>
          <span className="text-caption tabular-nums text-muted-foreground">{Math.round(view.scale * 100)}%</span>
          <Button type="button" size="icon" variant="outline" className="h-7 w-7" aria-label={t("graph.view.zoomIn")} onClick={() => zoomBy(1.25)}>
            <ZoomIn className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button type="button" size="icon" variant="outline" className="h-7 w-7" aria-label={t("graph.view.zoomOut")} onClick={() => zoomBy(1 / 1.25)}>
            <ZoomOut className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button type="button" size="icon" variant="outline" className="h-7 w-7" aria-label={t("graph.view.resetView")} onClick={resetView}>
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
        </div>
      </div>
      <div className="overflow-hidden rounded-panel border border-border bg-card shadow-elevation1">
        <svg
          ref={svgRef}
          role="img"
          aria-labelledby="graph-visual-heading"
          viewBox={`0 0 ${width} ${height}`}
          className="h-[28rem] w-full cursor-grab touch-none active:cursor-grabbing"
          data-testid="graph-visualization"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
        >
          <defs>
            <marker id="graph-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--muted-foreground))" />
            </marker>
          </defs>
          <g transform={`translate(${view.tx} ${view.ty}) scale(${view.scale})`}>
            {visibleEdges.map((edge) => {
              const from = nodeByID.get(edge.from)!;
              const to = nodeByID.get(edge.to)!;
              const appearance = edgeAppearance(edge);
              const labelled = selectedId != null && (edge.from === selectedId || edge.to === selectedId);
              const midX = (from.x + to.x) / 2;
              const midY = (from.y + to.y) / 2;
              return (
                <g key={`${edge.from}-${edge.type}-${edge.to}`} data-testid="graph-edge" data-edge-type={edge.type} opacity={appearance.opacity}>
                  <path d={edgePath(from, to)} fill="none" stroke={appearance.stroke} strokeWidth={appearance.strokeWidth} markerEnd="url(#graph-arrow)" />
                  {labelled && (
                    <text x={midX} y={midY - 6} textAnchor="middle" className="fill-muted-foreground text-[10px]">
                      {graphEdgeTypeLabel(edge.type)}
                    </text>
                  )}
                  <title>{`${from.name || from.id} ${graphEdgeTypeLabel(edge.type)} ${to.name || to.id}`}</title>
                </g>
              );
            })}
            {positioned.map((node) => {
              const style = graphNodeKindStyle(node.kind);
              const selected = node.id === selectedId;
              const affected = impactActive && impactIds!.has(node.id);
              const isFocus = node.id === focusId;
              const dimmed = impactActive && !affected && !isFocus;
              const stroke = isFocus ? "hsl(var(--brand-accent))" : affected ? "hsl(var(--risk-critical))" : style.stroke;
              return (
                <g
                  key={node.id}
                  role="button"
                  tabIndex={0}
                  aria-label={`Graph node ${node.name || node.id}`}
                  data-testid="graph-node"
                  data-node-kind={node.kind}
                  data-node-id={node.id}
                  opacity={dimmed ? 0.25 : 1}
                  onClick={() => onSelect(node.id)}
                  onKeyDown={(event) => selectWithKeyboard(event, node.id)}
                  className="cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-brand-accent"
                >
                  {isFocus && (
                    <circle cx={node.x} cy={node.y} r={24} fill="none" stroke="hsl(var(--risk-critical) / 0.6)" strokeWidth={1.5} strokeDasharray="4 3" />
                  )}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={selected ? 19 : 16}
                    fill={style.fill}
                    stroke={stroke}
                    strokeWidth={selected || affected || isFocus ? 3 : 2}
                  />
                  <text x={node.x} y={node.y + 3.5} textAnchor="middle" className="pointer-events-none fill-foreground text-[10px] font-semibold">
                    {nodeInitial(node)}
                  </text>
                  <text x={node.x} y={node.y + 32} textAnchor="middle" className="pointer-events-none fill-foreground text-[10px]">
                    {truncateLabel(node.name || node.id)}
                  </text>
                  <title>{`${node.name || node.id} (${graphNodeKindLabel(node.kind)})`}</title>
                </g>
              );
            })}
          </g>
        </svg>
      </div>
      <div data-testid="graph-text-fallback" className="rounded-panel border border-border p-3 text-sm">
        <h3 className="font-semibold">Graph text fallback</h3>
        <ul className="mt-2 grid gap-1 md:grid-cols-2">
          {nodes.map((node) => (
            <li key={node.id}>
              <button type="button" className="text-left text-brand-accent underline" onClick={() => onSelect(node.id)}>
                {node.name || node.id} ({graphNodeKindLabel(node.kind)})
              </button>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/** layoutNodes lays the graph out as a layered DAG (left → right): each node's
 * column is its longest path from a root, rows within a column are ordered by
 * the barycenter of their neighbors to reduce crossings, and columns are
 * vertically centered. Cycles are tolerated (layer relaxation is bounded), so
 * arbitrary served graphs render without a special case. */
function layoutNodes(nodes: GraphNode[], edges: GraphEdge[]): { positioned: PositionedNode[]; width: number; height: number } {
  const colWidth = 150;
  const rowHeight = 62;
  const padX = 80;
  const padY = 48;

  if (nodes.length === 0) return { positioned: [], width: 720, height: 360 };
  if (nodes.length === 1) return { positioned: [{ ...nodes[0], x: 360, y: 180 }], width: 720, height: 360 };

  const ids = new Set(nodes.map((node) => node.id));
  const usable = edges.filter((edge) => ids.has(edge.from) && ids.has(edge.to) && edge.from !== edge.to);

  // Longest-path layering with bounded relaxation (tolerates cycles).
  const layer = new Map<string, number>(nodes.map((node) => [node.id, 0]));
  for (let pass = 0; pass < nodes.length; pass++) {
    let changed = false;
    for (const edge of usable) {
      const want = (layer.get(edge.from) ?? 0) + 1;
      if (want > (layer.get(edge.to) ?? 0) && want < nodes.length) {
        layer.set(edge.to, want);
        changed = true;
      }
    }
    if (!changed) break;
  }

  // Column buckets in stable input order.
  const columns = new Map<number, string[]>();
  for (const node of nodes) {
    const l = layer.get(node.id) ?? 0;
    if (!columns.has(l)) columns.set(l, []);
    columns.get(l)!.push(node.id);
  }

  // Barycenter ordering: two sweeps over neighbor average positions.
  const neighbors = new Map<string, string[]>();
  for (const edge of usable) {
    if (!neighbors.has(edge.from)) neighbors.set(edge.from, []);
    if (!neighbors.has(edge.to)) neighbors.set(edge.to, []);
    neighbors.get(edge.from)!.push(edge.to);
    neighbors.get(edge.to)!.push(edge.from);
  }
  const rowIndex = new Map<string, number>();
  const layerKeys = Array.from(columns.keys()).sort((a, b) => a - b);
  for (const key of layerKeys) columns.get(key)!.forEach((id, index) => rowIndex.set(id, index));
  for (let sweep = 0; sweep < 2; sweep++) {
    for (const key of sweep % 2 === 0 ? layerKeys : [...layerKeys].reverse()) {
      const column = columns.get(key)!;
      const scored = column.map((id) => {
        const near = neighbors.get(id) ?? [];
        const score = near.length > 0 ? near.reduce((sum, other) => sum + (rowIndex.get(other) ?? 0), 0) / near.length : (rowIndex.get(id) ?? 0);
        return { id, score };
      });
      scored.sort((a, b) => a.score - b.score || a.id.localeCompare(b.id));
      scored.forEach(({ id }, index) => rowIndex.set(id, index));
      columns.set(
        key,
        scored.map(({ id }) => id),
      );
    }
  }

  const maxLayer = layerKeys[layerKeys.length - 1] ?? 0;
  const maxRows = Math.max(...layerKeys.map((key) => columns.get(key)!.length));
  const width = Math.max(720, padX * 2 + maxLayer * colWidth);
  const height = Math.max(360, padY * 2 + (maxRows - 1) * rowHeight);

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const positioned: PositionedNode[] = [];
  for (const key of layerKeys) {
    const column = columns.get(key)!;
    const yStart = (height - (column.length - 1) * rowHeight) / 2;
    column.forEach((id, index) => {
      const node = nodeById.get(id)!;
      positioned.push({ ...node, x: padX + key * colWidth, y: Math.round(yStart + index * rowHeight) });
    });
  }
  return { positioned, width, height };
}

function edgePath(from: PositionedNode, to: PositionedNode): string {
  if (Math.abs(from.x - to.x) < 1) {
    // Same column: bow the edge out so it does not overlap the node stack.
    const bow = 46 * Math.sign(from.y <= to.y ? 1 : -1);
    return `M ${from.x} ${from.y} C ${from.x + bow} ${from.y}, ${to.x + bow} ${to.y}, ${to.x} ${to.y}`;
  }
  const midX = (from.x + to.x) / 2;
  return `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function truncateLabel(value: string, max = 18): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function nodeInitial(node: GraphNode): string {
  const source = node.name || graphNodeKindLabel(node.kind) || node.id;
  return source.slice(0, 2).toUpperCase();
}

function humanize(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}
