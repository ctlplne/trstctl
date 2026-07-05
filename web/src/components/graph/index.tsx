import { useState } from "react";
import { SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type GraphNode, type GraphImpact } from "@/lib/api";

/** BlastRadiusExplorer is the quick "what breaks if this is compromised?"
 * entry point. Standalone it fetches and lists the blast radius itself; when
 * the parent passes `onAnalyze` (the Graph page), it delegates instead so the
 * whole page shares one selection and one analysis — picked credentials get
 * painted on the map and detailed in the analysis rail, not in a second,
 * disconnected result list. */
export function BlastRadiusExplorer({
  nodes,
  selectedId,
  onAnalyze,
}: {
  nodes: GraphNode[];
  selectedId?: string;
  onAnalyze?: (id: string) => void;
}) {
  const { t } = useTranslation();
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [localSelected, setLocalSelected] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const delegated = Boolean(onAnalyze);
  const selected = delegated ? (selectedId ?? "") : localSelected;

  async function explore(id: string) {
    setLocalSelected(id);
    setError(null);
    setImpact(null);
    if (!id) return;
    if (onAnalyze) {
      onAnalyze(id);
      return;
    }
    try {
      setImpact(await api.graphBlastRadius(id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <SectionCard title="Blast radius explorer" description="pick a credential and see everything that breaks if it is compromised">
      <label className="grid gap-1 text-body">
        <span className="font-medium">Credential</span>
        <select value={selected} onChange={(event) => void explore(event.target.value)} className="min-h-9 rounded-control border border-border bg-background px-2 text-body">
          <option value="">Select a node…</option>
          {nodes.map((node) => (
            <option key={node.id} value={node.id}>
              {node.name} ({node.kind})
            </option>
          ))}
        </select>
      </label>
      {delegated && <p className="mt-2 text-caption text-muted-foreground">{t("graph.explorer.delegatedHint")}</p>}
      {impact ? (
        <div className="mt-3">
          <p className="text-caption text-muted-foreground">{impact.affected.length} affected credentials</p>
          <AttentionList ariaLabel="Affected credentials">
            {impact.affected.map((node) => (
              <AttentionRow key={node.id}>
                <span className="flex-1 truncate">{node.name}</span>
                <span className="w-28 truncate text-caption text-muted-foreground">{node.kind}</span>
              </AttentionRow>
            ))}
          </AttentionList>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="mt-2 text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </SectionCard>
  );
}
