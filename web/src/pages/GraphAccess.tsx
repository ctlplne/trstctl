import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { graphEdgeTypeLabel, graphNodeKindLabel } from "@/components/GraphView";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type GraphAccessLink, type GraphNode, type GraphPath, type GraphReachers } from "@/lib/api";
import { apiProblemContext as apiProblemMessage } from "@/lib/apiProblem";

// G1: "who can reach this database?" and "how does this person reach it?",
// answered by the server from the same graph as blast radius. Every holder,
// credential and approver is shown with the record that links it and how
// strongly that record establishes the link; the coverage note says what the
// answer cannot see, so an empty answer is never read as "nobody".

// Resources first: the usual question is about a database, host or API.
function byKindThenName(a: GraphNode, b: GraphNode) {
  const rank = (node: GraphNode) => (node.kind === "resource" ? 0 : 1);
  return rank(a) - rank(b) || (a.name || a.id).localeCompare(b.name || b.id) || a.id.localeCompare(b.id);
}

function nodeLabel(node: GraphNode) {
  return `${node.name || node.id} · ${graphNodeKindLabel(node.kind)}`;
}

function Evidence({ link }: { link: GraphAccessLink }) {
  const { t } = useTranslation();
  return (
    <li className="grid gap-0.5">
      <span className="font-medium">{nodeLabel(link.node)}</span>
      <span className="text-caption text-muted-foreground">
        {t("graph.access.evidence", { relation: graphEdgeTypeLabel(link.edge.type), source: link.edge.source || "—", confidence: link.edge.confidence || "—" })}
      </span>
    </li>
  );
}

export function WhoCanReach({ nodes }: { nodes: GraphNode[] }) {
  const { t } = useTranslation();
  const choices = useMemo(() => [...nodes].sort(byKindThenName), [nodes]);
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<GraphReachers | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!target) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.graphReachers(target));
    } catch (reason) {
      setError(apiProblemMessage(reason, t("graph.access.failed")));
    } finally {
      setBusy(false);
    }
  }

  const targetName = result ? result.target.name || result.target.id : "";
  return (
    <section aria-labelledby="graph-who-can-reach" className="grid gap-3">
      <h2 id="graph-who-can-reach" className="text-title font-semibold">
        {t("graph.access.heading")}
      </h2>
      <p className="max-w-3xl text-sm text-muted-foreground">{t("graph.access.help")}</p>
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t("graph.access.target")} controlId="graph-access-target" className="min-w-0 max-w-full">
          {(control) => (
            <Select {...control} className="min-w-0 max-w-full" value={target} onChange={(event) => setTarget(event.target.value)}>
              <option value="">{t("graph.access.choose")}</option>
              {choices.map((node) => (
                <option key={node.id} value={node.id}>
                  {nodeLabel(node)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Button type="button" loading={busy} disabled={!target} onClick={() => void run()}>
          {t("graph.access.run")}
        </Button>
      </div>
      {error ? <p role="alert">{error}</p> : null}
      {result ? (
        <div className="grid gap-3" aria-live="polite">
          <h3 className="font-semibold">{t("graph.access.result", { name: targetName, count: result.access.length })}</h3>
          <ul className="grid gap-3">
            {result.access.map((grant) => (
              <li key={grant.credential.id} className="grid gap-2 rounded-panel border border-border p-3 text-sm">
                <div>
                  <p className="font-medium">{t("graph.access.credential", { name: nodeLabel(grant.credential) })}</p>
                  <p className="text-caption text-muted-foreground">
                    {t("graph.access.evidence", {
                      relation: graphEdgeTypeLabel(grant.grant.type),
                      source: grant.grant.source || "—",
                      confidence: grant.grant.confidence || "—",
                    })}
                  </p>
                </div>
                <div className="grid gap-1">
                  <p className="font-medium">{t("graph.access.holders")}</p>
                  {grant.holders.length ? (
                    <ul className="grid gap-1">
                      {grant.holders.map((link) => (
                        <Evidence key={`${link.node.id}-${link.edge.source}`} link={link} />
                      ))}
                    </ul>
                  ) : (
                    <p className="text-caption text-muted-foreground">{t("graph.access.noHolder")}</p>
                  )}
                </div>
                <div className="grid gap-1">
                  <p className="font-medium">{t("graph.access.approvers")}</p>
                  {grant.approvers.length ? (
                    <ul className="grid gap-1">
                      {grant.approvers.map((link) => (
                        <Evidence key={`${link.node.id}-${link.edge.source}`} link={link} />
                      ))}
                    </ul>
                  ) : (
                    <p className="text-caption text-muted-foreground">{t("graph.access.noApproval")}</p>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <div className="grid gap-1 text-caption text-muted-foreground">
            <p>{result.coverage.note}</p>
            <p>{t("graph.access.notCovered", { items: result.coverage.not_covered.join("; ") })}</p>
          </div>
        </div>
      ) : null}
    </section>
  );
}

export function PathFinder({ nodes }: { nodes: GraphNode[] }) {
  const { t } = useTranslation();
  const choices = useMemo(() => [...nodes].sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id) || a.id.localeCompare(b.id)), [nodes]);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [result, setResult] = useState<GraphPath | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!from || !to) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.graphPath(from, to));
    } catch (reason) {
      setError(apiProblemMessage(reason, t("graph.path.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="graph-path-finder" className="grid gap-3">
      <h2 id="graph-path-finder" className="text-title font-semibold">
        {t("graph.path.heading")}
      </h2>
      <div className="flex flex-wrap items-end gap-3">
        {(
          [
            ["graph-path-from", t("graph.path.from"), from, setFrom],
            ["graph-path-to", t("graph.path.to"), to, setTo],
          ] as const
        ).map(([id, label, value, set]) => (
          <Field key={id} label={label} controlId={id} className="min-w-0 max-w-full">
            {(control) => (
              <Select {...control} className="min-w-0 max-w-full" value={value} onChange={(event) => set(event.target.value)}>
                <option value="">{t("graph.access.choose")}</option>
                {choices.map((node) => (
                  <option key={node.id} value={node.id}>
                    {nodeLabel(node)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ))}
        <Button type="button" variant="outline" loading={busy} disabled={!from || !to} onClick={() => void run()}>
          {t("graph.path.run")}
        </Button>
      </div>
      {error ? <p role="alert">{error}</p> : null}
      {result ? (
        <ol className="grid gap-1 text-sm" aria-label={t("graph.path.heading")}>
          {result.path.nodes.map((node, index) => {
            const edge = index > 0 ? result.path.edges[index - 1] : undefined;
            return (
              <li key={`${node.id}-${index}`} className="grid gap-0.5">
                {edge ? (
                  <span className="text-caption text-muted-foreground">
                    {t("graph.access.evidence", { relation: graphEdgeTypeLabel(edge.type), source: edge.source || "—", confidence: edge.confidence || "—" })}
                  </span>
                ) : null}
                <span className="font-medium">{nodeLabel(node)}</span>
              </li>
            );
          })}
        </ol>
      ) : null}
    </section>
  );
}
