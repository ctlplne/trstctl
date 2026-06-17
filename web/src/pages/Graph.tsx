import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useResource } from "@/lib/useResource";

export function Graph() {
  const { data, loading, error } = useResource(api.graph);
  const [selected, setSelected] = useState("");
  const [affected, setAffected] = useState<number | null>(null);
  const [blastError, setBlastError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!selected && data?.nodes?.[0]) setSelected(data.nodes[0].id);
  }, [data, selected]);

  async function runBlastRadius() {
    if (!selected) return;
    setBusy(true);
    setBlastError(null);
    try {
      const result = await api.graphBlastRadius(selected);
      setAffected(result.affected.length);
    } catch (err) {
      setBlastError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="graph-heading">
      <h1 id="graph-heading" className="mb-4 text-2xl font-semibold">
        Graph
      </h1>

      {loading && <p role="status">Loading graph...</p>}
      {error && <p role="alert">Could not load graph: {error}</p>}

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
                  {affected ?? "-"}
                </p>
              </CardContent>
            </Card>
          </div>

          <form
            className="mb-5 flex flex-wrap items-end gap-3 rounded-md border border-border p-4"
            onSubmit={(e) => {
              e.preventDefault();
              void runBlastRadius();
            }}
          >
            <label className="flex-1 space-y-1 text-sm font-medium">
              Node
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="block w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              >
                {data.nodes.map((node) => (
                  <option key={node.id} value={node.id}>
                    {node.name || node.id}
                  </option>
                ))}
              </select>
            </label>
            <Button type="submit" disabled={busy || !selected}>
              Analyze
            </Button>
          </form>

          {blastError && <p role="alert">Could not compute blast radius: {blastError}</p>}

          <table className="w-full text-left text-sm">
            <caption className="sr-only">Credential graph nodes</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pr-4 font-medium">Name</th>
                <th scope="col" className="py-2 pr-4 font-medium">Kind</th>
                <th scope="col" className="py-2 font-medium">ID</th>
              </tr>
            </thead>
            <tbody>
              {data.nodes.length === 0 && (
                <tr>
                  <td colSpan={3} className="py-4 text-muted-foreground">No graph nodes returned.</td>
                </tr>
              )}
              {data.nodes.map((node) => (
                <tr key={node.id} className="border-b border-border">
                  <td className="py-2 pr-4">{node.name || "-"}</td>
                  <td className="py-2 pr-4">{node.kind}</td>
                  <td className="py-2 font-mono text-xs">{node.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
