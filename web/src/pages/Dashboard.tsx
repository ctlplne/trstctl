import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/EmptyState";

export function Dashboard() {
  const certs = useResource(api.certificates);
  const risk = useResource(api.risk);

  const topRisk = (risk.data ?? []).slice(0, 5);
  const fresh =
    !certs.loading && !risk.loading && (certs.data?.length ?? 0) === 0 && (risk.data?.length ?? 0) === 0;

  return (
    <section aria-labelledby="dashboard-heading">
      <h1 id="dashboard-heading" className="mb-4 text-2xl font-semibold">
        Overview
      </h1>

      {fresh && (
        <div className="mb-6">
          <EmptyState
            title="Welcome to trstctl"
            ctaTo="/wizard"
            ctaLabel="Get started"
          >
            Connect a CA, install an agent, and issue your first certificate — in under 15 minutes.
          </EmptyState>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Certificates</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold" data-testid="cert-count">
              {certs.loading ? "…" : (certs.data?.length ?? 0)}
            </p>
            <p className="text-sm text-muted-foreground">in the inventory</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Scored credentials</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{risk.loading ? "…" : (risk.data?.length ?? 0)}</p>
            <p className="text-sm text-muted-foreground">risk-ranked</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Highest risk</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-3xl font-semibold">{topRisk[0] ? Math.round(topRisk[0].score) : "—"}</p>
            <p className="text-sm text-muted-foreground">top score</p>
          </CardContent>
        </Card>
      </div>

      {topRisk.length > 0 && (
        <div className="mt-6">
          <h2 className="mb-2 text-lg font-semibold">Rotate first</h2>
          <ul className="space-y-1 text-sm">
            {topRisk.map((c) => (
              <li key={c.credential_id} className="flex justify-between border-b border-border py-1">
                <span>{c.subject}</span>
                <span className="font-medium">{Math.round(c.score)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
