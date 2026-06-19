import { Fragment, useMemo, useState } from "react";
import { api, type CredentialRisk } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { Button } from "@/components/ui/button";
import { UnavailableState } from "@/components/StatePrimitives";

const privilegeLabel = ["Low", "Standard", "High", "Critical"];
const factorKeys = ["age", "rotation", "privilege", "exposure", "owner", "sensitivity"] as const;

type RiskFactor = (typeof factorKeys)[number];
type SortKey = "score" | RiskFactor;
type FilterKey = "all" | RiskFactor;

const factorLabels: Record<RiskFactor, string> = {
  age: "Age",
  rotation: "Rotation",
  privilege: "Privilege",
  exposure: "Exposure",
  owner: "Owner",
  sensitivity: "Sensitivity",
};

export function Risk() {
  const { data, loading, error } = useResource(api.risk);
  const [sortBy, setSortBy] = useState<SortKey>("score");
  const [filterBy, setFilterBy] = useState<FilterKey>("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const certRows = useMemo(() => (data ?? []).filter(isCertificateRisk), [data]);
  const ignoredCount = (data?.length ?? 0) - certRows.length;
  const rows = useMemo(
    () =>
      certRows
        .filter((row) => filterBy === "all" || factorPercent(row.components[filterBy]) > 0)
        .sort((a, b) => sortValue(b, sortBy) - sortValue(a, sortBy)),
    [certRows, filterBy, sortBy],
  );

  return (
    <section aria-labelledby="risk-heading">
      <h1 id="risk-heading" className="mb-4 text-2xl font-semibold">
        Credential risk
      </h1>
      <p className="mb-4 text-sm text-muted-foreground">Ranked by composite score — what to rotate first.</p>
      <div className="mb-4">
        <UnavailableState title="Certificates only today">
          The served risk endpoint currently scores certificate inventory records only.
          BACKEND-RISK-ALLKINDS tracks risk scoring for SSH certificates, SSH keys,
          secrets, API keys, tokens, and workload identities.
        </UnavailableState>
      </div>
      {loading && <p role="status">Loading risk scores…</p>}
      {error && <p role="alert">Could not load risk scores: {error}</p>}
      {data && (
        <>
          {ignoredCount > 0 && (
            <p className="mb-3 text-sm text-amber-700 dark:text-amber-300">
              {ignoredCount} non-certificate risk record{ignoredCount === 1 ? " is" : "s are"} waiting on BACKEND-RISK-ALLKINDS before this page displays them.
            </p>
          )}

          <div className="mb-4 flex flex-wrap gap-3 text-sm">
            <label className="grid gap-1 font-medium" htmlFor="risk-sort">
              Sort by
              <select
                id="risk-sort"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as SortKey)}
                className="rounded-md border border-border bg-background px-3 py-2"
              >
                <option value="score">Composite score</option>
                {factorKeys.map((factor) => (
                  <option key={factor} value={factor}>
                    {factorLabels[factor]}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 font-medium" htmlFor="risk-filter">
              Focus factor
              <select
                id="risk-filter"
                value={filterBy}
                onChange={(e) => setFilterBy(e.target.value as FilterKey)}
                className="rounded-md border border-border bg-background px-3 py-2"
              >
                <option value="all">All factors</option>
                {factorKeys.map((factor) => (
                  <option key={factor} value={factor}>
                    {factorLabels[factor]}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <table className="w-full text-left text-sm">
            <caption className="sr-only">Credentials ranked by risk score</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pr-4 font-medium">Credential</th>
                <th scope="col" className="py-2 pr-4 font-medium">Score</th>
                <th scope="col" className="py-2 pr-4 font-medium">Top factor</th>
                <th scope="col" className="py-2 pr-4 font-medium">Exposure</th>
                <th scope="col" className="py-2 pr-4 font-medium">Owner</th>
                <th scope="col" className="py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-4 text-muted-foreground">
                    No certificate risk scores match the current filter.
                  </td>
                </tr>
              )}
              {rows.map((c) => {
                const top = topFactor(c);
                const isExpanded = expanded === c.credential_id;
                return (
                  <Fragment key={c.credential_id}>
                    <tr key={c.credential_id} className="border-b border-border">
                      <td className="py-2 pr-4" data-testid="risk-subject">{c.subject}</td>
                      <td className="py-2 pr-4 font-medium">{Math.round(c.score)}</td>
                      <td className="py-2 pr-4">{factorLabels[top]} {factorPercent(c.components[top])}</td>
                      <td className="py-2 pr-4">{c.exposure}</td>
                      <td className="py-2 pr-4">{c.owner_active ? "active" : "orphaned"}</td>
                      <td className="py-2">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => setExpanded(isExpanded ? null : c.credential_id)}
                        >
                          {isExpanded ? "Hide factors" : "Show factors"}
                        </Button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${c.credential_id}-detail`} className="border-b border-border bg-muted/30">
                        <td colSpan={6} className="py-4">
                          <RiskDetail risk={c} activeFactor={filterBy === "all" ? top : filterBy} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}

function RiskDetail({ risk, activeFactor }: { risk: CredentialRisk; activeFactor: RiskFactor }) {
  const encodedCredential = encodeURIComponent(risk.credential_id);
  const graphNode = encodeURIComponent(`cert:${risk.credential_id}`);
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_16rem]">
      <div>
        <h2 className="mb-2 text-sm font-semibold">Six-factor breakdown</h2>
        <div className="grid gap-2 md:grid-cols-2">
          {factorKeys.map((factor) => (
            <FactorBar
              key={factor}
              factor={factor}
              value={risk.components[factor]}
              active={factor === activeFactor}
            />
          ))}
        </div>
      </div>
      <div>
        <h2 className="mb-2 text-sm font-semibold">Drilldown links</h2>
        <ul className="space-y-1">
          <li>
            <a className="text-primary underline" href={`/certificates?credential=${encodedCredential}`}>
              Credential detail
            </a>
          </li>
          <li>
            <a className="text-primary underline" href={`/owners?status=${risk.owner_active ? "active" : "orphaned"}`}>
              Owner status {risk.owner_active ? "active" : "orphaned"}
            </a>
          </li>
          <li>
            <a className="text-primary underline" href={`/graph?node=${graphNode}`}>
              Graph blast radius
            </a>
          </li>
          <li>
            <a className="text-primary underline" href={`/audit?credential=${encodedCredential}`}>
              Audit evidence
            </a>
          </li>
        </ul>
      </div>
    </div>
  );
}

function FactorBar({ factor, value, active }: { factor: RiskFactor; value: number; active: boolean }) {
  const pct = factorPercent(value);
  return (
    <div
      data-testid={`risk-factor-${factor}`}
      className={active ? "rounded-md border border-primary p-2" : "rounded-md border border-border p-2"}
    >
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="font-medium">{factorLabels[factor]}</span>
        <span>{pct}</span>
      </div>
      <div className="h-2 rounded-full bg-background" aria-label={`${factorLabels[factor]} risk ${pct}`}>
        <div className="h-2 rounded-full bg-primary" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function isCertificateRisk(risk: CredentialRisk): boolean {
  return risk.kind === "certificate" || risk.kind === "x509_certificate";
}

function factorPercent(value: number): number {
  const normalized = value <= 1 ? value * 100 : value;
  return Math.max(0, Math.min(100, Math.round(normalized)));
}

function sortValue(risk: CredentialRisk, sortBy: SortKey): number {
  return sortBy === "score" ? risk.score : factorPercent(risk.components[sortBy]);
}

function topFactor(risk: CredentialRisk): RiskFactor {
  return factorKeys.reduce((best, next) =>
    factorPercent(risk.components[next]) > factorPercent(risk.components[best]) ? next : best,
  );
}

export { privilegeLabel };
