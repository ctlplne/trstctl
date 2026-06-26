import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Info } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { api, type CredentialRisk, type RiskQuery } from "@/lib/api";
import { DataGrid, type DataGridColumn, type DataGridSort } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";
import { UnavailableState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";
import { riskBand } from "@/lib/statusVocab";
import { formatDate as formatDatePolicy } from "@/i18n/format";

const privilegeLabel = ["Low", "Standard", "High", "Critical"];
const sensitivityLabel = ["Public", "Internal", "Confidential", "Restricted"];
const factorKeys = ["age", "rotation", "privilege", "exposure", "owner", "sensitivity"] as const;
const riskThresholds = [
  { value: "critical", label: "90-100" },
  { value: "high", label: "70-89" },
  { value: "medium", label: "40-69" },
  { value: "low", label: "1-39" },
  { value: "none", label: "0" },
] as const;

type RiskFactor = (typeof factorKeys)[number];
type RiskSortColumn = "score" | "expires_at";

const factorLabels: Record<RiskFactor, string> = {
  age: "Age",
  rotation: "Rotation",
  privilege: "Privilege",
  exposure: "Exposure",
  owner: "Owner",
  sensitivity: "Sensitivity",
};

export function Risk() {
  const [searchParams] = useSearchParams();
  const initialSort = searchParams.get("sort") === "expiry" ? "expiry" : "score";
  const [data, setData] = useState<CredentialRisk[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState<RiskQuery>({ sort: initialSort });
  const [sort, setSort] = useState<DataGridSort>({
    columnId: initialSort === "expiry" ? "expires_at" : "score",
    direction: "desc",
  });
  const [minScore, setMinScore] = useState("");
  const [privilege, setPrivilege] = useState("");
  const [owner, setOwner] = useState(searchParams.get("owner") ?? "");
  const [search, setSearch] = useState(searchParams.get("q") ?? "");
  const [expanded, setExpanded] = useState<string | null>(null);
  const certRows = useMemo(() => (data ?? []).filter(isCertificateRisk), [data]);
  const ignoredCount = (data?.length ?? 0) - certRows.length;
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return certRows;
    return certRows.filter((row) =>
      [row.subject, row.credential_id, row.kind, row.owner_active ? "active" : "orphaned"].join(" ").toLowerCase().includes(needle),
    );
  }, [certRows, search]);
  const expandedRisk = useMemo(() => certRows.find((row) => row.credential_id === expanded) ?? null, [certRows, expanded]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api
      .risk(query)
      .then((risk) => {
        if (!active) return;
        setData(risk);
      })
      .catch((err) => {
        if (!active) return;
        setData(null);
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query]);

  function applySort(next: DataGridSort) {
    const columnId = next.columnId as RiskSortColumn;
    const serverSort = columnId === "expires_at" ? "expiry" : "score";
    setSort(next);
    setQuery((current) => ({ ...current, sort: serverSort }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsedMinScore = Number(minScore);
    const parsedPrivilege = Number(privilege);
    setQuery((current) => ({
      ...current,
      minScore: minScore.trim() && Number.isFinite(parsedMinScore) ? parsedMinScore : undefined,
      privilege: privilege !== "" && Number.isFinite(parsedPrivilege) ? parsedPrivilege : undefined,
      owner: owner.trim() || undefined,
    }));
  }

  const columns = useMemo<Array<DataGridColumn<CredentialRisk>>>(
    () => [
      { id: "subject", header: "Credential", cell: (risk) => <span data-testid="risk-subject">{risk.subject}</span> },
      {
        id: "score",
        header: "Score",
        sortable: true,
        cell: (risk) => (
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{Math.round(risk.score)}</span>
            <StatusBadge vocabulary="risk" value={riskBand(risk.score)} />
          </div>
        ),
      },
      { id: "top_factor", header: "Top factor", cell: (risk) => formatTopFactor(risk) },
      { id: "expires_at", header: "Expires", sortable: true, cell: (risk) => formatDate(risk.expires_at) },
      {
        id: "privilege",
        header: "Privilege",
        cell: (risk) => <RiskScaleLabel label={scaleLabel(privilegeLabel, risk.privilege)} raw={risk.privilege} name="privilege" />,
      },
      {
        id: "sensitivity",
        header: "Sensitivity",
        cell: (risk) => <RiskScaleLabel label={scaleLabel(sensitivityLabel, risk.sensitivity)} raw={risk.sensitivity} name="sensitivity" />,
      },
      { id: "owner", header: "Owner", cell: (risk) => (risk.owner_active ? "active" : "orphaned") },
      {
        id: "actions",
        header: "Actions",
        cell: (risk) => {
          const isExpanded = expanded === risk.credential_id;
          return (
            <Button type="button" size="sm" variant="outline" onClick={() => setExpanded(isExpanded ? null : risk.credential_id)}>
              {isExpanded ? "Hide factors" : "Show factors"}
            </Button>
          );
        },
      },
    ],
    [expanded],
  );

  return (
    <section aria-labelledby="risk-heading">
      <PageHeader titleId="risk-heading" title="Credential risk" description="Ranked by composite score — what to rotate first." />
      <div className="mb-4">
        <UnavailableState title="Certificates only today">
          Risk scoring covers certificates today; scoring for SSH certificates, SSH keys, secrets, API keys, tokens, and workload identities is coming soon.
        </UnavailableState>
      </div>
      {data && ignoredCount > 0 && (
        <p className="mb-3 text-sm text-status-warning">
          {ignoredCount} non-certificate risk record{ignoredCount === 1 ? " is" : "s are"} waiting on console support for other credential kinds, which is
          coming soon.
        </p>
      )}

      <RiskLegend />

      <DataGrid
        ariaLabel="Certificate risk scores"
        rows={rows}
        columns={columns}
        getRowId={(risk) => risk.credential_id}
        state={loading ? "loading" : error ? "error" : rows.length === 0 ? "empty" : "ready"}
        stateTitle={error ? "Could not load risk scores" : "No matching certificate rows"}
        stateMessage={error ?? "No certificate risk scores match the current filter."}
        sort={sort}
        onSort={applySort}
        showColumnChooser
        toolbar={({ columnChooser }) => (
          <DataGridToolbar
            searchLabel="Search credential risk rows"
            searchPlaceholder="Search credential or owner state"
            searchValue={search}
            onSearchChange={setSearch}
            filters={
              <RiskFilterForm
                minScore={minScore}
                privilege={privilege}
                owner={owner}
                onMinScore={setMinScore}
                onPrivilege={setPrivilege}
                onOwner={setOwner}
                onSubmit={applyFilters}
              />
            }
            columnChooser={columnChooser}
          />
        )}
      />

      {expandedRisk && (
        <section aria-labelledby="risk-detail-heading" className="mt-4 rounded-panel border border-border bg-card p-4 shadow-elevation1">
          <h2 id="risk-detail-heading" className="mb-2 text-title font-semibold">
            Six-factor breakdown for {expandedRisk.subject}
          </h2>
          <RiskDetail risk={expandedRisk} activeFactor={topFactor(expandedRisk)} />
        </section>
      )}
    </section>
  );
}

function RiskFilterForm({
  minScore,
  privilege,
  owner,
  onMinScore,
  onPrivilege,
  onOwner,
  onSubmit,
}: {
  minScore: string;
  privilege: string;
  owner: string;
  onMinScore: (value: string) => void;
  onPrivilege: (value: string) => void;
  onOwner: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form className="flex flex-wrap items-end gap-2" onSubmit={onSubmit}>
      <label className="grid gap-1 text-sm font-medium">
        Minimum score
        <input
          className="min-h-9 w-28 rounded-control border border-input bg-background px-2 text-sm"
          type="number"
          min={0}
          max={100}
          value={minScore}
          onChange={(event) => onMinScore(event.target.value)}
        />
      </label>
      <label className="grid gap-1 text-sm font-medium">
        Privilege
        <select
          className="min-h-9 rounded-control border border-input bg-background px-2 text-sm"
          value={privilege}
          onChange={(event) => onPrivilege(event.target.value)}
        >
          <option value="">Any privilege</option>
          {privilegeLabel.map((label, index) => (
            <option key={label} value={index}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label className="grid gap-1 text-sm font-medium">
        Owner
        <input
          className="min-h-9 w-36 rounded-control border border-input bg-background px-2 text-sm"
          value={owner}
          onChange={(event) => onOwner(event.target.value)}
          placeholder="owner id"
        />
      </label>
      <Button type="submit" size="sm" variant="outline">
        Apply risk filters
      </Button>
    </form>
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
            <FactorBar key={factor} factor={factor} value={risk.components[factor]} active={factor === activeFactor} />
          ))}
        </div>
        <dl className="mt-4 grid gap-2 text-sm md:grid-cols-2">
          <div className="rounded-md border border-border p-2">
            <dt className="font-medium text-muted-foreground">Privilege label</dt>
            <dd>
              {scaleLabel(privilegeLabel, risk.privilege)} <span className="text-muted-foreground">(raw {risk.privilege})</span>
            </dd>
          </div>
          <div className="rounded-md border border-border p-2">
            <dt className="font-medium text-muted-foreground">Sensitivity label</dt>
            <dd>
              {scaleLabel(sensitivityLabel, risk.sensitivity)} <span className="text-muted-foreground">(raw {risk.sensitivity})</span>
            </dd>
          </div>
        </dl>
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

function RiskLegend() {
  const description = riskThresholds.map((band) => `${riskBandLabel(band.value)} ${band.label}`).join(", ");

  return (
    <div className="group relative mb-4 inline-flex">
      <Button type="button" size="sm" variant="outline" aria-describedby="risk-band-tooltip" title={description}>
        <Info className="h-4 w-4" aria-hidden="true" />
        Risk bands
      </Button>
      <div
        id="risk-band-tooltip"
        role="tooltip"
        className="pointer-events-none absolute start-0 top-full z-20 mt-2 w-72 rounded-panel border border-border bg-card p-3 text-sm opacity-0 shadow-elevation2 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100"
      >
        <p className="mb-2 font-medium">Risk band thresholds</p>
        <div className="flex flex-wrap gap-2">
          {riskThresholds.map((band) => (
            <span key={band.value} className="inline-flex items-center gap-2 rounded-control border border-border px-2 py-1">
              <StatusBadge vocabulary="risk" value={band.value} />
              <span className="text-muted-foreground">{band.label}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function riskBandLabel(value: (typeof riskThresholds)[number]["value"]): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function RiskScaleLabel({ label, raw, name }: { label: string; raw: number; name: string }) {
  return (
    <span title={`Raw ${name} value ${raw}`}>
      {label}
      <span className="sr-only">, raw {raw}</span>
    </span>
  );
}

function FactorBar({ factor, value, active }: { factor: RiskFactor; value: number; active: boolean }) {
  const pct = factorPercent(value);
  return (
    <div data-testid={`risk-factor-${factor}`} className={active ? "rounded-md border border-primary p-2" : "rounded-md border border-border p-2"}>
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

function formatTopFactor(risk: CredentialRisk): string {
  const factor = topFactor(risk);
  return `${factorLabels[factor]} ${factorPercent(risk.components[factor])}`;
}

function scaleLabel(labels: string[], value: number): string {
  return labels[value] ?? `Unknown ${value}`;
}

function formatDate(value?: string): string {
  return formatDatePolicy(value);
}

function topFactor(risk: CredentialRisk): RiskFactor {
  return factorKeys.reduce((best, next) => (factorPercent(risk.components[next]) > factorPercent(risk.components[best]) ? next : best));
}

export { privilegeLabel, sensitivityLabel };
