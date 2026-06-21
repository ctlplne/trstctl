import { useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  Info,
  ListFilter,
  Map,
  Search,
  ShieldCheck,
} from "lucide-react";
import {
  featureCoverageDomains,
  featureCoverageItems,
  featureCoverageTotals,
  featureMaturityLabels,
  type FeatureCoverageItem,
  type FeatureCoveragePhase,
  type FeatureCoverageState,
} from "@/lib/featureCoverage";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type StateFilter = "all" | FeatureCoverageState;
type PhaseFilter = "all" | FeatureCoveragePhase;

const stateCopy: Record<FeatureCoverageState, { label: string; tone: string; icon: typeof CheckCircle2 }> = {
  operate: {
    label: "Operate",
    tone: "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-200",
    icon: CheckCircle2,
  },
  observe: {
    label: "Observe",
    tone: "border-blue-300 bg-blue-50 text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-200",
    icon: Eye,
  },
  disclose: {
    label: "Disclose",
    tone: "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200",
    icon: Info,
  },
};

function StateBadge({ state }: { state: FeatureCoverageState }) {
  const { icon: Icon, label, tone } = stateCopy[state];
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium", tone)}>
      <Icon aria-hidden="true" className="h-3.5 w-3.5" />
      {label}
    </span>
  );
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  helper,
}: {
  icon: typeof Map;
  label: string;
  value: string | number;
  helper: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icon aria-hidden="true" className="h-4 w-4 text-primary" />
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-semibold">{value}</p>
        <p className="mt-1 text-sm text-muted-foreground">{helper}</p>
      </CardContent>
    </Card>
  );
}

function PhasePill({ phase }: { phase: FeatureCoveragePhase }) {
  return (
    <span className="rounded-md border border-border bg-muted px-2 py-1 font-mono text-xs font-medium">
      {phase}
    </span>
  );
}

function surfaceText(label: "API" | "CLI", values: string[], na: string) {
  if (values.length === 0) return `N/A: ${na.replace(/^N\/A:\s*/i, "")}`;
  const noun = label === "API" ? "operation" : "command";
  const preview = values.slice(0, 4).join(", ");
  const suffix = values.length > 4 ? `, +${values.length - 4} more` : "";
  return `${values.length} ${noun}${values.length === 1 ? "" : "s"}: ${preview}${suffix}`;
}

function SurfaceLine({
  label,
  values,
  na,
}: {
  label: "API" | "CLI";
  values: string[];
  na: string;
}) {
  return (
    <p className="mt-2">
      <span className="font-medium text-foreground">{label}:</span> {surfaceText(label, values, na)}
    </p>
  );
}

function FeatureRow({ item }: { item: FeatureCoverageItem }) {
  return (
    <tr data-testid="feature-row">
      <td className="align-top">
        <div className="flex flex-col gap-1">
          <span className="font-mono text-xs font-semibold">{item.id}</span>
          <PhasePill phase={item.phase} />
        </div>
      </td>
      <td className="min-w-64 align-top">
        <p className="font-medium">{item.name}</p>
        <p className="mt-1 text-xs text-muted-foreground">{item.domain}</p>
      </td>
      <td className="align-top">
        <StateBadge state={item.state} />
      </td>
      <td className="min-w-72 align-top text-sm text-muted-foreground">
        <p>
          <span className="font-medium text-foreground">Backend:</span> {item.backendStatus}
        </p>
        <p className="mt-2">
          <span className="font-medium text-foreground">Served state:</span> {featureMaturityLabels[item.servedState]}
        </p>
        <SurfaceLine label="API" values={item.apiSurface} na={item.apiNA} />
        <SurfaceLine label="CLI" values={item.cliSurface} na={item.cliNA} />
        <p className="mt-2">
          <span className="font-medium text-foreground">Current GUI:</span> {item.currentMapping}
        </p>
      </td>
      <td className="min-w-96 align-top text-sm">
        <p>{item.targetMapping}</p>
        <p className="mt-2 text-xs text-muted-foreground">{item.acceptanceTest}</p>
      </td>
    </tr>
  );
}

export function FeatureCoverage() {
  const [stateFilter, setStateFilter] = useState<StateFilter>("all");
  const [phaseFilter, setPhaseFilter] = useState<PhaseFilter>("all");
  const [domainFilter, setDomainFilter] = useState("all");
  const [query, setQuery] = useState("");

  const filteredItems = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return featureCoverageItems.filter((item) => {
      if (stateFilter !== "all" && item.state !== stateFilter) return false;
      if (phaseFilter !== "all" && item.phase !== phaseFilter) return false;
      if (domainFilter !== "all" && item.domain !== domainFilter) return false;
      if (!needle) return true;
      return [
        item.id,
        item.name,
        item.domain,
        item.backendStatus,
        item.currentMapping,
        item.targetMapping,
        item.apiSurface.join(" "),
        item.apiNA,
        item.cliSurface.join(" "),
        item.cliNA,
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [domainFilter, phaseFilter, query, stateFilter]);

  return (
    <section aria-labelledby="coverage-heading" className="space-y-6">
      <PageHeader
        titleId="coverage-heading"
        eyebrow={
          <span className="inline-flex items-center gap-2">
            <Map aria-hidden="true" className="h-3.5 w-3.5" />
            GUI feature-map harness
          </span>
        }
        title="Backend-to-GUI coverage"
        description="This page maps every documented trstctl backend capability to a GUI outcome. It does not pretend unfinished systems are live. Each item is marked as operable, observable, or explicitly disclosed so there are no silent product gaps."
        actions={
          <div className="rounded-control border border-border px-3 py-2 text-caption text-muted-foreground">
            Source: <span className="font-mono">feature-map-backlog.json</span>
          </div>
        }
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard icon={ListFilter} label="Feature backlog" value={featureCoverageTotals.features} helper="documented features represented here" />
        <SummaryCard icon={Map} label="Capability domains" value={featureCoverageTotals.domains} helper="from certs to secrets, SSH, SPIFFE, AI, and policy" />
        <SummaryCard icon={ShieldCheck} label="Mapped outcomes" value={featureCoverageTotals.features} helper="each item has operate, observe, or disclose posture" />
        <SummaryCard icon={AlertTriangle} label="Silent gaps" value={0} helper="nothing is allowed to be invisible in the GUI map" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_20rem]">
        <Card>
          <CardHeader>
            <CardTitle>Roadmap phases</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {(["P0", "P1", "P2", "P3"] as const).map((phase) => (
                <button
                  key={phase}
                  type="button"
                  onClick={() => setPhaseFilter(phaseFilter === phase ? "all" : phase)}
                  className={cn(
                    "rounded-md border border-border p-4 text-left hover:bg-muted",
                    phaseFilter === phase && "border-primary bg-muted",
                  )}
                  aria-pressed={phaseFilter === phase}
                >
                  <span className="font-mono text-sm font-semibold">{phase}</span>
                  <span className="mt-2 block text-2xl font-semibold">{featureCoverageTotals.phases[phase]}</span>
                  <span className="block text-xs text-muted-foreground">
                    {phase === "P0" && "foundation and core served workflows"}
                    {phase === "P1" && "non-certificate operator workflows"}
                    {phase === "P2" && "advanced evidence and worker surfaces"}
                    {phase === "P3" && "strategic roadmap disclosures"}
                  </span>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Outcome legend</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p><StateBadge state="operate" /> means a real UI action or workflow already exists.</p>
            <p><StateBadge state="observe" /> means the GUI can show status, evidence, audit, or partial parity.</p>
            <p><StateBadge state="disclose" /> means the GUI now names the gap and explains the required target mapping.</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Domains</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="coverage-domains">
            {featureCoverageDomains.map((domain) => (
              <button
                key={domain.name}
                type="button"
                onClick={() => setDomainFilter(domainFilter === domain.name ? "all" : domain.name)}
                className={cn(
                  "rounded-md border border-border p-4 text-left hover:bg-muted",
                  domainFilter === domain.name && "border-primary bg-muted",
                )}
                aria-pressed={domainFilter === domain.name}
              >
                <span className="block font-medium">{domain.name}</span>
                <span className="mt-2 block text-sm text-muted-foreground">
                  {domain.count} features, {domain.disclose} disclosures
                </span>
                <span className="mt-3 flex flex-wrap gap-1">
                  {domain.phases.map((phase) => (
                    <PhasePill key={phase} phase={phase} />
                  ))}
                </span>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <CardTitle>Feature map</CardTitle>
              <p className="mt-1 text-sm text-muted-foreground">
                Showing {filteredItems.length} of {featureCoverageItems.length} backend features.
              </p>
            </div>
            <div className="flex flex-wrap gap-2" role="group" aria-label="Coverage outcome filter">
              {(["all", "operate", "observe", "disclose"] as const).map((state) => (
                <Button
                  key={state}
                  type="button"
                  variant={stateFilter === state ? "default" : "outline"}
                  size="sm"
                  onClick={() => setStateFilter(state)}
                  aria-pressed={stateFilter === state}
                >
                  {state === "all" ? "All" : stateCopy[state].label}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4 grid gap-3 lg:grid-cols-[1fr_18rem]">
            <label className="relative block text-sm font-medium">
              <span className="sr-only">Search feature map</span>
              <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="h-9 w-full rounded-md border border-border bg-background pl-9 pr-3 text-sm"
                aria-label="Search feature coverage"
                placeholder="Search by ID, feature, domain, backend, or mapping"
              />
            </label>
            <label className="block text-sm font-medium">
              <span className="sr-only">Filter by domain</span>
              <select
                value={domainFilter}
                onChange={(event) => setDomainFilter(event.target.value)}
                className="h-9 w-full rounded-md border border-border bg-background px-3 text-sm"
              >
                <option value="all">All domains</option>
                {featureCoverageDomains.map((domain) => (
                  <option key={domain.name} value={domain.name}>
                    {domain.name}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="overflow-x-auto rounded-md border border-border" role="region" aria-label="Feature coverage table" tabIndex={0}>
            <table className="w-full min-w-[72rem] text-left text-sm">
              <caption className="sr-only">Feature coverage map with backend status, GUI mapping, and acceptance criteria</caption>
              <thead className="bg-muted text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Feature</th>
                  <th className="px-4 py-3">Outcome</th>
                  <th className="px-4 py-3">Reality today</th>
                  <th className="px-4 py-3">Target GUI mapping and acceptance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredItems.map((item) => (
                  <FeatureRow key={item.id} item={item} />
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
