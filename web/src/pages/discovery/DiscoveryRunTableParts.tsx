import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DataGrid, type DataGridColumn, type DataGridToolbarControls } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { StatusBadge } from "@/components/StatusBadge";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import type { DiscoveryRun, DiscoverySource } from "@/lib/api";

function shortID(id: string): string {
  return id.length <= 12 ? id : id.slice(0, 12);
}

function formatDateTime(value?: string): string {
  return formatDateTimePolicy(value);
}

function gridControlsToolbar({ columnChooser, savedViews }: DataGridToolbarControls) {
  return <DataGridToolbar columnChooser={columnChooser} savedViews={savedViews} />;
}

function runExecution(run: DiscoveryRun): string {
  if (run.execution !== "relay") return translateNow("discovery.run.controlPlane");
  const relay = run.executed_by_agent_id || run.required_agent_id;
  const suffix = relay ? ` · ${shortID(relay)}` : "";
  return `${translateNow("discovery.run.relay")} · ${run.segment || translateNow("discovery.run.unbound")}${suffix}`;
}

export function RunTable({
  runs,
  sourceByID,
  busy,
  onRetry,
  hasOlder,
  loadingOlder,
  onLoadOlder,
}: {
  runs: DiscoveryRun[];
  sourceByID: Map<string, DiscoverySource>;
  busy: string | null;
  onRetry: (run: DiscoveryRun) => void;
  hasOlder: boolean;
  loadingOlder: boolean;
  onLoadOlder: () => void;
}) {
  const columns: Array<DataGridColumn<DiscoveryRun>> = [
    {
      id: "run",
      header: "Run",
      className: "font-mono text-xs",
      cell: (run) => shortID(run.id),
    },
    {
      id: "source",
      header: "Source",
      cell: (run) => sourceByID.get(run.source_id)?.name ?? <span className="font-mono text-xs">{run.source_id}</span>,
    },
    {
      id: "status",
      header: "Status",
      cell: (run) => <StatusBadge vocabulary="lifecycle" value={run.status} />,
    },
    {
      id: "targets",
      header: "Targets",
      cell: (run) => run.targets,
    },
    {
      id: "discovered",
      header: "Discovered",
      cell: (run) => run.discovered,
    },
    {
      id: "failed",
      header: "Failed",
      cell: (run) => run.failed + run.rejected + run.blocked,
    },
    {
      id: "failure-detail",
      header: "Failure detail",
      cell: (run) => {
        const unresolved = (run.target_results ?? []).filter((result) => result.status !== "succeeded");
        if (!run.error && unresolved.length === 0) {
          return <span className="text-muted-foreground">—</span>;
        }
        return (
          <div className="max-w-[28rem] space-y-1 text-xs">
            {run.error ? (
              <span className="block break-words text-risk-critical" title={run.error}>
                {run.error}
              </span>
            ) : null}
            {unresolved.length > 0 ? (
              <ul className="list-none space-y-0.5 pl-0 font-mono" aria-label={translateNow("discovery.run.targetOutcomes")}>
                {unresolved.map((result) => (
                  <li key={`${run.id}:${result.target}`} className="break-words">
                    <span className="text-foreground">{result.target}</span> <StatusBadge vocabulary="lifecycle" value={result.status} />
                    {/* A reason the run summary already states is not repeated under every target. */}
                    {result.error && !run.error?.includes(result.error) ? <span className="text-muted-foreground"> {result.error}</span> : null}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "executor",
      header: translateNow("discovery.run.executor"),
      cell: (run) => runExecution(run),
    },
    {
      id: "recovery",
      header: translateNow("discovery.run.recoveryColumn"),
      cell: (run) => {
        if (run.retry_of_run_id) {
          return <span className="text-xs text-muted-foreground">{translateNow("discovery.run.retries", { id: shortID(run.retry_of_run_id) })}</span>;
        }
        if (run.status !== "failed" && run.status !== "partial") {
          return <span className="text-muted-foreground">—</span>;
        }
        return (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy === `retry:${run.id}`}
            aria-label={translateNow("discovery.run.retryAria", { id: shortID(run.id) })}
            onClick={() => onRetry(run)}
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {busy === `retry:${run.id}` ? translateNow("discovery.run.retrying") : translateNow("discovery.run.retryAction")}
          </Button>
        );
      },
    },
    {
      id: "completed",
      header: "Completed",
      cell: (run) => formatDateTime(run.completed_at),
    },
  ];
  return (
    <div className="grid gap-3">
      <DataGrid
        ariaLabel="Discovery runs"
        rows={runs}
        columns={columns}
        getRowId={(run) => run.id}
        showColumnChooser
        viewStorageKey="discovery-runs"
        toolbar={gridControlsToolbar}
      />
      {hasOlder ? (
        <Button type="button" variant="outline" disabled={loadingOlder} onClick={onLoadOlder}>
          {translateNow(loadingOlder ? "discovery.run.loadingOlder" : "discovery.run.loadOlder")}
        </Button>
      ) : null}
    </div>
  );
}
