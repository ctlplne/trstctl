import { useState } from "react";
import { DataGrid, type DataGridColumn, type DataGridToolbarControls } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { Dialog } from "@/components/Dialog";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DiscoverySchedule, type DiscoverySource } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

type ScheduleAction = "pause" | "resume" | "retire";

/** The server owns schedule state. Each control reads the exact returned row and
 * refreshes the list; retirement remains visible as a durable tombstone. */
export function DiscoveryScheduleTable({
  schedules,
  sourceByID,
  onUpdated,
  onRefresh,
  onNotice,
}: {
  schedules: DiscoverySchedule[];
  sourceByID: Map<string, DiscoverySource>;
  onUpdated: (schedule: DiscoverySchedule) => void;
  onRefresh: () => Promise<unknown>;
  onNotice: (message: string) => void;
}) {
  const { t, formatDateTime } = useTranslation();
  const canWrite = useCan("discovery:write");
  const [busyID, setBusyID] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retireSchedule, setRetireSchedule] = useState<DiscoverySchedule | null>(null);

  async function control(schedule: DiscoverySchedule, action: ScheduleAction) {
    setError(null);
    setBusyID(schedule.id);
    try {
      const updated =
        action === "pause"
          ? await api.pauseDiscoverySchedule(schedule.id)
          : action === "resume"
            ? await api.resumeDiscoverySchedule(schedule.id)
            : await api.retireDiscoverySchedule(schedule.id);
      onUpdated(updated);
      await onRefresh();
      onNotice(
        t("discovery.schedule.controlComplete", {
          name: updated.name,
          action: t(`discovery.schedule.${action}`),
        }),
      );
      setRetireSchedule(null);
    } catch (err) {
      setError(apiProblemMessage(err, t("discovery.schedule.controlFailed")));
    } finally {
      setBusyID(null);
    }
  }

  const columns: Array<DataGridColumn<DiscoverySchedule>> = [
    {
      id: "name",
      header: t("discovery.schedule.name"),
      cell: (schedule) => (
        <div>
          <div className="font-medium">{schedule.name}</div>
          <div className="font-mono text-xs text-muted-foreground">{schedule.id}</div>
        </div>
      ),
    },
    {
      id: "source",
      header: t("discovery.schedule.source"),
      cell: (schedule) => sourceByID.get(schedule.source_id)?.name ?? <span className="font-mono text-xs">{schedule.source_id}</span>,
    },
    { id: "interval", header: t("discovery.schedule.interval"), cell: (schedule) => `${schedule.interval_seconds}s` },
    {
      id: "state",
      header: t("discovery.schedule.state"),
      cell: (schedule) => (
        <StatusBadge
          vocabulary="lifecycle"
          value={schedule.retired_at ? "retired" : schedule.enabled ? "enabled" : "paused"}
          label={schedule.retired_at ? t("discovery.schedule.retired") : schedule.enabled ? t("discovery.schedule.enabled") : t("discovery.schedule.paused")}
          tone={schedule.retired_at ? "neutral" : schedule.enabled ? "success" : "warning"}
        />
      ),
    },
    { id: "updated", header: t("discovery.schedule.updated"), cell: (schedule) => formatDateTime(schedule.updated_at ?? "") },
    {
      id: "actions",
      header: t("discovery.schedule.actions"),
      cell: (schedule) =>
        schedule.retired_at || !canWrite ? null : (
          <div className="flex flex-wrap gap-1">
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busyID !== null}
              loading={busyID === schedule.id && retireSchedule?.id !== schedule.id}
              onClick={() => void control(schedule, schedule.enabled ? "pause" : "resume")}
            >
              {schedule.enabled ? t("discovery.schedule.pause") : t("discovery.schedule.resume")}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="destructive-outline"
              disabled={busyID !== null}
              onClick={() => {
                setError(null);
                setRetireSchedule(schedule);
              }}
            >
              {t("discovery.schedule.retire")}
            </Button>
          </div>
        ),
    },
  ];

  return (
    <>
      {error && <ErrorState title={t("discovery.schedule.controlFailed")}>{error}</ErrorState>}
      <DataGrid
        ariaLabel={t("discovery.schedule.table")}
        rows={schedules}
        columns={columns}
        getRowId={(schedule) => schedule.id}
        showColumnChooser
        viewStorageKey="discovery-schedules"
        toolbar={({ columnChooser, savedViews }: DataGridToolbarControls) => <DataGridToolbar columnChooser={columnChooser} savedViews={savedViews} />}
      />
      {retireSchedule && (
        <Dialog
          open
          role="alertdialog"
          onClose={() => {
            if (busyID === null) setRetireSchedule(null);
          }}
          closeOnBackdropClick={busyID === null}
          titleId="retire-discovery-schedule-heading"
          descriptionId="retire-discovery-schedule-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card shadow-elevation2"
        >
          <div className="grid gap-4 p-5">
            <h2 id="retire-discovery-schedule-heading" className="text-title font-semibold">
              {t("discovery.schedule.retireTitle")}
            </h2>
            <p id="retire-discovery-schedule-description" className="text-sm text-muted-foreground">
              {t("discovery.schedule.retireDescription", { name: retireSchedule.name })}
            </p>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" disabled={busyID !== null} onClick={() => setRetireSchedule(null)}>
                {t("discovery.schedule.cancel")}
              </Button>
              <Button type="button" variant="destructive" loading={busyID !== null} onClick={() => void control(retireSchedule, "retire")}>
                {t("discovery.schedule.retire")}
              </Button>
            </div>
          </div>
        </Dialog>
      )}
    </>
  );
}
