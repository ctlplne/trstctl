import { useState } from "react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { formatDateTime as formatDate } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, type SecretRotationSchedule } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RotationHealthBadges } from "./SecretsPageParts";

type ScheduleAction = "pause" | "resume" | "retire";

/** The schedule table owns the lifecycle controls and their exact server
 * readback. The page still owns create and due-run, so both operations refresh
 * the same list without another copy of schedule state. */
export function SecretRotationScheduleTable({
  schedules,
  canWrite,
  onUpdated,
  onRefresh,
  onNotice,
}: {
  schedules: SecretRotationSchedule[];
  canWrite: boolean;
  onUpdated: (schedule: SecretRotationSchedule) => void;
  onRefresh: () => Promise<unknown>;
  onNotice: (notice: string) => void;
}) {
  const { t } = useTranslation();
  const [busyID, setBusyID] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retireSchedule, setRetireSchedule] = useState<SecretRotationSchedule | null>(null);

  async function control(schedule: SecretRotationSchedule, action: ScheduleAction) {
    setError(null);
    setBusyID(schedule.id);
    try {
      const updated =
        action === "pause"
          ? await api.pauseSecretRotationSchedule(schedule.id)
          : action === "resume"
            ? await api.resumeSecretRotationSchedule(schedule.id)
            : await api.retireSecretRotationSchedule(schedule.id);
      onUpdated(updated);
      const actionLabel = action === "pause" ? t("secrets.rotation.pause") : action === "resume" ? t("secrets.rotation.resume") : t("secrets.rotation.retire");
      onNotice(t("secrets.rotation.controlComplete", { name: updated.name, action: actionLabel }));
      setRetireSchedule(null);
      await onRefresh();
    } catch (err) {
      setError(apiProblemMessage(err, t("secrets.rotation.controlFailed")));
    } finally {
      setBusyID(null);
    }
  }

  const columns: Array<DataGridColumn<SecretRotationSchedule>> = [
    { id: "name", header: t("secrets.rotation.scheduleNameColumn"), sortable: true, cell: (item) => <span className="font-medium">{item.name}</span> },
    {
      id: "key",
      header: t("secrets.rotation.scheduleKeyColumn"),
      cell: (item) => (
        <span className="block max-w-44 truncate font-mono text-xs" title={item.key}>
          {item.key}
        </span>
      ),
    },
    { id: "interval", header: t("secrets.rotation.scheduleIntervalColumn"), cell: (item) => formatRotationInterval(item.interval_seconds) },
    {
      id: "enabled",
      header: t("secrets.rotation.scheduleStatus"),
      cell: (item) => (
        <StatusBadge
          vocabulary="lifecycle"
          value={item.retired_at ? "retired" : item.enabled ? "enabled" : "paused"}
          label={item.retired_at ? t("secrets.rotation.retired") : item.enabled ? t("secrets.rotation.enabled") : t("secrets.rotation.paused")}
          tone={item.retired_at ? "neutral" : item.enabled ? "success" : "warning"}
        />
      ),
    },
    {
      id: "last-run",
      header: t("secrets.rotation.scheduleLastRunColumn"),
      cell: (item) => <StatusBadge vocabulary="lifecycle" value={item.last_run_status || "never"} />,
    },
    {
      id: "next-run",
      header: t("secrets.rotation.nextDue"),
      cell: (item) => <span title={!item.enabled ? t("secrets.rotation.retainedDue") : undefined}>{formatDate(item.next_run_at)}</span>,
    },
    {
      id: "rotation-health",
      header: t("secrets.rotation.scheduleHealthColumn"),
      cell: (item) =>
        item.retired_at ? (
          <span className="text-caption text-muted-foreground">{t("secrets.rotation.retired")}</span>
        ) : (
          <RotationHealthBadges schedule={item} />
        ),
    },
    {
      id: "actions",
      header: t("secrets.rotation.scheduleActions"),
      cell: (item) =>
        item.retired_at ? null : (
          <div className="flex flex-wrap gap-1">
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={!canWrite || busyID !== null}
              loading={busyID === item.id && retireSchedule?.id !== item.id}
              onClick={() => void control(item, item.enabled ? "pause" : "resume")}
            >
              {item.enabled ? t("secrets.rotation.pause") : t("secrets.rotation.resume")}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="destructive-outline"
              disabled={!canWrite || busyID !== null}
              onClick={() => {
                setError(null);
                setRetireSchedule(item);
              }}
            >
              {t("secrets.rotation.retire")}
            </Button>
          </div>
        ),
    },
  ];

  return (
    <>
      {error && <ErrorState title={t("secrets.rotation.controlFailed")}>{error}</ErrorState>}
      <DataGrid
        ariaLabel={t("secrets.rotation.scheduleTableLabel")}
        rows={schedules}
        columns={columns}
        getRowId={(item) => item.id}
        state={schedules.length === 0 ? "empty" : "ready"}
        stateTitle={t("secrets.rotation.scheduleEmptyTitle")}
        stateMessage={t("secrets.rotation.scheduleStateMessage")}
      />
      {retireSchedule && (
        <Dialog
          open
          role="alertdialog"
          onClose={() => {
            if (busyID === null) setRetireSchedule(null);
          }}
          closeOnBackdropClick={busyID === null}
          titleId="retire-rotation-schedule-heading"
          descriptionId="retire-rotation-schedule-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card shadow-elevation2"
        >
          <div className="grid gap-4 p-5">
            <h2 id="retire-rotation-schedule-heading" className="text-title font-semibold">
              {t("secrets.rotation.retireSchedule")}
            </h2>
            <p id="retire-rotation-schedule-description" className="text-sm text-muted-foreground">
              {t("secrets.rotation.retireDescription", { name: retireSchedule.name })}
            </p>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" disabled={busyID !== null} onClick={() => setRetireSchedule(null)}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="button" variant="destructive" loading={busyID !== null} onClick={() => void control(retireSchedule, "retire")}>
                {t("secrets.rotation.retire")}
              </Button>
            </div>
          </div>
        </Dialog>
      )}
    </>
  );
}

function formatRotationInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "-";
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
