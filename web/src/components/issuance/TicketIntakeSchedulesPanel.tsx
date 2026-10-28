import { useState } from "react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Button } from "@/components/ui/button";
import { Num } from "@/components/typography";
import { TicketIntakeWizard } from "./TicketIntakeWizard";
import { api, type TicketIntakeSchedule } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { apiProblemMessage } from "@/lib/apiProblem";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { translateNow as t } from "@/i18n/I18nProvider";

export const ticketIntakeSchedulesQueryKey = ["ticket-intake-schedules"] as const;
// An omitted name on an older server identifies the protocol's default source.
const scheduleName = (schedule: TicketIntakeSchedule) => schedule.name ?? "default";
const identity = (schedule: TicketIntakeSchedule) => `${schedule.system}:${scheduleName(schedule)}`;

function Coverage({ schedule }: { schedule: TicketIntakeSchedule }) {
  return (
    <div className="space-y-1 text-caption">
      <p>
        {schedule.system} · {t(schedule.enabled ? "protocols.ari.schedulerEnabled" : "protocols.ari.schedulerDisabled")} ·{" "}
        {t("discovery.monitoring.columnLastRun")}: <Num>{schedule.last_run_at?.slice(0, 16).replace("T", " ") ?? "—"}</Num>
      </p>
      {schedule.sweep_id ? (
        <>
          <p>
            {schedule.expected_count == null
              ? t("ticket.intake.coverage.unknown.aud470001", {
                  provider: schedule.system ?? "ITSM",
                  read: String(schedule.read_count),
                  pages: String(schedule.pages_completed),
                })
              : t("ticket.intake.coverage.known.aud470002", {
                  provider: schedule.system ?? "ITSM",
                  read: String(schedule.read_count),
                  expected: String(schedule.expected_count),
                  pages: String(schedule.pages_completed),
                })}
          </p>
          <p className={schedule.coverage_complete ? "text-success" : "text-risk-warning"}>
            {schedule.coverage_complete
              ? t("ticket.intake.coverage.complete.aud470003", { eligible: String(schedule.eligible_count), skipped: String(schedule.skipped_count) })
              : t("ticket.intake.coverage.incomplete.aud470004", { cursor: schedule.next_cursor || "start" })}
          </p>
        </>
      ) : null}
      {schedule.last_error ? <p className="text-risk-critical">{schedule.last_error}</p> : null}
      <details>
        <summary>{t("ticket.intake.named.evidence")}</summary>
        <p>{schedule.guidance}</p>
      </details>
    </div>
  );
}

export function TicketIntakeSchedulesPanel({ canConfigure }: { canConfigure: boolean }) {
  const queryClient = useQueryClient();
  const query = useApiQuery(ticketIntakeSchedulesQueryKey, () => api.ticketIntakeSchedules());
  const rows = query.data?.items ?? [];
  const [editing, setEditing] = useState<{ current?: TicketIntakeSchedule } | null>(null);
  const [removing, setRemoving] = useState<{ schedule: TicketIntakeSchedule; key: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function savedSchedule(schedule: TicketIntakeSchedule) {
    queryClient.setQueryData<{ items: TicketIntakeSchedule[] }>(ticketIntakeSchedulesQueryKey, (current) => ({
      items: [...(current?.items ?? []).filter((item) => identity(item) !== identity(schedule)), schedule].sort((a, b) =>
        identity(a).localeCompare(identity(b)),
      ),
    }));
    void queryClient.invalidateQueries({ queryKey: ticketIntakeSchedulesQueryKey });
    setEditing(null);
    setSaved(true);
  }

  async function remove() {
    if (!removing || busy || !removing.schedule.system) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteTicketIntakeSchedule(removing.schedule.system, scheduleName(removing.schedule), removing.key);
      queryClient.setQueryData<{ items: TicketIntakeSchedule[] }>(ticketIntakeSchedulesQueryKey, (current) => ({
        items: (current?.items ?? []).filter((item) => identity(item) !== identity(removing.schedule)),
      }));
      void queryClient.invalidateQueries({ queryKey: ticketIntakeSchedulesQueryKey });
      setRemoving(null);
    } catch (failure) {
      setError(apiProblemMessage(failure, t("ticket.intake.named.removeFailed")));
    } finally {
      setBusy(false);
    }
  }

  const columns: DataGridColumn<TicketIntakeSchedule>[] = [
    { id: "name", header: t("ticket.intake.named.name"), cell: (schedule) => <Num>{scheduleName(schedule)}</Num> },
    {
      id: "source",
      header: t("ticket.intake.named.sourceStep"),
      cell: (schedule) => (
        <div className="text-caption">
          <p>
            <Num>
              {schedule.system} · {schedule.sn_table || schedule.jira_project}
            </Num>
          </p>
          <p>
            {t("ticket.intake.setup.owner_field")}: <Num>{schedule.owner_field || t("ticket.intake.setup.none")}</Num>
          </p>
        </div>
      ),
    },
    { id: "coverage", header: t("ticket.intake.named.coverage"), cell: (schedule) => <Coverage schedule={schedule} /> },
    ...(canConfigure
      ? [
          {
            id: "actions",
            header: t("ticket.intake.named.actions"),
            cell: (schedule: TicketIntakeSchedule) => (
              <div className="flex gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setEditing({ current: schedule });
                    setSaved(false);
                  }}
                >
                  {t("ticket.intake.setup.edit")}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="destructive-outline"
                  onClick={() => {
                    setRemoving({ schedule, key: newIdempotencyKey() });
                    setError(null);
                  }}
                >
                  {t("ticket.intake.named.remove")}
                </Button>
              </div>
            ),
          },
        ]
      : []),
  ];

  return (
    <section className="space-y-3">
      <h3 className="text-sm font-semibold">{t("source.vantage.relay.a3vant0003")}</h3>
      {saved ? <p role="status">{t("ticket.intake.setup.saved")}</p> : null}
      {canConfigure && !editing ? (
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            setEditing({});
            setSaved(false);
          }}
        >
          {t("ticket.intake.setup.configure")}
        </Button>
      ) : null}
      {editing ? (
        <TicketIntakeWizard
          key={editing.current ? identity(editing.current) : "new"}
          initial={editing.current}
          onCancel={() => setEditing(null)}
          onSaved={savedSchedule}
        />
      ) : null}
      {removing ? (
        <section aria-label={t("ticket.intake.named.removeReview")} className="space-y-2 rounded-control border border-border p-3">
          <p>{t("ticket.intake.named.removeHelp", { name: scheduleName(removing.schedule), system: removing.schedule.system ?? "ITSM" })}</p>
          {error ? <p role="alert">{error}</p> : null}
          <div className="flex gap-2">
            <Button type="button" variant="destructive" loading={busy} onClick={() => void remove()}>
              {t("ticket.intake.named.removeConfirm")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setRemoving(null)}>
              {t("cmdb.setup.cancel")}
            </Button>
          </div>
        </section>
      ) : null}
      <DataGrid
        ariaLabel={t("ticket.intake.named.list")}
        rows={rows}
        columns={columns}
        getRowId={identity}
        state={query.loading ? "loading" : query.error ? "error" : rows.length ? "ready" : "empty"}
        stateTitle={!query.loading && !query.error && rows.length === 0 ? t("ticket.intake.named.empty") : undefined}
        stateMessage={query.error ?? t("ticket.intake.named.emptyHelp")}
      />
    </section>
  );
}
