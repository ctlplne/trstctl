// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { CredentialChip } from "@/components/CredentialChip";
import { Button } from "@/components/ui/button";
import { Num } from "@/components/typography";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import type { ProviderActivity } from "@/lib/providerApi";

function activityColumns(): DataGridColumn<ProviderActivity>[] {
  return [
    {
      id: "event",
      header: translateNow("provider.activity.event"),
      cell: (item) => (
        <div className="grid gap-1">
          <span className="font-mono font-medium">{item.type}</span>
          <span className="text-muted-foreground">{item.operator_email || item.subject || item.operator_id}</span>
        </div>
      ),
    },
    {
      id: "customer",
      header: translateNow("source.provider.access.customer.aud580004"),
      cell: (item) => (item.tenant_id ? <CredentialChip value={item.tenant_id} label={translateNow("source.provider.access.customer.aud580004")} /> : null),
    },
    {
      id: "result",
      header: translateNow("provider.activity.result"),
      cell: (item) => (
        <div className="grid gap-1">
          {item.offboard_state === "pending" || item.offboard_state === "failed" || item.offboard_state === "completed" ? (
            <span>
              {translateNow(
                item.offboard_state === "completed"
                  ? "provider.offboard.completed"
                  : item.offboard_state === "failed"
                    ? "provider.offboard.failed"
                    : "provider.offboard.pending",
              )}
            </span>
          ) : null}
          {item.reason ? <span className="text-muted-foreground">{item.reason}</span> : null}
        </div>
      ),
    },
    { id: "time", header: translateNow("provider.activity.time"), cell: (item) => <time dateTime={item.at}>{formatDateTime(item.at)}</time> },
    { id: "sequence", header: translateNow("provider.activity.sequence"), cell: (item) => <Num>#{item.sequence}</Num> },
  ];
}

export function ProviderOffboardingAttention({
  activity,
  busy,
  onContinue,
}: {
  activity: ProviderActivity[] | null;
  busy: boolean;
  onContinue: (customerId: string, requestId: string) => void;
}) {
  // A pending deletion may already have removed the customer from the roster.
  // Read its continuation authority from the retained server activity, never
  // infer it from a role, a visible customer, or an old successful action.
  const outstanding = activity?.filter((item) => item.offboard_state === "pending" || item.offboard_state === "failed") ?? [];
  if (outstanding.length === 0) return null;
  return (
    <section className="mt-6" aria-labelledby="provider-offboard-attention">
      <h2 id="provider-offboard-attention" className="text-title font-semibold">
        {translateNow("provider.offboard.attention")}
      </h2>
      <DataGrid
        ariaLabel={translateNow("provider.offboard.attention")}
        className="mt-2"
        rows={outstanding}
        getRowId={(item) => item.event_id}
        columns={[
          ...activityColumns(),
          {
            id: "actions",
            header: translateNow("source.provider.col.actions.l3prov0017"),
            cell: (item) =>
              item.can_continue_offboard === true && item.offboard_state === "pending" && item.request_event_id && item.tenant_id ? (
                <Button type="button" variant="destructive-outline" loading={busy} onClick={() => onContinue(item.tenant_id!, item.request_event_id!)}>
                  {translateNow("provider.offboard.continue")}
                </Button>
              ) : null,
          },
        ]}
      />
    </section>
  );
}

export function ProviderActivityPanel({ activity }: { activity: ProviderActivity[] | null }) {
  // Pin the visible start to a served event, not its changing array index, so
  // polling does not move an operator who is reading older recent records.
  const [firstEventId, setFirstEventId] = useState<string | null>(null);
  const rows = activity ?? [];
  useEffect(() => {
    if (activity !== null && firstEventId && (activity.length <= 10 || !activity.some((item) => item.event_id === firstEventId))) {
      setFirstEventId(null);
    }
  }, [activity, firstEventId]);
  const start =
    rows.length > 10 && firstEventId
      ? Math.max(
          0,
          rows.findIndex((item) => item.event_id === firstEventId),
        )
      : 0;
  const pageRows = rows.slice(start, start + 10);
  return (
    <section className="mt-6" aria-labelledby="provider-activity-heading">
      <h2 id="provider-activity-heading" className="text-title font-semibold">
        {translateNow("source.recent.activity.6cb44b5633")}
      </h2>
      <DataGrid
        ariaLabel={translateNow("source.recent.activity.6cb44b5633")}
        className="mt-2"
        rows={pageRows}
        getRowId={(item) => item.event_id}
        state={activity === null ? "loading" : activity.length ? "ready" : "empty"}
        stateMessage={translateNow("dashboard.recentActivity.empty")}
        columns={activityColumns()}
        pagination={
          rows.length > 10 ? (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={start === 0}
                onClick={() => setFirstEventId(start <= 10 ? null : (rows[start - 10]?.event_id ?? null))}
              >
                {translateNow("provider.activity.newer")}
              </Button>
              <span className="text-caption text-muted-foreground" aria-live="polite">
                {translateNow("provider.activity.range", { start: start + 1, end: start + pageRows.length, total: rows.length })}
              </span>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={start + pageRows.length >= rows.length}
                onClick={() => setFirstEventId(rows[start + 10]?.event_id ?? null)}
              >
                {translateNow("provider.activity.older")}
              </Button>
            </div>
          ) : undefined
        }
      />
    </section>
  );
}
