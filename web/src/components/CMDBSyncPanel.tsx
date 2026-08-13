import { type CMDBReconcileSchedule } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";

// CMDBSyncPanel shows whether ownership is actually being re-read (I2).
//
// It renders nothing when no schedule was ever configured — a panel saying
// "not set up" on every estate that does not use ServiceNow is noise. But once
// a schedule EXISTS it always renders, including when it is paused or failing,
// because those are the two states that otherwise look identical to a healthy
// sync that had nothing to do.
function readCMDBSchedule(): Promise<CMDBReconcileSchedule> {
  return optionalApiCall<CMDBReconcileSchedule>("cmdbSchedule", {
    configured: false,
    enabled: false,
    read_count: 0,
    pages_completed: 0,
    coverage_complete: false,
    coverage_status: "not_configured",
    removed_count: 0,
    changed_count: 0,
    guidance: "",
  });
}

export function CMDBSyncPanel() {
  // Optional-method guard, as on the other Owners panels: an absent client
  // method must hide this panel, not break the page.
  const schedule = useApiQuery(["cmdb-schedule"], readCMDBSchedule);
  const s = schedule.data ?? undefined;
  if (!s?.configured) return null;
  return (
    <section aria-labelledby="cmdb-sync-heading" className="ui-panel space-y-2 p-comfortable">
      <h2 id="cmdb-sync-heading" className="text-title font-semibold">
        {translateNow("source.cmdb.sync.heading.i2own00009")}
      </h2>
      {!s.enabled ? (
        <p className="text-sm">{translateNow("source.cmdb.sync.paused.i2own00010")}</p>
      ) : s.last_run_at ? (
        <p className="text-sm">
          {translateNow("source.cmdb.sync.lastrun.i2own00011", {
            value1: s.last_run_at.slice(0, 16).replace("T", " "),
            value2: String(Math.round((s.interval_seconds ?? 0) / 60)),
          })}
        </p>
      ) : !s.sweep_id ? (
        <p className="text-sm">{translateNow("source.cmdb.sync.neverran.i2own00012")}</p>
      ) : null}
      {s.last_error ? <p className="text-sm text-risk-critical">{translateNow("source.cmdb.sync.failing.i2own00013", { value1: s.last_error })}</p> : null}
      {s.sweep_id ? (
        <div className="rounded-control border border-border bg-muted/30 p-3 text-sm" role="status">
          <p>
            {s.expected_count == null
              ? translateNow("cmdb.sync.coverage.unknown.aud460001", {
                  read: String(s.read_count),
                  pages: String(s.pages_completed),
                })
              : translateNow("cmdb.sync.coverage.known.aud460002", {
                  read: String(s.read_count),
                  expected: String(s.expected_count),
                  pages: String(s.pages_completed),
                })}
          </p>
          {s.coverage_complete ? (
            <p className="mt-1 text-success">
              {translateNow("cmdb.sync.coverage.complete.aud460003", {
                changed: String(s.changed_count),
                removed: String(s.removed_count),
              })}
            </p>
          ) : (
            <p className="mt-1 text-risk-warning">
              {translateNow("cmdb.sync.coverage.incomplete.aud460004", {
                cursor: s.next_cursor || "start of cmdb_ci",
              })}
            </p>
          )}
        </div>
      ) : null}
      {s.execution === "relay" ? <p className="text-caption text-muted-foreground">{translateNow("source.cmdb.sync.relay.i2own00014")}</p> : null}
      <p className="text-caption text-muted-foreground">{s.guidance}</p>
    </section>
  );
}
