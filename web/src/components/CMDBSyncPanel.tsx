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
  return optionalApiCall<CMDBReconcileSchedule>("cmdbSchedule", { configured: false, enabled: false, guidance: "" });
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
      ) : (
        <p className="text-sm">{translateNow("source.cmdb.sync.neverran.i2own00012")}</p>
      )}
      {s.last_error ? (
        <p className="text-sm text-risk-critical">
          {translateNow("source.cmdb.sync.failing.i2own00013", { value1: s.last_error })}
        </p>
      ) : null}
      <p className="text-caption text-muted-foreground">{s.guidance}</p>
    </section>
  );
}
