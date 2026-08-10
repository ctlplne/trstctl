import { useState } from "react";
import { api, type MDMDeviceList, type MDMDeviceTrace, type MDMPollScheduleList } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";

function readMDMDevices(): Promise<MDMDeviceList> {
  return optionalApiCall<MDMDeviceList>("mdmDevices", { items: [], failed: 0, unobserved: 0, guidance: "" });
}

function readMDMDeviceTrace(mdm: string, id: string): Promise<MDMDeviceTrace> {
  return api.mdmDeviceTrace(mdm, id);
}

function readMDMPollSchedules(): Promise<MDMPollScheduleList> {
  return optionalApiCall<MDMPollScheduleList>("mdmPollSchedules", { items: [], guidance: "" });
}

// MDMDevicesPanel shows the read-only Intune/Jamf correlation (I5).
//
// Failed and unobserved are rendered as different things, and counted
// separately, because they are different problems: one device reported trouble,
// the other is a device nothing has heard from. Merging them into one
// "unhealthy" number sends somebody to re-push a profile that is already
// installed — the MDM was simply unreachable.
export function MDMDevicesPanel() {
  const devices = useApiQuery(["mdm-devices"], readMDMDevices);
  const schedules = useApiQuery(["mdm-poll-schedules"], readMDMPollSchedules);
  const [selected, setSelected] = useState<{ mdm: string; id: string } | null>(null);
  const trace = useApiQuery(["mdm-device-trace", selected?.mdm, selected?.id], () => readMDMDeviceTrace(selected?.mdm ?? "", selected?.id ?? ""), {
    enabled: selected !== null,
  });
  const items = devices.data?.items ?? [];
  const scheduleItems = schedules.data?.items ?? [];
  if (items.length === 0 && scheduleItems.length === 0) return null;
  return (
    <section aria-labelledby="mdm-devices-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="mdm-devices-heading" className="text-title font-semibold">
        {translateNow("source.mdm.devices.heading.i5mdm00001")}
      </h2>
      {scheduleItems.length > 0 ? (
        <div className="space-y-1">
          <h3 className="text-sm font-semibold">{translateNow("source.vantage.relay.a3vant0003")}</h3>
          <ul className="space-y-1 text-caption text-muted-foreground">
            {scheduleItems.map((schedule) => (
              <li key={schedule.mdm ?? schedule.base_url}>
                <span className="font-medium">{schedule.mdm ?? "—"}</span>
                {" · "}
                {translateNow(schedule.enabled ? "protocols.ari.schedulerEnabled" : "protocols.ari.schedulerDisabled")}
                {" · "}
                {schedule.execution ?? "—"}
                {" · "}
                {translateNow("discovery.monitoring.columnLastRun")}: {schedule.last_run_at?.slice(0, 16).replace("T", " ") ?? "—"}
                {schedule.last_error ? <span className="mt-1 block text-risk-critical">{schedule.last_error}</span> : null}
              </li>
            ))}
          </ul>
          <p className="text-caption text-muted-foreground">{schedules.data?.guidance}</p>
        </div>
      ) : null}
      {items.length > 0 ? (
        <>
          <p className="text-sm">
            {translateNow("source.mdm.devices.counts.i5mdm00002", {
              value1: String(items.length),
              value2: String(devices.data?.failed ?? 0),
              value3: String(devices.data?.unobserved ?? 0),
            })}
          </p>
          {(devices.data?.renewal_at_risk ?? 0) > 0 ? (
            <p className="text-sm text-risk-critical">
              {translateNow("source.mdm.devices.renewalrisk.i5mdm00004", {
                value1: String(devices.data?.renewal_at_risk ?? 0),
              })}
            </p>
          ) : null}
          <ul className="space-y-2 text-sm">
            {items.slice(0, 25).map((item) => (
              <li key={`${item.mdm}:${item.mdm_device_id}:${item.transaction_id ?? ""}`} className="border-b border-border pb-2 last:border-0">
                <span className="font-mono text-xs">{item.device_name || item.mdm_device_id}</span>{" "}
                <span className="text-caption text-muted-foreground">
                  {item.install_state === "unknown" ? translateNow("source.mdm.devices.unobserved.i5mdm00003") : item.install_state}
                </span>
                {item.install_detail ? <span className="mt-1 block text-caption text-muted-foreground">{item.install_detail}</span> : null}
                {item.renewal_at_risk && item.renewal_detail ? <span className="mt-1 block text-caption text-risk-critical">{item.renewal_detail}</span> : null}
                <button
                  type="button"
                  className="mt-1 block text-caption text-brand-accent underline"
                  onClick={() => setSelected({ mdm: item.mdm, id: item.mdm_device_id })}
                >
                  {translateNow("source.view.details.d1bf045bb5")}
                </button>
                {selected?.mdm === item.mdm && selected.id === item.mdm_device_id && trace.data ? (
                  <div className="mt-2 rounded-control border border-border p-2" role="status">
                    <p>{trace.data.trace.summary}</p>
                    <ol className="mt-1 grid gap-1 text-caption text-muted-foreground">
                      {trace.data.trace.steps.map((step) => (
                        <li key={step.stage}>
                          <span className="font-mono">{step.stage}</span>: {step.outcome}
                          {step.detail ? <> {translateNow("source.mdm.devices.stepdetail.i5mdm00005", { value1: step.detail })}</> : null}
                        </li>
                      ))}
                    </ol>
                  </div>
                ) : null}
                {selected?.mdm === item.mdm && selected.id === item.mdm_device_id && trace.error ? (
                  <p className="mt-2 text-caption text-risk-critical" role="alert">
                    {trace.error}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
          <p className="text-caption text-muted-foreground">{devices.data?.guidance}</p>
        </>
      ) : null}
    </section>
  );
}
