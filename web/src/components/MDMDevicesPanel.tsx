import { type MDMDeviceList } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";

function readMDMDevices(): Promise<MDMDeviceList> {
  return optionalApiCall<MDMDeviceList>("mdmDevices", { items: [], failed: 0, unobserved: 0, guidance: "" });
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
  const items = devices.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <section aria-labelledby="mdm-devices-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="mdm-devices-heading" className="text-title font-semibold">
        {translateNow("source.mdm.devices.heading.i5mdm00001")}
      </h2>
      <p className="text-sm">
        {translateNow("source.mdm.devices.counts.i5mdm00002", {
          value1: String(items.length),
          value2: String(devices.data?.failed ?? 0),
          value3: String(devices.data?.unobserved ?? 0),
        })}
      </p>
      <ul className="space-y-2 text-sm">
        {items.slice(0, 25).map((item) => (
          <li key={`${item.mdm}:${item.mdm_device_id}:${item.transaction_id ?? ""}`} className="border-b border-border pb-2 last:border-0">
            <span className="font-mono text-xs">{item.device_name || item.mdm_device_id}</span>{" "}
            <span className="text-caption text-muted-foreground">
              {item.install_state === "unknown"
                ? translateNow("source.mdm.devices.unobserved.i5mdm00003")
                : item.install_state}
            </span>
            {item.install_detail ? (
              <span className="mt-1 block text-caption text-muted-foreground">{item.install_detail}</span>
            ) : null}
          </li>
        ))}
      </ul>
      <p className="text-caption text-muted-foreground">{devices.data?.guidance}</p>
    </section>
  );
}
