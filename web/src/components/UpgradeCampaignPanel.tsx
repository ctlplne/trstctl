import { useEffect, useState } from "react";
import { type AgentUpgradeCampaign } from "@/lib/api";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";

function readCampaign(): Promise<AgentUpgradeCampaign> {
  return optionalApiCall<AgentUpgradeCampaign>("agentUpgradeCampaign", {
    active: false, rings: {}, versions: {}, guidance: "",
  });
}

// UpgradeCampaignPanel shows a staged rollout's real state (A5).
//
// Halted and paused render differently on purpose: one is the machine's finding
// that a build is bad, the other is a person stopping deliberately. An operator
// resuming a pause they made must not silently resume a halt they never saw.
// The halted ring is shown because that is where a resume restarts — skipping
// ahead would leave the agents whose failure stopped the rollout on the broken
// build while the campaign reported success.
export function UpgradeCampaignPanel() {
  // useEffect rather than useApiQuery: the Agents page fetches this way, and a
  // panel that dragged a QueryClient requirement onto a page that has none
  // would take the whole page down wherever that provider is absent.
  const [data, setData] = useState<AgentUpgradeCampaign | null>(null);
  useEffect(() => {
    let active = true;
    readCampaign()
      .then((c) => {
        if (active) setData(c);
      })
      .catch(() => {
        // A panel that cannot load hides itself. It must not blank the fleet
        // page an operator opened to look at their agents.
        if (active) setData(null);
      });
    return () => {
      active = false;
    };
  }, []);
  const rings = data?.rings ?? {};
  if (!data?.active && Object.keys(rings).length === 0) return null;
  const ringSummary = Object.entries(rings)
    .map(([ring, n]) => `${ring} ${n}`)
    .join(", ");
  return (
    <section aria-labelledby="upgrade-campaign-heading" className="ui-panel space-y-2 p-comfortable">
      <h2 id="upgrade-campaign-heading" className="text-title font-semibold">
        {translateNow("source.fleet.upgrade.heading.a5fl000001")}
      </h2>
      {data?.status === "halted" ? (
        <p className="text-sm text-risk-critical">
          {translateNow("source.fleet.upgrade.halted.a5fl000002", {
            value1: data.halted_at_ring ?? "",
          })}
        </p>
      ) : data?.status === "paused" ? (
        <p className="text-sm">{translateNow("source.fleet.upgrade.paused.a5fl000003")}</p>
      ) : null}
      {data?.reason ? <p className="text-sm">{data.reason}</p> : null}
      <p className="text-caption text-muted-foreground">
        {translateNow("source.fleet.upgrade.rings.a5fl000004", { value1: ringSummary })}
      </p>
      <ul className="space-y-1 text-sm">
        {Object.entries(data?.versions ?? {}).map(([version, n]) => (
          <li key={version} className="text-caption text-muted-foreground">
            <span className="font-mono text-xs">{version}</span> — {String(n)}
          </li>
        ))}
      </ul>
      <p className="text-caption text-muted-foreground">{data?.guidance}</p>
    </section>
  );
}
