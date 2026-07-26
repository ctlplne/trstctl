import { describe, expect, it } from "vitest";
import { sourceActivityByID } from "@/pages/discovery/DiscoveryPageParts";
import type { DiscoveryMonitoring } from "@/lib/api";

type MonitoringSource = DiscoveryMonitoring["sources"][number];

function monitoringRow(overrides: Partial<MonitoringSource> & { source_id: string }): MonitoringSource {
  return {
    kind: "network",
    name: "estate scan",
    schedule_id: "",
    scheduled: false,
    run_count: 1,
    completed_run_count: 1,
    failed_run_count: 0,
    finding_count: 0,
    open_finding_count: 0,
    certificate_inventory_count: 0,
    monitoring_interval_seconds: 3600,
    last_run_id: "run-1",
    last_run_status: "succeeded",
    last_run_error: "",
    findings_path: "",
    repository_path: "",
    updated_at: "2026-07-26T00:00:00Z",
    ...overrides,
  } as MonitoringSource;
}

// S-C15: the join is what lets the sources table answer "did this run, and
// did it find anything" without a trip to the Runs tab.
describe("discovery source activity join", () => {
  it("keys activity by source id and carries last run, findings, and schedule", () => {
    const activity = sourceActivityByID([
      monitoringRow({
        source_id: "src-1",
        scheduled: true,
        finding_count: 12,
        open_finding_count: 3,
        last_run_completed_at: "2026-07-26T10:00:00Z",
      }),
    ]);

    expect(activity.get("src-1")).toMatchObject({
      lastRunStatus: "succeeded",
      lastRunAt: "2026-07-26T10:00:00Z",
      findings: 12,
      openFindings: 3,
      scheduled: true,
      drifting: false,
      neverRan: false,
    });
  });

  it("flags a scheduled source whose most recent run failed as drifting", () => {
    const activity = sourceActivityByID([
      monitoringRow({ source_id: "src-2", scheduled: true, last_run_status: "failed", failed_run_count: 2, last_run_error: "dial tcp: timeout" }),
    ]);

    const row = activity.get("src-2");
    expect(row?.drifting).toBe(true);
    expect(row?.lastRunError).toBe("dial tcp: timeout");
  });

  it("does not call an unscheduled failure drift — one manual run is not a trend", () => {
    const activity = sourceActivityByID([monitoringRow({ source_id: "src-3", scheduled: false, last_run_status: "failed" })]);
    expect(activity.get("src-3")?.drifting).toBe(false);
  });

  it("marks a configured source with no runs as never-ran rather than failed", () => {
    const activity = sourceActivityByID([monitoringRow({ source_id: "src-4", run_count: 0, completed_run_count: 0, last_run_status: "" })]);
    const row = activity.get("src-4");
    expect(row?.neverRan).toBe(true);
    expect(row?.drifting).toBe(false);
  });

  it("falls back to the last discovery timestamp when no run completion is served", () => {
    const activity = sourceActivityByID([monitoringRow({ source_id: "src-5", last_discovery_at: "2026-07-25T08:00:00Z" })]);
    expect(activity.get("src-5")?.lastRunAt).toBe("2026-07-25T08:00:00Z");
  });

  it("returns an empty map when monitoring is unavailable", () => {
    expect(sourceActivityByID([]).size).toBe(0);
  });
});
