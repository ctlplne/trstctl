import { describe, expect, it } from "vitest";
import { rotationHealth } from "@/pages/secrets/SecretsPageParts";
import type { SecretRotationSchedule } from "@/lib/api";

const now = new Date("2026-07-26T12:00:00Z");
const hour = 3600;

function schedule(overrides: Partial<SecretRotationSchedule> = {}): SecretRotationSchedule {
  return {
    id: "sched-1",
    name: "db password",
    key: "apps/api/password",
    interval_seconds: 24 * hour,
    enabled: true,
    created_at: "2026-06-01T00:00:00Z",
    next_run_at: "2026-07-27T00:00:00Z",
    last_run_at: "2026-07-26T00:00:00Z",
    last_run_status: "completed",
    ...overrides,
  } as SecretRotationSchedule;
}

// S-C19: these flags are the difference between "here is a timestamp" and
// "this secret has not rotated", so each condition is pinned.
describe("secret rotation health", () => {
  it("reports a healthy schedule as neither overdue nor stale", () => {
    const health = rotationHealth(schedule(), now);
    expect(health).toEqual({ overdue: false, overdueDays: 0, stale: false, neverRun: false, lastRunFailed: false });
  });

  it("flags an enabled schedule whose next run is in the past, with whole days", () => {
    const health = rotationHealth(schedule({ next_run_at: "2026-07-23T12:00:00Z" }), now);
    expect(health.overdue).toBe(true);
    expect(health.overdueDays).toBe(3);
  });

  it("never flags a disabled schedule — that is an operator decision, not a finding", () => {
    const health = rotationHealth(schedule({ enabled: false, next_run_at: "2026-01-01T00:00:00Z", last_run_at: undefined }), now);
    expect(health.overdue).toBe(false);
    expect(health.stale).toBe(false);
    expect(health.neverRun).toBe(true);
  });

  it("treats two missed intervals as stale, but tolerates one", () => {
    // interval 24h: 36h of silence is one missed run, 60h is two.
    expect(rotationHealth(schedule({ last_run_at: "2026-07-25T00:00:00Z" }), now).stale).toBe(false);
    expect(rotationHealth(schedule({ last_run_at: "2026-07-24T00:00:00Z" }), now).stale).toBe(true);
  });

  it("flags a schedule that has never produced a run", () => {
    const health = rotationHealth(schedule({ last_run_at: undefined, last_run_status: "" }), now);
    expect(health.neverRun).toBe(true);
  });

  it("surfaces a failed last run, which is usually why the next one did not happen", () => {
    const health = rotationHealth(schedule({ last_run_status: "failed" }), now);
    expect(health.lastRunFailed).toBe(true);
  });

  it.each(["rolled_back", "delivery_failed", "rollback_failed", "retire_pending"] as const)("surfaces explicit incomplete outcome %s", (lastRunStatus) => {
    expect(rotationHealth(schedule({ last_run_status: lastRunStatus }), now).lastRunFailed).toBe(true);
  });

  it("falls back to the overdue signal when the last run timestamp is unusable", () => {
    const health = rotationHealth(schedule({ last_run_at: "not-a-date", next_run_at: "2026-07-20T00:00:00Z" }), now);
    expect(health.overdue).toBe(true);
    expect(health.stale).toBe(true);
  });
});
