import { describe, expect, it } from "vitest";
import { rolloutSteps } from "@/pages/SSHTrust";

// S-C16: the stepper draws the rollout state machine, so what counts as done,
// current, and terminal is pinned rather than inferred from a badge color.
describe("SSH trust rollout stepper", () => {
  it("marks earlier steps done and the served status current on the happy path", () => {
    expect(rolloutSteps("planned")).toEqual([
      { status: "planned", state: "current" },
      { status: "validating", state: "upcoming" },
      { status: "health_passed", state: "upcoming" },
    ]);
    expect(rolloutSteps("validating")).toEqual([
      { status: "planned", state: "done" },
      { status: "validating", state: "current" },
      { status: "health_passed", state: "upcoming" },
    ]);
  });

  it("shows a completed rollout with the final step current, not upcoming", () => {
    const steps = rolloutSteps("health_passed");
    expect(steps.map((step) => step.state)).toEqual(["done", "done", "current"]);
  });

  it("replaces the remaining path with the terminal branch on rollback", () => {
    const steps = rolloutSteps("rolled_back");
    expect(steps).toEqual([
      { status: "planned", state: "done" },
      { status: "validating", state: "done" },
      { status: "rolled_back", state: "terminal" },
    ]);
    // health_passed must NOT appear — the rollout never reached it.
    expect(steps.some((step) => step.status === "health_passed")).toBe(false);
  });

  it("treats failure as the same terminal branch", () => {
    const steps = rolloutSteps("failed");
    expect(steps[2]).toEqual({ status: "failed", state: "terminal" });
  });
});
