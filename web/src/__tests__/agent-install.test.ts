import { describe, expect, it } from "vitest";
import { buildAgentInstallPlan } from "@/lib/agentInstall";

describe("agent install command contract", () => {
  it("builds an explicit, runnable loopback evaluation command from the base origin", () => {
    const plan = buildAgentInstallPlan({ origin: "http://127.0.0.1:60280", agentName: "qa relay", roles: ["network"] });

    expect(plan.blockedReason).toBeUndefined();
    expect(plan.command).toContain("--enroll-url http://127.0.0.1:60280");
    expect(plan.command).toContain("--allow-insecure-loopback-enrollment");
    expect(plan.command).toContain("--server localhost:19443");
    expect(plan.command).toContain("--server-name localhost");
    expect(plan.command).toContain("--name 'qa relay'");
    expect(plan.command).toContain("--relay-claim");
    expect(plan.command).not.toContain("/enroll/bootstrap");
    expect(plan.command).not.toContain("<control-plane");
  });

  it("uses pinned HTTPS semantics without the loopback escape hatch", () => {
    const plan = buildAgentInstallPlan({ origin: "https://trstctl.example:8443", agentName: "host-1", roles: ["host"] });

    expect(plan.blockedReason).toBeUndefined();
    expect(plan.command).toContain("--enroll-url https://trstctl.example:8443");
    expect(plan.command).toContain("--server trstctl.example:9443");
    expect(plan.command).toContain("--server-name trstctl.example");
    expect(plan.command).not.toContain("--allow-insecure-loopback-enrollment");
    expect(plan.command).not.toContain("--relay-claim");
  });

  it("refuses to print a token-bearing enrollment command on non-loopback HTTP", () => {
    const plan = buildAgentInstallPlan({ origin: "http://trstctl.example:8080", agentName: "host-1" });

    expect(plan.command).toBe("");
    expect(plan.blockedReason).toMatch(/need HTTPS/i);
  });
});
