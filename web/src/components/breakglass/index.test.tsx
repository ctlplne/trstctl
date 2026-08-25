import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { BreakGlassReconcile } from "@/components/breakglass";
import type { CapabilityView } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";

const { breakglassIssue, breakglassReconcile } = vi.hoisted(() => ({
  breakglassIssue: vi.fn(),
  breakglassReconcile: vi.fn(),
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, breakglassIssue, breakglassReconcile } };
});

const unavailableDetail = "This operation is not mounted because its runtime dependency is not configured.";
const unavailableRuntime: CapabilityView = {
  schema_version: 2,
  contract_schema_version: 3,
  enforcement_note: "The server checks every operation again when it executes.",
  license: { tier: "community", state: "community" },
  operations: [],
  items: [
    {
      capability_id: "F34",
      name: "Break-glass procedures",
      purpose: "Issue and reconcile short-lived emergency credentials.",
      tool: "operations",
      classification: "primary",
      console_route: "/incidents",
      maturity: "partial_workflow",
      release_blocking: true,
      edition: "core",
      runtime_state: "partially_available",
      authorization_state: "partial",
      dependency_state: "documented_not_runtime_verified",
      dependencies: [],
      stages: [{ name: "execute", completion: "blocked", reason: unavailableDetail }],
      actions: {
        allowed: [],
        scoped: [],
        denied: [],
        unavailable: [
          { operation_id: "issueBreakglass", code: "dependency_not_configured", detail: unavailableDetail },
          { operation_id: "reconcileBreakglass", code: "dependency_not_configured", detail: unavailableDetail },
        ],
      },
    },
  ],
};

describe("break-glass runtime truth", () => {
  it("keeps valid-looking emergency requests disabled when the exact operations are unavailable", () => {
    render(
      <CapabilityFixtureProvider view={unavailableRuntime}>
        <BreakGlassReconcile />
      </CapabilityFixtureProvider>,
    );

    fireEvent.change(screen.getByLabelText("Online issue request (JSON)"), { target: { value: '{"request_id":"bg-1"}' } });
    fireEvent.change(screen.getByLabelText("Offline-issued bundles (JSON)"), { target: { value: "[]" } });
    expect(screen.getByRole("button", { name: "Issue break-glass certificate" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reconcile break-glass bundles" })).toBeDisabled();
    expect(screen.getAllByText(unavailableDetail)).toHaveLength(2);
    expect(breakglassIssue).not.toHaveBeenCalled();
    expect(breakglassReconcile).not.toHaveBeenCalled();
  });
});
