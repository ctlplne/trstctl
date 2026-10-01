import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { CapabilityView } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { UsageEvidencePanel } from "@/components/TenantCustodyPanels";

const { usageEvidence } = vi.hoisted(() => ({ usageEvidence: vi.fn() }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, usageEvidence } };
});

function runtime(operations: CapabilityView["operations"]): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks again at execution.",
    license: { tier: "community", state: "community" },
    operations,
    items: [],
  };
}

describe("System health usage evidence preflight", () => {
  beforeEach(() => usageEvidence.mockReset());

  it("explains an unattached provider operation without offering a request that will 404", async () => {
    render(
      <CapabilityFixtureProvider view={runtime([])}>
        <UsageEvidencePanel />
      </CapabilityFixtureProvider>,
    );

    expect(screen.getByText("This running build does not serve usage and invoice evidence. There is no invoice to pull from this panel.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pull evidence" })).not.toBeInTheDocument();
    expect(usageEvidence).not.toHaveBeenCalled();
  });

  it("allows a served and authorized operation to pull the selected period", async () => {
    usageEvidence.mockResolvedValue({ signable: false, reason: "Metering coverage is incomplete.", lines: [], digest: "test-digest" });
    render(
      <CapabilityFixtureProvider view={runtime([{ operation_id: "getUsageEvidence", state: "allowed" }])}>
        <UsageEvidencePanel />
      </CapabilityFixtureProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: "Pull evidence" }));
    await waitFor(() => expect(usageEvidence).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Metering coverage is incomplete.")).toBeInTheDocument();
  });

  it("does not offer a pull action when the served operation denies this role", () => {
    render(
      <CapabilityFixtureProvider view={runtime([{ operation_id: "getUsageEvidence", state: "denied" }])}>
        <UsageEvidencePanel />
      </CapabilityFixtureProvider>,
    );

    expect(screen.getByText("Your role cannot read usage evidence. Ask an administrator for audit read access.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pull evidence" })).not.toBeInTheDocument();
    expect(usageEvidence).not.toHaveBeenCalled();
  });
});
