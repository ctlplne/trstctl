import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { AppQueryProvider } from "@/lib/query";
import { TrustOperations } from "@/pages/TrustOperations";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    contextualRiskPriorities: vi.fn(),
    incidentExecutions: vi.fn(),
    notifications: vi.fn(),
    notificationChannels: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    ownershipAttribution: vi.fn(),
    bulkheadStats: vi.fn(),
    auditEvents: vi.fn(),
    connectorDeliveries: vi.fn(),
    agentJobPosture: vi.fn(),
    platformSystem: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.contextualRiskPriorities.mockResolvedValue({ priorities: [] });
  apiMock.incidentExecutions.mockResolvedValue({ items: [] });
  apiMock.notifications.mockResolvedValue({ items: [] });
  apiMock.notificationChannels.mockResolvedValue({ items: [] });
  apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
  apiMock.ownershipAttribution.mockResolvedValue({ summary: {} });
  apiMock.bulkheadStats.mockResolvedValue({ served: true, pools: [] });
  apiMock.auditEvents.mockResolvedValue([]);
  apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
  apiMock.agentJobPosture.mockResolvedValue({ served: true, queues: [], receipts: { rejected: 0 } });
  apiMock.platformSystem.mockResolvedValue({ signer_mode: "isolated", dependencies: [{ name: "signer", ready: true }] });
});

function incidentCapability(available: boolean): CapabilityViewItem {
  const detail = "Automated response is turned off in this deployment.";
  return {
    capability_id: "F31",
    name: "Credential compromise workflow",
    purpose: "Prove that Operations checks exact incident-read readiness.",
    tool: "operations",
    classification: "primary",
    console_route: "/incidents",
    maturity: "partial_workflow",
    release_blocking: true,
    edition: "core",
    runtime_state: available ? "available" : "unavailable",
    authorization_state: available ? "full" : "none",
    dependency_state: "none",
    dependencies: [],
    stages: [{ name: "observe", completion: available ? "complete" : "blocked", ...(available ? {} : { reason: detail }) }],
    actions: {
      allowed: available ? ["listIncidentExecutions"] : [],
      scoped: [],
      denied: [],
      unavailable: available ? [] : [{ operation_id: "listIncidentExecutions", code: "dependency_not_configured", detail }],
    },
  };
}

function incidentRuntime(available: boolean): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks every operation again when it executes.",
    license: { tier: "community", state: "community" },
    operations: [],
    items: [incidentCapability(available)],
  };
}

function renderPage(available: boolean) {
  return render(
    <CapabilityFixtureProvider view={incidentRuntime(available)}>
      <AppQueryProvider>
        <MemoryRouter>
          <TrustOperations />
        </MemoryRouter>
      </AppQueryProvider>
    </CapabilityFixtureProvider>,
  );
}

describe("Operations cockpit capability preflight", () => {
  it("skips unavailable incident evidence while preserving independent operational reads", async () => {
    renderPage(false);

    await waitFor(() => {
      expect(apiMock.contextualRiskPriorities).toHaveBeenCalled();
      expect(apiMock.notifications).toHaveBeenCalled();
      expect(apiMock.notificationChannels).toHaveBeenCalled();
      expect(apiMock.notificationRoutingPolicies).toHaveBeenCalled();
      expect(apiMock.ownershipAttribution).toHaveBeenCalled();
      expect(apiMock.bulkheadStats).toHaveBeenCalled();
      expect(apiMock.auditEvents).toHaveBeenCalled();
      expect(apiMock.connectorDeliveries).toHaveBeenCalled();
      expect(apiMock.agentJobPosture).toHaveBeenCalled();
      expect(apiMock.platformSystem).toHaveBeenCalled();
    });
    expect(apiMock.incidentExecutions).not.toHaveBeenCalled();
    expect((await screen.findAllByText(/incident evidence.*unavailable/i)).length).toBeGreaterThan(0);
  });

  it("restores the incident evidence read when the exact runtime operation is available", async () => {
    renderPage(true);

    await waitFor(() => expect(apiMock.incidentExecutions).toHaveBeenCalledWith({ limit: 100 }));
  });
});
