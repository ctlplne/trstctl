import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn(),
    risk: vi.fn(),
    contextualRiskPriorities: vi.fn(),
    nhiPolicyCompliance: vi.fn(),
    nhiOverPrivilegePosture: vi.fn(),
    nhiStalePosture: vi.fn(),
    nhiStaticPosture: vi.fn(),
    nhiExposurePosture: vi.fn(),
    nhiPostureAutomation: vi.fn(),
    probeNHIExposure: vi.fn(),
    identities: vi.fn(),
    issuanceRequests: vi.fn(),
    owners: vi.fn(),
    profiles: vi.fn(),
    approvalRequests: vi.fn(),
    profileEditApprovals: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: apiMock };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderRisk() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/risk"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function exposureFinding(overrides: Record<string, unknown>) {
  return {
    kind: "api_key",
    source: "discovery",
    owner_status: "owned",
    status: "discovered",
    severity: "high",
    risk_score: 88,
    finding_types: ["internet_exposed"],
    exposure_level: "internet",
    network_surface: "public-ingress",
    public_endpoints: ["https://api.example.com"],
    callback_urls: [],
    transport_security: "tls",
    auth_mode: "",
    recommendation: "Review the exposed deployment metadata.",
    evidence_refs: [],
    ...overrides,
  };
}

// A102: the exposure panel shows each row's latest live probe from a network
// relay and queues a new probe for an operator who may run discovery.
describe("NHI exposure live reachability", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.risk.mockResolvedValue([]);
    for (const panel of [
      apiMock.contextualRiskPriorities,
      apiMock.nhiPolicyCompliance,
      apiMock.nhiOverPrivilegePosture,
      apiMock.nhiStalePosture,
      apiMock.nhiStaticPosture,
      apiMock.nhiPostureAutomation,
    ]) {
      panel.mockResolvedValue({ summary: {}, findings: [], priorities: [], items: [], coverage: [], evidence_refs: [] });
    }
    apiMock.issuanceRequests.mockResolvedValue({ items: [], open: 0, guidance: "" });
    apiMock.profileEditApprovals.mockResolvedValue({ items: [] });
    apiMock.approvalRequests.mockResolvedValue([]);
    apiMock.identities.mockResolvedValue([]);
    apiMock.owners.mockResolvedValue([]);
    apiMock.profiles.mockResolvedValue([]);
    apiMock.nhiExposurePosture.mockResolvedValue({
      capability: "CAP-POST-04",
      generated_at: "2026-10-24T00:00:00Z",
      coverage: ["internet_exposure", "relay_reachability_probes"],
      summary: {
        total_analyzed: 3,
        findings: 2,
        internet_exposed: 2,
        insecure_transport: 0,
        weak_authentication: 0,
        public_callbacks: 0,
        missing_network_policy: 0,
        wildcard_reachability: 0,
        probed: 1,
        live_reachable: 1,
        critical: 0,
        high: 2,
        medium: 0,
        low: 0,
        recommendations: 2,
      },
      findings: [
        exposureFinding({
          inventory_id: "finding/probed-1",
          display_name: "partner-webhook-token",
          reachability: {
            status: "reachable",
            probed_at: "2026-10-24T01:02:03Z",
            endpoints: [{ address: "api.example.com:443", outcome: "tls_certificate", reachable: true, observed_at: "2026-10-24T01:02:03Z" }],
          },
        }),
        exposureFinding({ inventory_id: "finding/unprobed-1", display_name: "billing-export-key", public_endpoints: ["https://billing.example.com"] }),
      ],
    });
    apiMock.probeNHIExposure.mockResolvedValue({
      run_id: "33333333-3333-3333-3333-333333333333",
      vantage: "relay",
      endpoints: [
        { inventory_id: "finding/probed-1", endpoint: "https://api.example.com", address: "api.example.com:443", server_name: "api.example.com" },
        { inventory_id: "finding/unprobed-1", endpoint: "https://billing.example.com", address: "billing.example.com:443", server_name: "billing.example.com" },
      ],
      omitted: 0,
      requested_at: "2026-10-24T02:00:00Z",
    });
  });

  it("shows each row's latest probe and queues a relay probe", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "ops-1", tenant_id: "t1", email: "ops@example.test" });
    const user = userEvent.setup();
    renderRisk();

    expect(await screen.findByText("partner-webhook-token")).toBeInTheDocument();
    expect(screen.getByText("Live reachability: 1 probed from a relay, 1 answered.")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Exposed NHI deployment recommendations" });
    expect(within(table).getByRole("columnheader", { name: "Live reachability" })).toBeInTheDocument();
    const probed = within(table).getByText("partner-webhook-token").closest("tr") as HTMLElement;
    expect(within(probed).getByText(/^Answered from a relay ·/)).toBeInTheDocument();
    const unprobed = within(table).getByText("billing-export-key").closest("tr") as HTMLElement;
    expect(within(unprobed).getByText("Not probed yet")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Probe from a relay" }));
    await waitFor(() => expect(apiMock.probeNHIExposure).toHaveBeenCalledWith({ inventory_ids: [] }));
    expect(
      await screen.findByText("Probe queued for 2 endpoints (run 33333333-3333-3333-3333-333333333333). Results appear here after a network relay reports."),
    ).toBeInTheDocument();
  });

  it("offers no probe to an operator who cannot run discovery", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["nhi:read", "risk:read"], subject: "viewer-1", tenant_id: "t1", email: "viewer@example.test" });
    renderRisk();

    expect(await screen.findByText("partner-webhook-token")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Probe from a relay" })).not.toBeInTheDocument();
  });
});
