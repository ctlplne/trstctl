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
    validateNHIAttackPaths: vi.fn(),
    discoverySources: vi.fn(),
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
    apiMock.discoverySources.mockResolvedValue({ items: [] });
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

  // A167: the row shows the cloud account's verdict and the resource that
  // decided it, and an operator with a cloud_network_path source can ask for a
  // validation; without one the panel says where to add it.
  it("shows the cloud path verdict and validates against a cloud network path source", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "ops-1", tenant_id: "t1", email: "ops@example.test" });
    const posture = await apiMock.nhiExposurePosture();
    posture.summary.path_validated = 1;
    posture.summary.path_open = 0;
    posture.findings[1].attack_path = {
      status: "blocked",
      checked_at: "2026-10-24T03:00:00Z",
      endpoints: [
        {
          address: "203.0.113.11:443",
          status: "blocked",
          blocked_by: "security_group",
          resource: "sg-admin",
          reason: "no security group admits tcp/443",
          checked_at: "2026-10-24T03:00:00Z",
        },
      ],
    };
    apiMock.nhiExposurePosture.mockResolvedValue(posture);
    apiMock.discoverySources.mockResolvedValue({
      items: [
        { id: "src-ec2", kind: "cloud_network_path", name: "aws-ec2-east" },
        { id: "src-lan", kind: "network", name: "lan" },
      ],
    });
    apiMock.validateNHIAttackPaths.mockResolvedValue({
      run_id: "44444444-4444-4444-4444-444444444444",
      source_id: "src-ec2",
      endpoints: [{ inventory_id: "finding/unprobed-1", endpoint: "https://billing.example.com", address: "billing.example.com:443" }],
      omitted: 0,
      requested_at: "2026-10-24T03:00:00Z",
    });
    const user = userEvent.setup();
    renderRisk();

    expect(await screen.findByText("Cloud paths validated for 1 records; 0 open to the internet.")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Exposed NHI deployment recommendations" });
    expect(within(table).getByRole("columnheader", { name: "Cloud path" })).toBeInTheDocument();
    const blocked = within(table).getByText("billing-export-key").closest("tr") as HTMLElement;
    expect(within(blocked).getByText("Blocked at sg-admin (security group)")).toBeInTheDocument();
    expect(within(blocked).getByText("no security group admits tcp/443")).toBeInTheDocument();
    const unvalidated = within(table).getByText("partner-webhook-token").closest("tr") as HTMLElement;
    expect(within(unvalidated).getByText("Not validated")).toBeInTheDocument();

    const picker = await screen.findByRole("combobox", { name: "Cloud account to validate against" });
    expect(
      within(picker)
        .getAllByRole("option")
        .map((option) => option.textContent),
    ).toEqual(["aws-ec2-east"]);
    await user.click(screen.getByRole("button", { name: "Validate paths in the cloud" }));
    await waitFor(() => expect(apiMock.validateNHIAttackPaths).toHaveBeenCalledWith({ source_id: "src-ec2", inventory_ids: [] }));
    expect(await screen.findByText(/^Cloud path validation queued for 1 endpoints \(run 44444444-4444-4444-4444-444444444444\)/)).toBeInTheDocument();
  });

  // A167-L1: a Google Cloud project's verdicts name the firewall rule that
  // admits the internet, and a blocked row says what about the network decided
  // (its implied ingress deny, or no route to the default internet gateway),
  // never presenting the network as a rule.
  it("names a Google Cloud firewall rule and the network that blocked a path", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "ops-1", tenant_id: "t1", email: "ops@example.test" });
    const posture = await apiMock.nhiExposurePosture();
    const verdict = (address: string, fields: Record<string, unknown>) => ({
      status: fields.status,
      checked_at: "2026-11-11T03:00:00Z",
      endpoints: [{ address, checked_at: "2026-11-11T03:00:00Z", ...fields }],
    });
    posture.findings = [
      exposureFinding({
        inventory_id: "finding/gcp-web",
        display_name: "gcp-web-token",
        attack_path: verdict("203.0.113.30:443", {
          status: "open",
          resource: "allow-https",
          rule: "priority 1000",
          path: ["web-1", "allow-https", "default-route-internet", "default-internet-gateway"],
          reason: "firewall rule allow-https admits tcp/443 from 0.0.0.0/0",
        }),
      }),
      exposureFinding({
        inventory_id: "finding/gcp-db",
        display_name: "gcp-db-token",
        attack_path: verdict("203.0.113.31:443", {
          status: "blocked",
          blocked_by: "firewall",
          resource: "prod",
          rule: "implied deny ingress (priority 65535)",
          reason: "no firewall rule on network prod admits tcp/443 from 0.0.0.0/0 to db-1",
        }),
      }),
      exposureFinding({
        inventory_id: "finding/gcp-lab",
        display_name: "gcp-lab-token",
        attack_path: verdict("203.0.113.32:443", {
          status: "blocked",
          blocked_by: "route",
          resource: "isolated",
          reason: "network isolated has no route from 0.0.0.0/0 that applies to lab-1",
        }),
      }),
    ];
    apiMock.nhiExposurePosture.mockResolvedValue(posture);
    renderRisk();

    const table = await screen.findByRole("table", { name: "Exposed NHI deployment recommendations" });
    const open = (await within(table).findByText("gcp-web-token")).closest("tr") as HTMLElement;
    expect(within(open).getByText("Open through allow-https")).toBeInTheDocument();
    expect(within(open).getByText("firewall rule allow-https admits tcp/443 from 0.0.0.0/0")).toBeInTheDocument();
    const firewall = within(table).getByText("gcp-db-token").closest("tr") as HTMLElement;
    expect(within(firewall).getByText("Blocked at prod (firewall)")).toBeInTheDocument();
    expect(within(firewall).getByText("no firewall rule on network prod admits tcp/443 from 0.0.0.0/0 to db-1")).toBeInTheDocument();
    expect(within(table).queryByText(/firewall rule prod/)).not.toBeInTheDocument();
    const route = within(table).getByText("gcp-lab-token").closest("tr") as HTMLElement;
    expect(within(route).getByText("Blocked at isolated (routing)")).toBeInTheDocument();
    expect(within(route).getByText("network isolated has no route from 0.0.0.0/0 that applies to lab-1")).toBeInTheDocument();
  });

  it("says where to add a cloud network path source when none exists", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "ops-1", tenant_id: "t1", email: "ops@example.test" });
    renderRisk();

    expect(await screen.findByText("To validate cloud paths, add a Cloud network paths source under Discover → Sources.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Validate paths in the cloud" })).not.toBeInTheDocument();
  });

  it("offers no probe to an operator who cannot run discovery", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["nhi:read", "risk:read"], subject: "viewer-1", tenant_id: "t1", email: "viewer@example.test" });
    renderRisk();

    expect(await screen.findByText("partner-webhook-token")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Probe from a relay" })).not.toBeInTheDocument();
  });
});
