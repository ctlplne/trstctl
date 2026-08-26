import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { Agents } from "@/pages/Agents";
import { ToastProvider } from "@/components/ToastProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    agents: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agentUpgradeCampaign: vi.fn(),
    agentJobPosture: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAgents() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <Agents />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("agent fleet surface", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
    apiMock.createEnrollmentToken.mockReset().mockResolvedValue({
      token: "BOOT-TOKEN-XYZ",
      enroll_path: "/enroll/bootstrap",
      roles: ["host"],
    });
    apiMock.agentUpgradeCampaign.mockReset().mockResolvedValue({
      active: false,
      rings: {},
      versions: { "0.4.0": 1, "0.3.8": 1 },
      guidance: "No rollout is active.",
    });
    apiMock.agentJobPosture.mockReset().mockResolvedValue({
      served: true,
      claimable_kinds: ["endpoint.renew"],
      generated_at: "2026-08-21T10:00:00Z",
      queues: [{ kind: "endpoint.renew", enabled: true, pending: 2, claimed: 1 }],
      redemptions: { total: 3, live: 1 },
      receipts: { verified: 8, rejected: 0 },
    });
    apiMock.agents.mockReset().mockResolvedValue([
      {
        id: "ag-1",
        name: "edge-01",
        status: "online",
        version: "0.4.0",
        last_seen_at: "2999-01-01T00:00:00Z",
        roles: ["host"],
        role_source: "certificate",
        workload_api: {
          state: "serving",
          detail: "Serving the local Workload API socket.",
          svids_issued: 4,
          reported_at: "2999-01-01T00:00:00Z",
        },
        enrollment_proxy: {
          state: "serving",
          detail: "Forwarding enrollment requests to healthy upstreams.",
          healthy_upstreams: 2,
          unhealthy_upstreams: 0,
          unknown_upstreams: 0,
          upstream_failures: 0,
          forwarded_requests: 12,
          refused_requests: 0,
          reported_at: "2999-01-01T00:00:00Z",
        },
        inventory_report_path: "agent.mtls.ReportInventory",
        discovery_capabilities: [
          {
            source_kind: "filesystem",
            label: "Filesystem certificates",
            reported_over: "agent.mtls.ReportInventory",
            metadata_only: true,
            private_key_bytes: false,
          },
          { source_kind: "trust-store", label: "Trust stores", reported_over: "agent.mtls.ReportInventory", metadata_only: true, private_key_bytes: false },
          {
            source_kind: "private-key",
            label: "Private-key material",
            reported_over: "agent.mtls.ReportInventory",
            metadata_only: true,
            private_key_bytes: false,
          },
        ],
      },
      {
        id: "ag-2",
        name: "branch-02",
        status: "degraded",
        version: "0.3.8",
        last_seen_at: "2000-01-01T00:00:00Z",
      },
      {
        id: "ag-3",
        name: "lab-03",
        status: "offline",
      },
    ]);
  });

  it("opens with one fleet answer, one Add agent action, and closed expert disclosures", async () => {
    apiMock.agents.mockResolvedValueOnce([]);
    renderAgents();

    expect(await screen.findByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(screen.getByText("Which in-network workers are online, trusted, and current.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "No agents are enrolled" })).toBeInTheDocument();
    expect(screen.getByText(/add one before trstctl can deploy or rotate credentials inside your network/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button").map((button) => button.textContent?.trim())).toEqual(["Add agent"]);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    expect(screen.queryByText("Host")).not.toBeInTheDocument();
    expect(screen.getByText("Fleet status and safe actions").closest("details")).not.toHaveAttribute("open");
    expect(screen.getByText("Enrollment and trust evidence").closest("details")).not.toHaveAttribute("open");
    expect(screen.getByText("Versions, queues, and diagnostics").closest("details")).not.toHaveAttribute("open");

    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));
    expect(screen.getByRole("dialog", { name: "Add agent" })).toBeInTheDocument();
    expect(screen.getByLabelText(/agent identity/i)).toBeInTheDocument();
    expect(screen.getByText("Host")).toBeInTheDocument();
  });

  it("answers online, certificate trust, and current evidence from served fleet fields", async () => {
    renderAgents();

    expect(await screen.findByRole("heading", { name: "1 of 3 active agents is online with a fresh heartbeat" })).toBeInTheDocument();
    expect(screen.getByText("1 of 3 active agents reports certificate-bound role evidence.")).toBeInTheDocument();
    expect(screen.getByText("1 of 3 active agents reports both a fresh heartbeat and version.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();

    fireEvent.click(screen.getByText("Fleet status and safe actions"));
    expect(await screen.findByRole("table", { name: "Registered in-network agents" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh fleet" })).toBeInTheDocument();
  });

  it("loads version and queue evidence only when its disclosure opens", async () => {
    renderAgents();
    await screen.findByText("Fleet status and safe actions");

    expect(apiMock.agentUpgradeCampaign).not.toHaveBeenCalled();
    expect(apiMock.agentJobPosture).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText("Versions, queues, and diagnostics"));

    await waitFor(() => expect(apiMock.agentUpgradeCampaign).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.agentJobPosture).toHaveBeenCalledTimes(1));
    expect((await screen.findAllByText("endpoint.renew")).length).toBeGreaterThan(0);
    expect(screen.getByText(/2 pending/i)).toBeInTheDocument();
    expect(screen.getAllByText(/No rollout is active/i).length).toBeGreaterThan(0);
  });

  it("keeps the calm default and Add agent dialog free of automated accessibility violations", async () => {
    apiMock.agents.mockResolvedValueOnce([]);
    const view = renderAgents();
    await screen.findByRole("heading", { name: "No agents are enrolled" });

    expect(await axe(view.container)).toHaveNoViolations();

    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));
    await screen.findByRole("dialog", { name: "Add agent" });
    expect(await axe(document.body)).toHaveNoViolations();
  });

  it("keeps all three expert evidence disclosures free of automated accessibility violations", async () => {
    const view = renderAgents();
    await screen.findByRole("heading", { name: /1 of 3 active agents/i });

    fireEvent.click(screen.getByText("Fleet status and safe actions"));
    fireEvent.click(screen.getByText("Enrollment and trust evidence"));
    fireEvent.click(screen.getByText("Versions, queues, and diagnostics"));
    await screen.findByRole("heading", { name: "Agent work queues" });

    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("renders agents with status chips and stale-heartbeat warnings", async () => {
    renderAgents();

    expect(await screen.findByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(apiMock.agents).toHaveBeenCalledTimes(1);
    await screen.findByRole("heading", { name: /1 of 3 active agents/i });
    fireEvent.click(screen.getByText("Fleet status and safe actions"));
    expect((await screen.findAllByText("edge-01")).length).toBeGreaterThan(0);
    expect(await screen.findByText("branch-02")).toBeInTheDocument();
    expect(await screen.findByText("lab-03")).toBeInTheDocument();
    expect(screen.getAllByText("online").length).toBeGreaterThan(0);
    expect(screen.getByText("degraded")).toBeInTheDocument();
    expect(screen.getByText("offline")).toBeInTheDocument();
    expect(screen.getByText(/stale heartbeat/i)).toBeInTheDocument();
  });

  it("shows empty-fleet guidance when no agents are enrolled", async () => {
    apiMock.agents.mockResolvedValueOnce([]);

    renderAgents();

    expect(await screen.findByRole("heading", { name: "No agents are enrolled" })).toBeInTheDocument();
    expect(screen.getByText(/add one before trstctl can deploy or rotate credentials/i)).toBeInTheDocument();
  });

  it("mints a one-time enrollment token without storing it in browser storage", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    renderAgents();
    await screen.findByRole("heading", { name: /1 of 3 active agents/i });
    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));

    fireEvent.change(screen.getByLabelText(/agent identity/i), { target: { value: "edge-01" } });
    fireEvent.click(screen.getByRole("button", { name: /mint enrollment token/i }));

    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledTimes(1));
    // A2: the mint carries the capability grant the operator selected. Host is
    // the default because it is what an agent with no grant already is — the
    // form cannot offer "no capability", because no such agent exists.
    expect(apiMock.createEnrollmentToken).toHaveBeenCalledWith({ allowed_identity: "edge-01", roles: ["host"] });
    expect(await screen.findByText("BOOT-TOKEN-XYZ")).toBeInTheDocument();
    expect(screen.getByText(/shown once/i)).toBeInTheDocument();
    const command = screen.getByText(/trstctl-agent --enroll-url/i).textContent ?? "";
    expect(command).toContain("--enroll-url http://localhost");
    expect(command).toContain("--allow-insecure-loopback-enrollment");
    expect(command).toContain("--server localhost:19443");
    expect(command).toContain("--server-name localhost");
    expect(command).toContain("--name edge-01");
    expect(command).not.toContain("/enroll/bootstrap");
    expect(command).not.toContain("<control-plane");
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("turns a network-role token into a relay-capable command", async () => {
    apiMock.createEnrollmentToken.mockResolvedValueOnce({ token: "BOOT-TOKEN-XYZ", enroll_path: "/enroll/bootstrap", roles: ["network"] });
    renderAgents();
    await screen.findByRole("heading", { name: /1 of 3 active agents/i });
    fireEvent.click(screen.getByRole("button", { name: "Add agent" }));
    fireEvent.click(screen.getByLabelText(/network relay/i));
    fireEvent.click(screen.getByRole("button", { name: /mint enrollment token/i }));

    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledWith({ roles: ["host", "network"] }));
    expect(screen.getByText(/trstctl-agent --enroll-url/i)).toHaveTextContent("--relay-claim");
  });

  it("opens an agent detail panel with served endpoint discovery coverage", async () => {
    renderAgents();
    await screen.findByRole("heading", { name: /1 of 3 active agents/i });
    fireEvent.click(screen.getByText("Fleet status and safe actions"));
    await screen.findByText("branch-02");

    const row = screen.getByRole("row", { name: /edge-01/i });
    fireEvent.click(within(row).getByRole("button", { name: /view details/i }));

    expect(screen.getByRole("heading", { name: "edge-01" })).toBeInTheDocument();
    expect(screen.getByText("ag-1")).toBeInTheDocument();
    expect(screen.getAllByText("0.4.0").length).toBeGreaterThan(0);
    expect(screen.getByText("Endpoint discovery")).toBeInTheDocument();
    expect(screen.getByText("agent.mtls.ReportInventory")).toBeInTheDocument();
    expect(screen.getByText("filesystem")).toBeInTheDocument();
    expect(screen.getByText("trust-store")).toBeInTheDocument();
    expect(screen.getByText("private-key")).toBeInTheDocument();
    expect(screen.getAllByText(/metadata-only/i).length).toBeGreaterThan(0);
    expect(screen.queryByText("Agent telemetry is limited for now")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Workload and enrollment services" })).toBeInTheDocument();
    expect(screen.getByText("Serving the local Workload API socket.")).toBeInTheDocument();
    expect(screen.getByText("Forwarding enrollment requests to healthy upstreams.")).toBeInTheDocument();
    expect(screen.getByText(/2 healthy, 0 unhealthy, 0 unknown/i)).toBeInTheDocument();
  });
});
