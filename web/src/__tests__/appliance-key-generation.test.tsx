import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { ApplianceKeyGenerationField } from "@/pages/connectors/ApplianceKeyGenerationField";

const { page } = vi.hoisted(() => ({ page: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { agentPage: page } }));

function Editor({ connector, initial }: { connector: string; initial: string }) {
  const [config, setConfig] = useState(initial);
  return (
    <AppQueryProvider>
      <ApplianceKeyGenerationField connector={connector} config={config} onChange={setConfig} required />
      <output data-testid="config">{config}</output>
    </AppQueryProvider>
  );
}

const config = () => JSON.parse(screen.getByTestId("config").textContent ?? "") as Record<string, unknown>;

describe("appliance key generation", () => {
  it("declares the appliance, asks for an enrolled network relay only, and withdraws the declaration", async () => {
    const relayID = "55555555-5555-4555-8555-55555555b001";
    page.mockReset().mockResolvedValue({
      agents: [
        { id: "host-1", name: "Application host", roles: ["host"], status: "active" },
        { id: relayID, name: "DMZ relay", roles: ["network"], status: "active" },
        { id: "retired", name: "Retired relay", roles: ["network"], status: "offboarded", offboarded_at: "2026-09-13T00:00:00Z" },
      ],
    });
    const user = userEvent.setup();
    render(<Editor connector="netscaler" initial='{"endpoint":"https://ns.example.com","username":"trstctl"}' />);
    expect(screen.queryByRole("combobox", { name: "Network relay" })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Key generation" }), "appliance");
    await screen.findByRole("option", { name: /DMZ relay/ });
    expect(screen.queryByRole("option", { name: /Application host|Retired relay/ })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Network relay" }), relayID);
    expect(config()).toEqual({ endpoint: "https://ns.example.com", username: "trstctl", key_generation: "appliance", required_agent_id: relayID });
    await user.selectOptions(screen.getByRole("combobox", { name: "Key generation" }), "control_plane");
    expect(config()).toEqual({ endpoint: "https://ns.example.com", username: "trstctl", required_agent_id: relayID });
    expect(screen.queryByRole("combobox", { name: "Network relay" })).not.toBeInTheDocument();
  });

  it("names what a Palo Alto firewall needs before the server refuses it", async () => {
    page.mockReset().mockResolvedValue({ agents: [] });
    render(<Editor connector="paloalto" initial='{"endpoint":"https://fw.example.com","key_generation":"appliance"}' />);
    expect(await screen.findByText(/ssl_tls_profile and commit_admin/)).toBeInTheDocument();
  });

  it("names why an F5 HA pair keeps control-plane keys", async () => {
    page.mockReset().mockResolvedValue({ agents: [] });
    render(<Editor connector="f5" initial='{"endpoint":"https://a.example.com","peer_endpoint":"https://b.example.com","key_generation":"appliance"}' />);
    expect(await screen.findByText(/HA pair cannot make its key/)).toBeInTheDocument();
  });

  it("names what a Cisco ISE node needs before the server refuses it", async () => {
    page.mockReset().mockResolvedValue({ agents: [] });
    render(<Editor connector="cisco" initial='{"endpoint":"https://ise.example.com","key_generation":"appliance"}' />);
    expect(await screen.findByText(/node_hostname and certificate_roles/)).toBeInTheDocument();
  });
});
