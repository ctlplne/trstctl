import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { DestinationHostField } from "@/pages/connectors/DestinationHostField";

const { page } = vi.hoisted(() => ({ page: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { agentPage: page } }));

function Editor() {
  const [config, setConfig] = useState('{"cert_path":"/app/server.crt","executor":"agent"}');
  return (
    <AppQueryProvider>
      <DestinationHostField config={config} onChange={setConfig} required />
      <output data-testid="config">{config}</output>
    </AppQueryProvider>
  );
}

describe("destination host assignment", () => {
  it("loads later fleet pages, excludes unavailable grants, and preserves exact configuration", async () => {
    const hostID = "44444444-4444-4444-8444-44444444a001";
    page
      .mockReset()
      .mockResolvedValueOnce({
        agents: [
          { id: "network", name: "Network relay", roles: ["network"], status: "active" },
          { id: "retired", name: "Retired host", roles: ["host"], status: "offboarded", offboarded_at: "2026-09-13T00:00:00Z" },
        ],
        next_cursor: "second-page",
      })
      .mockResolvedValueOnce({ agents: [{ id: hostID, name: "Application host", roles: ["host"], status: "offline" }] });
    const user = userEvent.setup();
    render(<Editor />);
    await user.click(await screen.findByRole("button", { name: "Load more agents" }));
    await screen.findByRole("option", { name: /Application host/ });
    expect(screen.queryByRole("option", { name: /Network relay|Retired host/ })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Host agent" }), hostID);
    expect(JSON.parse(screen.getByTestId("config").textContent ?? "")).toEqual({ cert_path: "/app/server.crt", executor: "agent", required_agent_id: hostID });
    expect(page).toHaveBeenLastCalledWith({ limit: 100, cursor: "second-page" });
    expect(screen.getByText(/another host cannot take over/)).toBeInTheDocument();
  });
});
