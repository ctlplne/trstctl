import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Agents } from "@/pages/Agents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    agents: vi.fn(),
    createEnrollmentToken: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAgents() {
  return render(
    <MemoryRouter>
      <Agents />
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
    });
    apiMock.agents.mockReset().mockResolvedValue([
      {
        id: "ag-1",
        name: "edge-01",
        status: "online",
        version: "0.4.0",
        last_seen_at: "2999-01-01T00:00:00Z",
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

  it("renders agents with status chips and stale-heartbeat warnings", async () => {
    renderAgents();

    expect(await screen.findByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(apiMock.agents).toHaveBeenCalledTimes(1);
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

    expect(await screen.findByText("No agents enrolled yet")).toBeInTheDocument();
    expect(screen.getByText(/mint a one-time enrollment token/i)).toBeInTheDocument();
  });

  it("mints a one-time enrollment token without storing it in browser storage", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    renderAgents();
    await screen.findByText("branch-02");

    fireEvent.click(screen.getByRole("button", { name: /mint enrollment token/i }));

    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("BOOT-TOKEN-XYZ")).toBeInTheDocument();
    expect(screen.getByText(/shown once/i)).toBeInTheDocument();
    expect(screen.getByText(/trstctl-agent --enroll-url/i)).toHaveTextContent("/enroll/bootstrap");
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("opens an agent detail panel with fields and honest unavailable telemetry", async () => {
    renderAgents();
    await screen.findByText("branch-02");

    const row = screen.getByRole("row", { name: /edge-01/i });
    fireEvent.click(within(row).getByRole("button", { name: /view details/i }));

    expect(screen.getByRole("heading", { name: "edge-01" })).toBeInTheDocument();
    expect(screen.getByText("ag-1")).toBeInTheDocument();
    expect(screen.getAllByText("0.4.0").length).toBeGreaterThan(0);
    expect(screen.getByText("Agent telemetry is limited for now")).toBeInTheDocument();
    expect(screen.getByText(/Discovery scanning, drift detection, and agent-driven certificate renewal all run in the agent itself/i)).toBeInTheDocument();
    expect(screen.getByText(/console views for capabilities, last scan, drift summary, and renewal state aren't surfaced here yet/i)).toBeInTheDocument();
  });
});
