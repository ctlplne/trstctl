import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ADCSDatabasePanel } from "@/components/posture/ADCSDatabasePanel";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { adcsDatabases: vi.fn(), collectADCSDatabase: vi.fn(), agents: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const relay = "6f1c2a9e-0b7d-4e35-9a41-2c8d7e3f5b10";

const list = {
  guidance: "",
  items: [
    {
      ca_config: "ca01.corp.example\\CORP-CA",
      issued: 2,
      pending: 1,
      revoked: 1,
      denied: 0,
      failed: 0,
      unknown: 0,
      unparsed: 0,
      total: 4,
      rows_read: 5,
      rows_rejected: 1,
      source: `relay:${relay}`,
      ingested_at: "2026-10-31T18:00:00Z",
    },
  ],
  collections: [
    {
      collection_id: "0b6d6a4e-6f0e-5a8c-9a3e-8d2f1c7b9e01",
      ca_config: "ca02.corp.example\\EDGE-CA",
      relay_agent_id: relay,
      status: "failed" as const,
      attempts: 1,
      last_error: "certutil could not read the CA database from this relay",
      requested_at: "2026-10-31T18:05:00Z",
    },
  ],
};

describe("A162 relay CA database reads", () => {
  beforeEach(() => {
    apiMock.adcsDatabases.mockReset().mockResolvedValue(list);
    apiMock.collectADCSDatabase.mockReset();
    apiMock.agents.mockReset().mockResolvedValue([
      { id: relay, name: "dc-relay-01", status: "active", roles: ["network"] },
      { id: "3a9e7c1d-5b2f-4d68-8e0a-1f4c6b2d9e73", name: "web-host-07", status: "active", roles: ["host"] },
    ]);
  });

  it("queues a read on the chosen network relay and shows a failed read's reason", async () => {
    apiMock.collectADCSDatabase.mockResolvedValue({
      collection_id: "1c2d",
      ca_config: "ca01.corp.example\\CORP-CA",
      relay_agent_id: relay,
      status: "queued",
      attempts: 0,
    });
    render(<ADCSDatabasePanel />);
    const reason = await screen.findByText("certutil could not read the CA database from this relay");
    const read = reason.closest("tr");
    expect(read).not.toBeNull();
    expect(within(read as HTMLElement).getByText("Failed")).toBeInTheDocument();
    expect(within(read as HTMLElement).getByText("ca02.corp.example\\EDGE-CA")).toBeInTheDocument();
    await screen.findByRole("option", { name: "dc-relay-01" });
    expect(screen.queryByRole("option", { name: "web-host-07" })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("CA (HOST\\CA-Name)"), { target: { value: "ca01.corp.example\\CORP-CA" } });
    fireEvent.change(screen.getByLabelText("Domain-joined relay"), { target: { value: relay } });
    fireEvent.click(screen.getByRole("button", { name: "Read with certutil" }));
    await waitFor(() => expect(apiMock.collectADCSDatabase).toHaveBeenCalledWith({ ca_config: "ca01.corp.example\\CORP-CA", relay_agent_id: relay }));
    expect(await screen.findByRole("status")).toHaveTextContent("A read of ca01.corp.example\\CORP-CA is queued for the relay.");
    expect(apiMock.adcsDatabases).toHaveBeenCalledTimes(2);
  });

  it("shows why a relay cannot take the read", async () => {
    apiMock.collectADCSDatabase.mockRejectedValue(
      new ApiError(
        409,
        JSON.stringify({
          title: "Conflict",
          status: 409,
          detail:
            "Run the selected relay on a domain-joined Windows host with --relay-claim and certutil (--adcs-certutil), and restore its authenticated executor census, before reading a CA database.",
        }),
      ),
    );
    render(<ADCSDatabasePanel />);
    await screen.findByRole("option", { name: "dc-relay-01" });
    fireEvent.change(screen.getByLabelText("CA (HOST\\CA-Name)"), { target: { value: "ca01.corp.example\\CORP-CA" } });
    fireEvent.change(screen.getByLabelText("Domain-joined relay"), { target: { value: relay } });
    fireEvent.click(screen.getByRole("button", { name: "Read with certutil" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/domain-joined Windows host with --relay-claim and certutil/);
  });
});
