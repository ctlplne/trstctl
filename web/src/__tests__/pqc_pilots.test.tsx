import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { PQCPilots } from "@/pages/posture/PQCPilots";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    pqcPilots: vi.fn(),
    pqcPilot: vi.fn(),
    startPQCPilot: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const fingerprint = "a".repeat(64);
const halted = {
  id: "55555555-5555-4555-8555-555555555555",
  tenant_id: "11111111-1111-1111-1111-111111111111",
  name: "Payments PQ pilot",
  authority_id: "pq-issuing-ca",
  status: "halted" as const,
  wave_count: 2,
  current_wave: 1,
  halted_at_wave: "canary",
  verdict_summary: "HALT: 1 of 2 targeted clients REFUSED the PQ leaf.",
  created_at: "2026-10-22T00:00:00Z",
  updated_at: "2026-10-22T00:01:00Z",
  signed_report: { key_id: "pqc-readiness-report", algorithm: "ECDSA-P256", report: { verdict: { halt: true } }, signature: "c2ln" },
  waves: [
    {
      index: 1,
      name: "canary",
      status: "assessed" as const,
      targets: [
        { target_id: "good-1", address: "127.0.0.1:4431", fingerprint },
        { target_id: "refuses-1", address: "127.0.0.1:4432", fingerprint },
      ],
      results: [
        {
          target_id: "good-1",
          outcome: "negotiated" as const,
          handshake_ms: 3,
          chain_bytes: 408,
          detail: "the client negotiated the post-quantum leaf",
          observed_at: "2026-10-22T00:00:30Z",
        },
        {
          target_id: "refuses-1",
          outcome: "rejected" as const,
          handshake_ms: 0,
          chain_bytes: 0,
          detail: "the client refused the handshake: tlsprobe: handshake 127.0.0.1:4432: EOF",
          observed_at: "2026-10-22T00:00:31Z",
        },
      ],
      verdict: {
        ready: false,
        halt: true,
        summary: "HALT: 1 of 2 targeted clients REFUSED the PQ leaf.",
        negotiated: 1,
        rejected: 1,
        unreachable: 0,
        not_attempted: 0,
      },
    },
    { index: 2, name: "broad", status: "skipped" as const, targets: [{ target_id: "never", address: "127.0.0.1:4433", fingerprint }] },
  ],
};

describe("PQCPilots", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.pqcPilots.mockResolvedValue({ items: [halted], next_cursor: "" });
    apiMock.pqcPilot.mockResolvedValue(halted);
    apiMock.startPQCPilot.mockResolvedValue({
      ...halted,
      id: "66666666-6666-4666-8666-666666666666",
      name: "Web PQ pilot",
      status: "running",
      current_wave: 1,
      halted_at_wave: "",
      verdict_summary: "",
      signed_report: undefined,
      waves: [],
    });
  });

  it("lists pilots, shows the canary's evidence and the skipped wave, and starts a new pilot", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <AppQueryProvider>
        <PQCPilots />
      </AppQueryProvider>,
    );
    const row = await screen.findByRole("button", { name: /Payments PQ pilot/ });
    expect(within(row).getByText("halted")).toBeInTheDocument();
    expect(within(row).getByText(/halted at canary/)).toBeInTheDocument();
    await user.click(row);
    const waves = await screen.findByRole("region", { name: /Waves and evidence/ });
    expect(within(waves).getByText("1. canary")).toBeInTheDocument();
    expect(within(waves).getByText("negotiated")).toBeInTheDocument();
    expect(within(waves).getByText("rejected")).toBeInTheDocument();
    expect(within(waves).getByText("3 ms · 408 B")).toBeInTheDocument();
    expect(within(waves).getByText(/Not probed: an earlier wave halted the pilot/)).toBeInTheDocument();
    expect(within(waves).getByText(/key pqc-readiness-report \(ECDSA-P256\)/)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/Pilot name/), "Web PQ pilot");
    await user.type(screen.getByLabelText(/Issuing authority ID/), "pq-issuing-ca");
    const wavesField = screen.getByLabelText(/Waves \(JSON\)/);
    await user.clear(wavesField);
    await user.click(wavesField);
    await user.paste(JSON.stringify([{ name: "canary", targets: [{ target_id: "t-1", address: "web.internal:443", fingerprint }] }]));
    await user.click(screen.getByRole("button", { name: "Start pilot" }));
    await waitFor(() => expect(apiMock.startPQCPilot).toHaveBeenCalledTimes(1));
    expect(apiMock.startPQCPilot.mock.calls[0][0]).toEqual({
      name: "Web PQ pilot",
      authority_id: "pq-issuing-ca",
      waves: [{ name: "canary", targets: [{ target_id: "t-1", address: "web.internal:443", fingerprint }] }],
    });
    expect(await screen.findByRole("status")).toHaveTextContent(/Pilot Web PQ pilot started/);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("refuses an invalid wave plan before calling the API", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <PQCPilots />
      </AppQueryProvider>,
    );
    await screen.findByRole("button", { name: /Payments PQ pilot/ });
    await user.type(screen.getByLabelText(/Pilot name/), "Broken");
    await user.type(screen.getByLabelText(/Issuing authority ID/), "pq-issuing-ca");
    const wavesField = screen.getByLabelText(/Waves \(JSON\)/);
    await user.clear(wavesField);
    await user.click(wavesField);
    await user.paste("[]");
    await user.click(screen.getByRole("button", { name: "Start pilot" }));
    expect(await screen.findByText(/Waves must be a JSON array/)).toBeInTheDocument();
    expect(apiMock.startPQCPilot).not.toHaveBeenCalled();
  });
});
