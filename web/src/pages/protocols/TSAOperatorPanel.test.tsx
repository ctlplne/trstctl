import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { TSAOperatorPanel } from "@/pages/protocols/TSAOperatorPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { tsaQualification: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("TSA operator qualification", () => {
  beforeEach(() => {
    apiMock.tsaQualification.mockReset();
  });

  it("previews exact runtime gates, shows the stock-client boundary, and proves a ready responder without issuing from the browser", async () => {
    apiMock.tsaQualification.mockResolvedValue({
      checked_at: "2026-08-30T18:15:00Z",
      ready: true,
      effect_free: true,
      endpoint: "/tsa",
      policy_oid: "1.3.6.1.4.1.59551.2.1",
      checks: [
        { id: "configured", label: "TSA enabled", passed: true, detail: "TSA is enabled in startup configuration." },
        { id: "endpoint-mounted", label: "TSA endpoint mounted", passed: true, detail: "The running control plane owns POST /tsa." },
      ],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["This qualification reads in-memory server posture only."],
      blockers: [],
    });

    render(
      <AppQueryProvider>
        <TSAOperatorPanel />
      </AppQueryProvider>,
    );

    expect(screen.getByRole("heading", { name: "Timestamp authority readiness" })).toBeInTheDocument();
    expect(screen.getByText(/does not mint a timestamp/i)).toBeInTheDocument();
    expect(screen.getByText(/OpenSSL command below is the real wire test/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Check TSA readiness" }));
    await waitFor(() => expect(apiMock.tsaQualification).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Ready for a stock-client test")).toBeInTheDocument();
    expect(screen.getByText("1.3.6.1.4.1.59551.2.1")).toBeInTheDocument();
    expect(screen.getByText("TSA endpoint mounted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();
  });

  it("shows each server-provided secure repair and keeps retry available after a blocked check", async () => {
    apiMock.tsaQualification.mockResolvedValue({
      checked_at: "2026-08-30T18:16:00Z",
      ready: false,
      effect_free: true,
      endpoint: "/tsa",
      policy_oid: "1.3.6.1.4.1.59551.2.1",
      checks: [
        {
          id: "signer",
          label: "Isolated timestamp signer",
          passed: false,
          detail: "This gate is not ready in the running process.",
          recovery: "Restore the isolated signer connection; never move the TSA key into the control-plane process.",
        },
      ],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["This qualification reads in-memory server posture only."],
      blockers: ["Isolated timestamp signer: restore the signer."],
    });

    render(
      <AppQueryProvider>
        <TSAOperatorPanel />
      </AppQueryProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Check TSA readiness" }));

    expect(await screen.findByText("Needs repair before timestamping")).toBeInTheDocument();
    expect(screen.getByText(/never move the TSA key into the control-plane process/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeEnabled();
  });

  it("rejects malformed readiness responses instead of presenting invented success", async () => {
    apiMock.tsaQualification.mockResolvedValue({ ready: true, checks: [] });
    render(
      <AppQueryProvider>
        <TSAOperatorPanel />
      </AppQueryProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Check TSA readiness" }));
    expect(await screen.findByText("TSA readiness check failed")).toBeInTheDocument();
    expect(screen.queryByText("Ready for a stock-client test")).not.toBeInTheDocument();
  });
});
