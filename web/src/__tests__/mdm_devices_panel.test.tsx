import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MDMDevicesPanel } from "@/components/MDMDevicesPanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    mdmDevices: vi.fn(),
    mdmDeviceTrace: vi.fn(),
    mdmPollSchedules: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("MDM device evidence trace", () => {
  beforeEach(() => {
    apiMock.mdmDevices.mockReset().mockResolvedValue({
      items: [{ mdm: "intune", mdm_device_id: "device-7", install_state: "ok" }],
      failed: 0,
      unobserved: 0,
      renewal_at_risk: 0,
      guidance: "Read-only correlation.",
    });
    apiMock.mdmDeviceTrace.mockReset().mockResolvedValue({
      trace: {
        device_id: "device-7",
        steps: [
          { stage: "requested", outcome: "ok", source: "scep" },
          { stage: "issued", outcome: "ok", source: "ca" },
          { stage: "installed", outcome: "ok", source: "intune" },
          { stage: "renewing", outcome: "ok", source: "ca" },
        ],
        summary: "Enrolled and current: every step confirmed.",
      },
      guidance: "Evidence-backed trace.",
    });
    apiMock.mdmPollSchedules.mockReset().mockResolvedValue({
      items: [{ configured: true, mdm: "intune", enabled: true, execution: "relay", last_run_at: "2026-08-10T02:00:00Z", guidance: "" }],
      guidance: "A network relay redeems the token per attempt; the control plane never dials the MDM.",
    });
  });

  it("opens the served trace from the device row and shows renewing evidence", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MDMDevicesPanel />
      </AppQueryProvider>,
    );

    await user.click(await screen.findByRole("button", { name: "View details" }));
    expect(apiMock.mdmDeviceTrace).toHaveBeenCalledWith("intune", "device-7");
    expect(await screen.findByText("Enrolled and current: every step confirmed.")).toBeInTheDocument();
    expect(screen.getByText((_, node) => node?.tagName === "LI" && node.textContent === "renewing: ok")).toBeInTheDocument();
    expect(
      screen.getByText((_, node) => node?.tagName === "LI" && node.textContent === "intune · Enabled · relay · Last run: 2026-08-10 02:00"),
    ).toBeInTheDocument();
    expect(screen.getByText(/control plane never dials the MDM/)).toBeInTheDocument();
  });

  it("keeps a waiting relay schedule visible before any device observation exists", async () => {
    apiMock.mdmDevices.mockResolvedValue({ items: [], failed: 0, unobserved: 0, renewal_at_risk: 0, guidance: "" });
    apiMock.mdmPollSchedules.mockResolvedValue({
      items: [{ configured: true, mdm: "jamf", enabled: true, execution: "relay", last_error: "a dispatched mdm.sync job is still waiting", guidance: "" }],
      guidance: "Relay-only read.",
    });
    render(
      <AppQueryProvider>
        <MDMDevicesPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Network relay" })).toBeInTheDocument();
    expect(screen.getByText("a dispatched mdm.sync job is still waiting")).toBeInTheDocument();
  });

  it("renders Jamf challenge failure and offline-renewal remediation without inventing success", async () => {
    apiMock.mdmDevices.mockResolvedValue({
      items: [
        {
          mdm: "jamf",
          mdm_device_id: "mac-offline",
          install_state: "unknown",
          renewal_at_risk: true,
          renewal_detail: "The device has not checked in since the renewal window opened.",
        },
      ],
      failed: 0,
      unobserved: 1,
      renewal_at_risk: 1,
      guidance: "Unknown is not failed.",
    });
    apiMock.mdmDeviceTrace.mockResolvedValue({
      trace: {
        device_id: "mac-offline",
        steps: [
          { stage: "requested", outcome: "ok", source: "scep" },
          {
            stage: "issued",
            outcome: "failed",
            source: "scep",
            detail: "Challenge validation rejected the request; verify audience, expiry, and one-time nonce.",
          },
          { stage: "installed", outcome: "unknown" },
          {
            stage: "renewing",
            outcome: "unknown",
            source: "jamf",
            detail: "No later SCEP renewal transaction is present; bring the device online and trigger an MDM check-in.",
          },
        ],
        broke_at: "issued",
        summary: "Enrollment broke at issued: challenge validation rejected the request.",
      },
      guidance: "Evidence-backed trace.",
    });

    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MDMDevicesPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("The device has not checked in since the renewal window opened.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "View details" }));
    expect(await screen.findByText(/Challenge validation rejected the request/)).toBeInTheDocument();
    expect(screen.getByText(/bring the device online and trigger an MDM check-in/)).toBeInTheDocument();
    expect(screen.getByText((_, node) => node?.tagName === "LI" && node.textContent?.startsWith("issued: failed") === true)).toBeInTheDocument();
  });
});
