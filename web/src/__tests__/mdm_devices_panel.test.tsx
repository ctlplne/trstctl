import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MDMDevicesPanel } from "@/components/MDMDevicesPanel";
import { RbacProvider } from "@/components/rbac";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    mdmDevices: vi.fn(),
    mdmDeviceTrace: vi.fn(),
    mdmPollSchedules: vi.fn(),
    putMDMPollSchedule: vi.fn(),
    agents: vi.fn(),
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
      items: [
        {
          configured: true,
          mdm: "intune",
          enabled: true,
          execution: "relay",
          required_agent_id: "44444444-4444-4444-8444-44444444a101",
          last_run_at: "2026-08-10T02:00:00Z",
          guidance: "",
        },
      ],
      guidance: "A network relay redeems the token per attempt; the control plane never dials the MDM.",
    });
    apiMock.putMDMPollSchedule.mockReset();
    apiMock.agents.mockReset().mockResolvedValue([
      {
        id: "44444444-4444-4444-8444-44444444a101",
        name: "qa-network-relay",
        status: "active",
        roles: ["network"],
        presence: { state: "online", online: true, detail: "", evaluated_at: "2026-10-12T00:00:00Z" },
      },
    ]);
  });

  it("offers first-use relay schedule setup with an exact review before saving", async () => {
    apiMock.mdmDevices.mockResolvedValue({ items: [], failed: 0, unobserved: 0, renewal_at_risk: 0, guidance: "" });
    apiMock.mdmPollSchedules.mockResolvedValueOnce({ items: [], guidance: "Relay-only read." }).mockResolvedValue({
      items: [
        {
          configured: true,
          mdm: "jamf",
          base_url: "https://jamf.qa.local",
          token_ref: "secret://mdm/jamf",
          required_agent_id: "44444444-4444-4444-8444-44444444a101",
          interval_seconds: 600,
          enabled: true,
          execution: "relay",
          guidance: "",
        },
      ],
      guidance: "Relay-only read.",
    });
    apiMock.putMDMPollSchedule.mockResolvedValue({
      configured: true,
      mdm: "jamf",
      base_url: "https://jamf.qa.local",
      token_ref: "secret://mdm/jamf",
      required_agent_id: "44444444-4444-4444-8444-44444444a101",
      interval_seconds: 600,
      enabled: true,
      execution: "relay",
    });
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MDMDevicesPanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("heading", { name: "MDM device correlation" })).toBeInTheDocument();
    await user.click(screen.getByText("Configure MDM read schedule"));
    await user.selectOptions(screen.getByLabelText("MDM provider"), "jamf");
    await user.type(screen.getByLabelText("MDM API base URL"), "https://jamf.qa.local");
    await user.type(screen.getByLabelText("Bearer token secret reference"), "secret://mdm/jamf");
    await user.selectOptions(screen.getByLabelText("Network relay for this MDM"), "44444444-4444-4444-8444-44444444a101");
    await user.clear(screen.getByLabelText("Poll interval in seconds"));
    await user.type(screen.getByLabelText("Poll interval in seconds"), "600");
    await user.click(screen.getByRole("button", { name: "Review schedule" }));
    expect(screen.getByText(/relay reads Jamf every 600 seconds/)).toBeInTheDocument();
    expect(apiMock.putMDMPollSchedule).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Save reviewed schedule" }));
    expect(apiMock.putMDMPollSchedule).toHaveBeenCalledWith({
      mdm: "jamf",
      base_url: "https://jamf.qa.local",
      token_ref: "secret://mdm/jamf",
      required_agent_id: "44444444-4444-4444-8444-44444444a101",
      filter: "",
      interval_seconds: 600,
      enabled: true,
      execution: "relay",
      renewal_window_days: 0,
    });
    expect(await screen.findByText((_, node) => node?.tagName === "LI" && node.textContent?.startsWith("jamf · Enabled · relay") === true)).toBeInTheDocument();
  });

  it("keeps read-only operators from configuring a relay schedule", async () => {
    apiMock.mdmDevices.mockResolvedValue({ items: [], failed: 0, unobserved: 0, renewal_at_risk: 0, guidance: "" });
    apiMock.mdmPollSchedules.mockResolvedValue({ items: [], guidance: "Relay-only read." });
    render(
      <AppQueryProvider>
        <RbacProvider permissions={["certs:read"]}>
          <MDMDevicesPanel />
        </RbacProvider>
      </AppQueryProvider>,
    );
    expect(await screen.findByRole("heading", { name: "MDM device correlation" })).toBeInTheDocument();
    expect(await screen.findByText(/No MDM read schedule is configured/)).toBeInTheDocument();
    expect(screen.queryByText("Configure MDM read schedule")).not.toBeInTheDocument();
    expect(apiMock.putMDMPollSchedule).not.toHaveBeenCalled();
  });

  it("refuses review of an enabled schedule without an exact network relay", async () => {
    apiMock.mdmDevices.mockResolvedValue({ items: [], failed: 0, unobserved: 0, renewal_at_risk: 0, guidance: "" });
    apiMock.mdmPollSchedules.mockResolvedValue({ items: [], guidance: "Relay-only read." });
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MDMDevicesPanel />
      </AppQueryProvider>,
    );
    await user.click(await screen.findByText("Configure MDM read schedule"));
    await user.type(screen.getByLabelText("MDM API base URL"), "https://jamf.qa.local");
    await user.type(screen.getByLabelText("Bearer token secret reference"), "secret://mdm/jamf");
    await user.click(screen.getByRole("button", { name: "Review schedule" }));
    expect(await screen.findByText("Select a network relay before enabling this schedule.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save reviewed schedule" })).not.toBeInTheDocument();
    expect(apiMock.putMDMPollSchedule).not.toHaveBeenCalled();
  });

  it("rejects a poll interval below the server floor before exposing Save", async () => {
    apiMock.mdmDevices.mockResolvedValue({ items: [], failed: 0, unobserved: 0, renewal_at_risk: 0, guidance: "" });
    apiMock.mdmPollSchedules.mockResolvedValue({ items: [], guidance: "Relay-only read." });
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MDMDevicesPanel />
      </AppQueryProvider>,
    );
    await user.click(await screen.findByText("Configure MDM read schedule"));
    await user.type(screen.getByLabelText("MDM API base URL"), "https://jamf.qa.local");
    await user.type(screen.getByLabelText("Bearer token secret reference"), "secret://mdm/jamf");
    await user.clear(screen.getByLabelText("Poll interval in seconds"));
    await user.type(screen.getByLabelText("Poll interval in seconds"), "299");
    await user.click(screen.getByRole("button", { name: "Review schedule" }));
    expect(screen.queryByRole("button", { name: "Save reviewed schedule" })).not.toBeInTheDocument();
    expect(apiMock.putMDMPollSchedule).not.toHaveBeenCalled();
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
      screen.getByText(
        (_, node) =>
          node?.tagName === "LI" && node.textContent?.startsWith("intune · Enabled · relay · qa-network-relay · Last run: 2026-08-10 02:00") === true,
      ),
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
