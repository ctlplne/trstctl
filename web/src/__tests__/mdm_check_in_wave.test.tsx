import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MDMCheckInWavePanel } from "@/components/MDMCheckInWavePanel";
import { api, ApiError } from "@/lib/api";

// N9-L2: every device of a renewal wave checks in under one approval. The
// requester picks the wave (or the devices whose renewal is at risk) and asks
// once; Run says the wave waits for approval until another reviewer approves
// it, then queues it; the waves list counts each device's outcome.

vi.mock("@/components/rbac", () => ({ useCan: () => true }));

const devices = {
  items: [
    { mdm: "intune", mdm_device_id: "dev-a", device_name: "laptop-a", serial_number: "SER-A", install_state: "ok", renewal_at_risk: true },
    { mdm: "intune", mdm_device_id: "dev-b", device_name: "laptop-b", serial_number: "SER-B", install_state: "ok" },
    { mdm: "jamf", mdm_device_id: "417", device_name: "mac-417", install_state: "ok" },
  ],
};

describe("N9-L2 MDM check-in waves", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, "mdmDevices").mockResolvedValue(devices as never);
    vi.spyOn(api, "mdmCheckInWaves").mockResolvedValue([
      {
        id: "wave-1",
        mdm: "intune",
        reason: "wave 6",
        approval_request_id: "ap-1",
        requested_by: "ops@example.test",
        device_count: 3,
        checked_in: 2,
        failed: 1,
        queued: 0,
        queued_at: "2026-11-11T08:00:00Z",
      },
    ] as never);
  });

  it("lists the MDM's devices and its waves with each device's outcome counted", async () => {
    render(<MDMCheckInWavePanel />);
    expect(await screen.findByRole("heading", { name: "Check in a renewal wave" })).toBeInTheDocument();
    expect(screen.getByText("laptop-a")).toBeInTheDocument();
    expect(screen.queryByText("mac-417")).not.toBeInTheDocument();
    const wave = screen.getByText("ops@example.test").closest("tr") as HTMLTableRowElement;
    expect(
      within(wave)
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    ).toEqual(expect.arrayContaining(["3", "2", "1", "0"]));
  });

  it("asks once for the devices at risk, waits for approval, then runs the wave", async () => {
    const user = userEvent.setup();
    const ask = vi.spyOn(api, "requestMDMCheckInWaveApproval").mockResolvedValue({
      mdm: "intune",
      devices: [{ device_id: "dev-a", device_name: "laptop-a" }],
      reason: "renewed SCEP profile",
      approval_request_id: "ap-9",
      approval_intent_digest: "sha256:aa",
      status: "pending",
      required_approvals: 1,
      approval_count: 0,
      expires_at: "2026-11-13T08:00:00Z",
    } as never);
    const run = vi
      .spyOn(api, "executeMDMCheckInWave")
      .mockRejectedValueOnce(new ApiError(409, JSON.stringify({ status: 409, detail: "not approved" })))
      .mockResolvedValueOnce({ id: "wave-9", mdm: "intune", device_count: 1, checked_in: 0, failed: 0, queued: 1 } as never);
    render(<MDMCheckInWavePanel />);
    await user.click(await screen.findByRole("button", { name: "Select the 1 devices whose renewal is at risk" }));
    expect(screen.getByRole("checkbox", { name: "Check in laptop-a in this wave" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Check in laptop-b in this wave" })).not.toBeChecked();
    await user.type(screen.getByRole("textbox", { name: "Reason for the reviewer" }), "renewed SCEP profile");
    await user.click(screen.getByRole("button", { name: "Ask to check in 1 devices" }));
    await waitFor(() => expect(ask).toHaveBeenCalledWith("intune", { device_ids: ["dev-a"], reason: "renewed SCEP profile" }));
    expect(await screen.findByText(/Approval ap-9 for 1 devices: pending/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run the wave" }));
    expect(await screen.findByText("The wave waits for another reviewer's approval.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run the wave" }));
    expect(await screen.findByText("The wave is queued: 1 check-ins through the schedule's relay.")).toBeInTheDocument();
    expect(run).toHaveBeenLastCalledWith("intune", { approval_request_id: "ap-9", approval_intent_digest: "sha256:aa", device_ids: ["dev-a"] });
    await waitFor(() => expect(api.mdmCheckInWaves).toHaveBeenCalledTimes(2));
  });
});
