import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import type { DiscoveryFinding } from "@/lib/api";
import * as client from "@/lib/cloudMachineApi";
import { CloudMachineFindingParts } from "./CloudMachineFindingParts";

vi.mock("@/lib/cloudMachineApi", () => ({
  cloudChangesKey: (id: string) => ["cloud-machine-changes", id],
  listCloudMachineChanges: vi.fn().mockResolvedValue({ items: [], next_cursor: "" }),
  proposeCloudMachineChange: vi.fn(),
  executeCloudMachineChange: vi.fn(),
}));
function finding(native = true): DiscoveryFinding {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    kind: "cloud_machine_entitlement",
    metadata: {
      version: 1,
      collected_at: "2026-11-05T00:00:00Z",
      ...(native ? { source_origin: "https://iam.amazonaws.com" } : {}),
      identity: { native_id: native ? "AIDAOWNED" : undefined, principal: { arn: "arn:aws:iam::111122223333:user/workload" } },
      keys: [
        { key: { id: "AKIAOWNED", status: "Active", created_at: "2020-01-01T00:00:00Z", last_use_coverage: "unavailable" }, long_lived: true, stale: false },
      ],
      evaluations: [
        {
          check: { action: "s3:GetObject", resource: "arn:aws:s3:::owned/report" },
          result: { decision: "indeterminate", reasons: [{ source: "organization", detail: "SCP evidence unavailable" }] },
          unused_in_covered_window: false,
          activity_coverage: "unavailable",
          observed_uses: 0,
          resource_unbound_uses: 0,
        },
      ],
      self_escalation_candidates: [],
      limitations: ["Live AWS enforcement unproven"],
    },
  } as unknown as DiscoveryFinding;
}
function mount(value = finding()) {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <CloudMachineFindingParts finding={value} />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}
describe("captured cloud permissions and exact human-reviewed changes", () => {
  it("shows the served indeterminate decision without inventing an unused permission", async () => {
    mount();
    expect(await screen.findByText("indeterminate")).toBeInTheDocument();
    expect(screen.getByText(/SCP evidence unavailable/)).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Deny s3/ })).not.toBeInTheDocument();
    expect(screen.getByText(/does not prove live AWS/)).toBeInTheDocument();
  });
  it("requires a fresh native binding before showing mutation controls", async () => {
    mount(finding(false));
    expect(await screen.findByText(/Capture this native source again/)).toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  });
  it("carries one selected key and a reference-only writer through review to an approval proposal", async () => {
    const user = userEvent.setup();
    vi.mocked(client.proposeCloudMachineChange).mockResolvedValue({
      id: "plan",
      state: "awaiting_approval",
      intent_digest: "digest",
      expires_at: "2026-11-05T01:00:00Z",
      intent: { action: "revoke_key", access_key_id: "AKIAOWNED" },
    } as never);
    mount();
    await user.selectOptions(await screen.findByRole("combobox"), "key:AKIAOWNED");
    await user.click(screen.getByRole("button", { name: /Next/ }));
    await user.type(screen.getByLabelText("Writer STS file reference"), "env:OWNED_WRITER_PATH");
    await user.type(screen.getByLabelText("Reason and workload impact"), "Retire the exact unused fixture key");
    await user.click(screen.getByRole("button", { name: /Next/ }));
    expect(client.proposeCloudMachineChange).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Create approval proposal" }));
    await waitFor(() =>
      expect(client.proposeCloudMachineChange).toHaveBeenCalledWith(
        expect.objectContaining({
          finding_id: finding().id,
          action: "revoke_key",
          access_key_id: "AKIAOWNED",
          writer_session_file_ref: "env:OWNED_WRITER_PATH",
          required_approvals: 2,
        }),
        expect.any(String),
      ),
    );
  });
});
