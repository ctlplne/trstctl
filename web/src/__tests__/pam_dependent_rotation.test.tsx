import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMDependentRotation } from "@/pages/PAMDependentRotation";
const { mock } = vi.hoisted(() => ({
  mock: {
    secretPage: vi.fn(),
    pamServiceDependentHosts: vi.fn(),
    pamServiceDependentScan: vi.fn(),
    previewPAMServiceDependentRotation: vi.fn(),
    queuePAMServiceDependentRotation: vi.fn(),
    pamServiceDependentRotation: vi.fn(),
    pamServiceDependentRotationSteps: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...mock } };
});
const accountID = "56900000-0000-4000-8000-000000000002";
const ref = { agent_id: "56900000-0000-4000-8000-000000000001", family: "services", name: "owned-web" };
const intent = {
  plan: {
    id: "change-1",
    account: { account_id: accountID, sid: "S-1-5-21-1-2-3-1001" },
    secret_name: "ad/svc",
    order: [ref],
    hosts: [],
    expires_at: "2099-01-01T00:00:00Z",
  },
  expected_version: 7,
  provider_binding: "native-binding",
  probes: [{ ref, probe_id: "owned-http" }],
};
const progress = {
  rotation: { id: "change-1", intent, direction: "inverse", directory_restored: true, failure: "native_update_failed" },
  command: { phase: "staged", error: "dependent_inverse_pending" },
};
beforeEach(() => {
  for (const m of Object.values(mock)) m.mockReset();
  mock.secretPage.mockResolvedValue({ items: [{ name: "ad/svc", version: 7 }] });
  mock.pamServiceDependentHosts.mockResolvedValue({
    items: [{ binding: { agent_id: ref.agent_id, enabled: true }, latest_scan: { id: "scan", current: true, status: "complete" } }],
  });
  mock.pamServiceDependentScan.mockResolvedValue({ status: "complete", report: { services: [{ name: ref.name }], tasks: [], pools: [] } });
  mock.previewPAMServiceDependentRotation.mockResolvedValue({ intent, intent_digest: "reviewed-digest" });
  mock.queuePAMServiceDependentRotation.mockResolvedValue(progress);
  mock.pamServiceDependentRotation.mockResolvedValue(progress);
  mock.pamServiceDependentRotationSteps.mockResolvedValue({
    items: [
      {
        intent: { step_id: "step-1", ref, direction: "inverse", action: "probe" },
        status: "uncertain",
        delivery_status: "failed",
        report: { failure: "native_task_start_unknown" },
      },
    ],
  });
});
function mount(id?: string, canManage = true) {
  const onRotationID = vi.fn();
  render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMDependentRotation accountID={accountID} canManage={canManage} rotationID={id} onRotationID={onRotationID} />
      </IntlProvider>
    </AppQueryProvider>,
  );
  return onRotationID;
}
it("requires exact review and acknowledgement before queuing and shows inverse uncertainty separately from delivery", async () => {
  const onRotationID = mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  const probe = await screen.findByLabelText("Useful-work probe for owned-web");
  await user.type(probe, "owned-http");
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await screen.findByText("reviewed-digest");
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Rotate account and dependents" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: /I accept the single-phase/ }));
  await user.click(screen.getByRole("button", { name: "Rotate account and dependents" }));
  await waitFor(() =>
    expect(mock.queuePAMServiceDependentRotation).toHaveBeenCalledWith(
      accountID,
      { intent, intent_digest: "reviewed-digest", acknowledge_single_phase: true },
      expect.any(String),
    ),
  );
  expect(onRotationID).toHaveBeenCalledWith("change-1");
  await screen.findByText("native_task_start_unknown");
  expect(screen.getByText("Delivery: failed")).toBeInTheDocument();
  expect(screen.getByText(/Directory restored: yes/)).toBeInTheDocument();
  expect(screen.queryByText("Rotation complete")).not.toBeInTheDocument();
});
it("reopens retained evidence without write authority and pages steps", async () => {
  mock.pamServiceDependentRotationSteps.mockImplementation(async (_id, after) => (after ? { items: [] } : { items: [], next_cursor: "step-1" }));
  mount("change-1", false);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Next steps" }));
  await waitFor(() => expect(mock.pamServiceDependentRotationSteps).toHaveBeenCalledWith("change-1", "step-1"));
  expect(screen.queryByRole("button", { name: "Preview rotation" })).not.toBeInTheDocument();
  expect(mock.secretPage).not.toHaveBeenCalled();
});
it("refuses partial inventory from a later host page before review", async () => {
  mock.pamServiceDependentHosts.mockImplementation(async (_id, after) =>
    after
      ? { items: [{ binding: { agent_id: "other", enabled: true }, latest_scan: { id: "partial", current: true, status: "partial" } }] }
      : { items: [], next_cursor: "next-host" },
  );
  mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  await screen.findByText(/Every enabled host needs/);
  expect(mock.previewPAMServiceDependentRotation).not.toHaveBeenCalled();
});

it("retries a failed password-reference read without recreating the rotation review", async () => {
  mock.secretPage.mockRejectedValueOnce(new Error("owned reference read unavailable"));
  mount();
  const user = userEvent.setup();
  await screen.findByText("owned reference read unavailable");
  expect(screen.getByRole("button", { name: "Review dependents" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Retry read" }));
  await screen.findByRole("option", { name: "ad/svc" });
  expect(mock.secretPage).toHaveBeenCalledTimes(2);
  expect(mock.previewPAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
});
