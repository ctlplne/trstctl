import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { MemoryRouter } from "react-router-dom";
import { PAMDependentRotation } from "@/pages/PAMDependentRotation";
const { mock } = vi.hoisted(() => ({
  mock: {
    secretPage: vi.fn(),
    openPAMServiceDependentReview: vi.fn(),
    appendPAMServiceDependentReviewPage: vi.fn(),
    sealPAMServiceDependentReview: vi.fn(),
    pamServiceDependentReview: vi.fn(),
    pamServiceDependentReviewPage: vi.fn(),
    previewPAMServiceDependentRecovery: vi.fn(),
    queuePAMServiceDependentRecovery: vi.fn(),
    requestPAMServiceReconciliationApproval: vi.fn(),
    pamServiceReconciliationPendingReview: vi.fn(),
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
    account: {
      account_id: accountID,
      sid: "S-1-5-21-1-2-3-1001",
      dn: "CN=owned-service,DC=example,DC=test",
      guid: "a".repeat(32),
      provider_id: "owned-directory",
      domain: "EXAMPLE",
      name: "owned-service",
    },
    secret_name: "ad/svc",
    order: [ref],
    hosts: [],
    expires_at: "2099-01-01T00:00:00Z",
  },
  expected_version: 7,
  provider_binding: "native-binding",
  probes: [{ ref, probe_id: "owned-http" }],
};
const reviewedDigest = "d".repeat(64);
const reviewHeader = "a".repeat(64),
  reviewFirst = "b".repeat(64),
  reviewTail = "c".repeat(64);
const reviewHost = {
  binding: { account: intent.plan.account, agent_id: ref.agent_id, enabled: true, revision: 7 },
  inventory_run_id: "scan",
  inventory_digest: reviewHeader,
  observed_at: "2026-11-07T06:00:00Z",
};
const pagedIntent = {
  ...intent,
  probes: [],
  plan: {
    ...intent.plan,
    version: 2,
    order: [],
    hosts: [],
    manifest: {
      version: 1,
      id: intent.plan.id,
      header_digest: reviewHeader,
      digest: "e".repeat(64),
      tail_digest: reviewTail,
      page_count: 2,
      entry_count: 1,
      host_count: 1,
      expires_at: intent.plan.expires_at,
    },
  },
};
function mockPagedReview(exact: typeof pagedIntent, hosts = [reviewHost]) {
  const root = {
    header: { id: exact.plan.id, account: exact.plan.account, secret_name: exact.plan.secret_name, mode: "mode" in exact ? exact.mode : undefined },
    header_digest: reviewHeader,
  };
  const makePage = (n: number, body: unknown) => ({ ...(body as object), version: 1, id: exact.plan.id, page_number: n, digest: n ? reviewTail : reviewFirst });
  const pages = new Map<number, unknown>([
    [0, makePage(0, { header_digest: reviewHeader, previous_digest: reviewHeader, hosts, entries: null })],
    [
      1,
      makePage(1, { header_digest: reviewHeader, previous_digest: reviewFirst, hosts: [hosts[0]], entries: [{ host: hosts[0], ref, probe_id: "owned-http" }] }),
    ],
  ]);
  const sealed = {
    ...root,
    intent: exact,
    intent_digest: reviewedDigest,
    page_count: 2,
    entry_count: exact.plan.manifest.entry_count,
    host_count: hosts.length,
    seal: { ...exact.plan.manifest, host_count: hosts.length },
  };
  mock.openPAMServiceDependentReview.mockResolvedValue(root);
  mock.appendPAMServiceDependentReviewPage.mockImplementation(async (_id, n, body) => {
    const page = makePage(n, body);
    pages.set(n, page);
    return page;
  });
  mock.sealPAMServiceDependentReview.mockResolvedValue(sealed);
  mock.pamServiceDependentReview.mockResolvedValue(sealed);
  mock.pamServiceDependentReviewPage.mockImplementation(async (_id, n) => pages.get(n));
}
const progress = {
  rotation: { id: "change-1", intent_digest: "original-intent", intent, direction: "inverse", directory_restored: true, failure: "native_update_failed" },
  command: { phase: "staged", error: "dependent_inverse_pending" },
};
beforeEach(() => {
  for (const m of Object.values(mock)) m.mockReset();
  mock.secretPage.mockResolvedValue({ items: [{ name: "ad/svc", version: 7 }] });
  mock.pamServiceDependentHosts.mockResolvedValue({
    items: [{ binding: reviewHost.binding, latest_scan: { id: "scan", current: true, status: "complete" } }],
  });
  mock.pamServiceDependentScan.mockResolvedValue({
    id: "scan",
    status: "complete",
    report_digest: reviewHeader,
    report: { run_id: "scan", observed_at: reviewHost.observed_at, services: [{ name: ref.name }], tasks: [], pools: [] },
  });
  mockPagedReview(pagedIntent);
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
        <MemoryRouter>
          <PAMDependentRotation accountID={accountID} canManage={canManage} rotationID={id} onRotationID={onRotationID} />
        </MemoryRouter>
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
  await screen.findByText(reviewedDigest);
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await screen.findByText("All review pages loaded.", { exact: false });
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Rotate account and dependents" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: /I accept the single-phase/ }));
  await user.click(screen.getByRole("button", { name: "Rotate account and dependents" }));
  await waitFor(() =>
    expect(mock.queuePAMServiceDependentRotation).toHaveBeenCalledWith(
      accountID,
      { intent: pagedIntent, intent_digest: reviewedDigest, acknowledge_single_phase: true },
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

const reconcileIntent = {
  ...intent,
  mode: "reconcile",
  reconcile: { dn: "CN=reconcile,DC=example,DC=test", sid: "S-1-5-21-1-2-3-1002", guid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
};
const reconcileApproval = {
  approval_request_id: "approval-1",
  approval_intent_digest: "approval-digest",
  status: "pending",
  required_approvals: 1,
  approval_count: 0,
  expires_at: intent.plan.expires_at,
};
it("requests independent reconciliation consent and refreshes the exact requester review before queuing", async () => {
  const exact = { ...pagedIntent, mode: "reconcile", reconcile: reconcileIntent.reconcile };
  mockPagedReview(exact);
  mock.requestPAMServiceReconciliationApproval.mockResolvedValue(reconcileApproval);
  mock.pamServiceReconciliationPendingReview.mockResolvedValue({
    intent: exact,
    intent_digest: reviewedDigest,
    approval: { ...reconcileApproval, status: "approved", approval_count: 1 },
    reason: "Recover external drift",
  });
  mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.selectOptions(screen.getByLabelText("Directory operation"), "reconcile");
  await user.type(screen.getByLabelText("Reason for reconciliation"), "Recover external drift");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  await user.type(await screen.findByLabelText("Useful-work probe for owned-web"), "owned-http");
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await screen.findByText(reconcileIntent.reconcile.dn);
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await screen.findByText("All review pages loaded.", { exact: false });
  expect(screen.getByRole("button", { name: "Rotate account and dependents" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Request independent reconciliation approval" }));
  expect(await screen.findByRole("link", { name: "Open independent approval" })).toHaveAttribute("href", "/approvals?request=approval-1");
  await user.click(screen.getByRole("checkbox", { name: /I accept the single-phase/ }));
  expect(screen.getByRole("button", { name: "Rotate account and dependents" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Refresh reconciliation approval" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Rotate account and dependents" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Rotate account and dependents" }));
  await waitFor(() =>
    expect(mock.queuePAMServiceDependentRotation).toHaveBeenCalledWith(
      accountID,
      {
        intent: exact,
        intent_digest: reviewedDigest,
        acknowledge_single_phase: true,
        approval_request_id: "approval-1",
        approval_intent_digest: "approval-digest",
      },
      expect.any(String),
    ),
  );
  expect(mock.requestPAMServiceReconciliationApproval).toHaveBeenCalledTimes(1);
});
it("reopens a claimed first command after reload and retries only the frozen payload", async () => {
  mock.pamServiceReconciliationPendingReview.mockResolvedValue({
    intent: reconcileIntent,
    intent_digest: "reviewed-digest",
    approval: { ...reconcileApproval, status: "consumed" },
    queue_pending: true,
    reason: "Recover external drift",
  });
  render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <MemoryRouter>
          <PAMDependentRotation accountID={accountID} canManage reviewID="change-1" approvalID="approval-1" onRotationID={vi.fn()} />
        </MemoryRouter>
      </IntlProvider>
    </AppQueryProvider>,
  );
  const user = userEvent.setup();
  await screen.findByText(reconcileIntent.reconcile.dn);
  expect(mock.pamServiceReconciliationPendingReview).toHaveBeenCalledWith(accountID, "change-1", "approval-1");
  expect(mock.previewPAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(mock.pamServiceDependentHosts).not.toHaveBeenCalled();
  await user.click(screen.getByRole("checkbox", { name: /I accept the single-phase/ }));
  await user.click(screen.getByRole("button", { name: "Rotate account and dependents" }));
  await waitFor(() =>
    expect(mock.queuePAMServiceDependentRotation).toHaveBeenCalledWith(
      accountID,
      expect.objectContaining({ intent: reconcileIntent, approval_request_id: "approval-1", approval_intent_digest: "approval-digest" }),
      expect.any(String),
    ),
  );
  expect(mock.requestPAMServiceReconciliationApproval).not.toHaveBeenCalled();
});

it("reviews the exact inverse effect and requires a reason and uncertainty acknowledgement before a replacement lease", async () => {
  const user = userEvent.setup();
  mock.pamServiceDependentRotation.mockResolvedValue({ ...progress, recovery_step_id: "step-1" });
  mock.previewPAMServiceDependentRecovery.mockResolvedValue({
    recovery_digest: "exact-effect",
    intent_digest: "original-intent",
    previous_step: {
      step_id: "step-1",
      ref,
      action: "probe",
      direction: "inverse",
      account_sid: "S-1-5-21-1-2-3-1001",
      probe_id: "owned-http",
      not_before: "2026-11-07T00:00:00Z",
      deadline: "2026-11-07T00:02:00Z",
    },
    previous_status: "uncertain",
    current_vault_version: 8,
    retained_generation_version: 7,
  });
  mock.queuePAMServiceDependentRecovery.mockResolvedValue({ step: { step_id: "replacement" }, recovery_digest: "exact-effect" });
  mount("change-1");
  await user.click(await screen.findByRole("button", { name: "Review inverse recovery" }));
  await screen.findByText("S-1-5-21-1-2-3-1001");
  expect(mock.previewPAMServiceDependentRecovery).toHaveBeenCalledWith("change-1", "step-1");
  const queue = screen.getByRole("button", { name: "Queue inverse recovery" });
  expect(queue).toBeDisabled();
  await user.type(screen.getByLabelText("Recovery reason"), "Observed exact terminal task and no running instances");
  expect(queue).toBeDisabled();
  await user.click(screen.getByLabelText("I reviewed this exact effect; the original failed, uncertain or expired outcome remains in the record."));
  await user.click(queue);
  await waitFor(() =>
    expect(mock.queuePAMServiceDependentRecovery).toHaveBeenCalledWith(
      "change-1",
      {
        step_id: "step-1",
        intent_digest: "original-intent",
        recovery_digest: "exact-effect",
        reason: "Observed exact terminal task and no running instances",
        acknowledge_original_outcome: true,
      },
      expect.any(String),
    ),
  );
});
it("does not expose inverse recovery to a read-only operator", async () => {
  mock.pamServiceDependentRotation.mockResolvedValue({ ...progress, recovery_step_id: "step-1" });
  mount("change-1", false);
  await screen.findByText("dependent_inverse_pending");
  expect(screen.queryByRole("button", { name: "Review inverse recovery" })).not.toBeInTheDocument();
});

it("authors one paged account review, retains an empty selected host, and queues only the server's exact sealed intent", async () => {
  const empty = { ...reviewHost, binding: { ...reviewHost.binding, agent_id: "56900000-0000-4000-8000-000000000003" }, inventory_run_id: "empty-scan" };
  const exact = { ...pagedIntent, plan: { ...pagedIntent.plan, manifest: { ...pagedIntent.plan.manifest, host_count: 2 } } };
  mockPagedReview(exact, [reviewHost, empty]);
  mock.pamServiceDependentHosts.mockResolvedValue({
    items: [reviewHost, empty].map((host) => ({ binding: host.binding, latest_scan: { id: host.inventory_run_id, current: true, status: "complete" } })),
  });
  mock.pamServiceDependentScan.mockImplementation(async (id) => ({
    id,
    status: "complete",
    report_digest: reviewHeader,
    report: { run_id: id, observed_at: reviewHost.observed_at, services: id === "scan" ? [{ name: ref.name }] : [], tasks: [], pools: [] },
  }));
  mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  await user.type(await screen.findByLabelText("Useful-work probe for owned-web"), "owned-http");
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await waitFor(() => expect(mock.openPAMServiceDependentReview).toHaveBeenCalledTimes(1));
  expect(mock.previewPAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(mock.appendPAMServiceDependentReviewPage).toHaveBeenNthCalledWith(
    1,
    "change-1",
    0,
    expect.objectContaining({ hosts: [reviewHost, empty], entries: [] }),
    expect.any(String),
  );
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Rotate account and dependents" })).toBeDisabled();
  await user.click(await screen.findByRole("button", { name: "Next review page" }));
  await screen.findByText("All review pages loaded.", { exact: false });
  await user.click(screen.getByRole("checkbox", { name: /I accept the single-phase/ }));
  await user.click(screen.getByRole("button", { name: "Rotate account and dependents" }));
  await waitFor(() =>
    expect(mock.queuePAMServiceDependentRotation).toHaveBeenCalledWith(
      accountID,
      { intent: exact, intent_digest: reviewedDigest, acknowledge_single_phase: true },
      expect.any(String),
    ),
  );
});

it("reopens a sealed review before approval without rescanning or rewriting its scope", async () => {
  const exact = { ...pagedIntent, mode: "reconcile", reconcile: reconcileIntent.reconcile };
  mockPagedReview(exact);
  mock.requestPAMServiceReconciliationApproval.mockResolvedValue(reconcileApproval);
  render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <MemoryRouter>
          <PAMDependentRotation accountID={accountID} canManage reviewID="change-1" onRotationID={vi.fn()} />
        </MemoryRouter>
      </IntlProvider>
    </AppQueryProvider>,
  );
  const user = userEvent.setup();
  await screen.findByText(reconcileIntent.reconcile.dn);
  expect(mock.pamServiceDependentReview).toHaveBeenCalledWith("change-1");
  expect(mock.pamServiceDependentHosts).not.toHaveBeenCalled();
  expect(mock.openPAMServiceDependentReview).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await screen.findByText("All review pages loaded.", { exact: false });
  const request = screen.getByRole("button", { name: "Request independent reconciliation approval" });
  expect(request).toBeDisabled();
  await user.type(screen.getByLabelText("Reason for reconciliation"), "Recover external drift from this exact sealed review");
  await user.click(request);
  await waitFor(() =>
    expect(mock.requestPAMServiceReconciliationApproval).toHaveBeenCalledWith(
      accountID,
      { intent: exact, intent_digest: reviewedDigest, reason: "Recover external drift from this exact sealed review" },
      expect.any(String),
    ),
  );
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
  expect(mock.appendPAMServiceDependentReviewPage).not.toHaveBeenCalled();
});
it("keeps authoring rows bounded, fills empty probes without overwriting custom work, and preserves global order across row pages", async () => {
  const exact = { ...pagedIntent, plan: { ...pagedIntent.plan, manifest: { ...pagedIntent.plan.manifest, entry_count: 28 } } };
  mockPagedReview(exact);
  mock.pamServiceDependentScan.mockResolvedValue({
    id: "scan",
    status: "complete",
    report_digest: reviewHeader,
    report: {
      run_id: "scan",
      observed_at: reviewHost.observed_at,
      services: Array.from({ length: 28 }, (_, n) => ({ name: `owned-${n}` })),
      tasks: [],
      pools: [],
    },
  });
  mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  await user.type(await screen.findByLabelText("Useful-work probe for owned-0"), "custom-health");
  expect(screen.getAllByLabelText(/^Useful-work probe for owned-/)).toHaveLength(25);
  await user.type(screen.getByLabelText("Useful-work probe for empty entries"), "shared-health");
  await user.click(screen.getByRole("button", { name: "Fill empty probes" }));
  expect(screen.getByLabelText("Useful-work probe for owned-0")).toHaveValue("custom-health");
  await user.click(screen.getByRole("button", { name: "Move owned-24 later" }));
  await user.click(screen.getByRole("button", { name: "Next dependent rows" }));
  expect(await screen.findByLabelText("Useful-work probe for owned-24")).toHaveValue("shared-health");
  expect(screen.getAllByLabelText(/^Useful-work probe for owned-/)).toHaveLength(3);
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await waitFor(() => expect(mock.appendPAMServiceDependentReviewPage).toHaveBeenCalledTimes(2));
  const entries = mock.appendPAMServiceDependentReviewPage.mock.calls[1][2].entries;
  expect(entries.slice(24, 27).map((v: { ref: { name: string } }) => v.ref.name)).toEqual(["owned-25", "owned-24", "owned-26"]);
  expect(entries[0].probe_id).toBe("custom-health");
  expect(entries[27].probe_id).toBe("shared-health");
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
});
it("retries a lost page response with identical write keys", async () => {
  mock.appendPAMServiceDependentReviewPage.mockRejectedValueOnce(new Error("owned page response lost"));
  mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  await user.type(await screen.findByLabelText("Useful-work probe for owned-web"), "owned-http");
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await screen.findByText("owned page response lost");
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await waitFor(() => expect(mock.sealPAMServiceDependentReview).toHaveBeenCalledTimes(1));
  expect(mock.openPAMServiceDependentReview.mock.calls[0]).toEqual(mock.openPAMServiceDependentReview.mock.calls[1]);
  expect(mock.appendPAMServiceDependentReviewPage.mock.calls[0]).toEqual(mock.appendPAMServiceDependentReviewPage.mock.calls[1]);
});

it("opens a different immutable draft when a probe changes after an interrupted write", async () => {
  mock.appendPAMServiceDependentReviewPage.mockRejectedValueOnce(new Error("owned interrupted write"));
  mount();
  const user = userEvent.setup();
  await screen.findByRole("option", { name: "ad/svc" });
  await user.selectOptions(screen.getByLabelText("Stored password reference"), "ad/svc");
  await user.click(screen.getByRole("button", { name: "Review dependents" }));
  const probe = await screen.findByLabelText("Useful-work probe for owned-web");
  await user.type(probe, "owned-http");
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await screen.findByText("owned interrupted write");
  await user.clear(probe);
  await user.type(probe, "different-health");
  await user.click(screen.getByRole("button", { name: "Preview rotation" }));
  await waitFor(() => expect(mock.sealPAMServiceDependentReview).toHaveBeenCalledTimes(1));
  expect(mock.openPAMServiceDependentReview.mock.calls[0][2]).not.toEqual(mock.openPAMServiceDependentReview.mock.calls[1][2]);
  expect(mock.appendPAMServiceDependentReviewPage.mock.calls[2][2].entries[0].probe_id).toBe("different-health");
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
});

it("lets a read-only operator inspect the frozen pages of an existing operation", async () => {
  mock.pamServiceDependentRotation.mockResolvedValue({ ...progress, rotation: { ...progress.rotation, intent: pagedIntent, intent_digest: reviewedDigest } });
  mount("change-1", false);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Next review page" }));
  await screen.findByText("owned-http");
  expect(mock.pamServiceDependentReviewPage).toHaveBeenCalledWith("change-1", 1);
  expect(mock.secretPage).not.toHaveBeenCalled();
  expect(mock.openPAMServiceDependentReview).not.toHaveBeenCalled();
  expect(mock.queuePAMServiceDependentRotation).not.toHaveBeenCalled();
});
