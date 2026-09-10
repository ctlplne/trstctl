import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppRoutes } from "@/App";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    authMethods: vi.fn(),
    me: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    approvalRequests: vi.fn(),
    approveApprovalRequest: vi.fn(),
    denyApprovalRequest: vi.fn(),
    agentJobPosture: vi.fn(),
    bulkheadStats: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderOperations() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/operations"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

const failedDelivery = {
  id: "d31196d1-c483-524e-b249-1629748f38f2",
  tenant_id: "11111111-1111-4111-8111-111111111111",
  connector: "api-token",
  destination: "connector.deploy/github-actions",
  target: "release",
  status: "failed" as const,
  attempts: 3,
  reason: "repository permission denied",
  detail: "The GitHub Actions deployment token could not write the release secret.",
  rollback_ref: "rollback/deploy/d31196d1",
  idempotency_key: "operations-design-failed-1",
  outbox_id: 42,
  created_at: "2026-08-19T23:11:00Z",
  updated_at: "2026-08-19T23:12:00Z",
};

const succeededRotation = {
  id: "4ee3862f-901c-54ef-b9b5-73fb064802f7",
  tenant_id: "11111111-1111-4111-8111-111111111111",
  identity_id: "54e2c12a-2642-43f0-ab8a-b0432d69ada3",
  trigger: "scheduler",
  status: "succeeded" as const,
  idempotency_key: "operations-design-rotation-1",
  outbox_id: 43,
  created_at: "2026-08-19T23:03:00Z",
  completed_at: "2026-08-19T23:03:30Z",
  updated_at: "2026-08-19T23:03:30Z",
};

describe("Jobs and queues design contract", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "operator-1", tenant_id: "t1", email: "operator@example.test" });
    apiMock.rotationRuns.mockResolvedValue({ items: [succeededRotation] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [failedDelivery] });
    apiMock.approvalRequests.mockResolvedValue([]);
    apiMock.agentJobPosture.mockResolvedValue({
      served: true,
      generated_at: "2026-08-20T23:15:00Z",
      claimable_kinds: ["connector.deploy", "discovery.run"],
      queues: [
        { kind: "connector.deploy", enabled: true, pending: 2, claimed: 0, oldest_unclaimed_seconds: 7200 },
        { kind: "discovery.run", enabled: true, pending: 0, claimed: 0 },
      ],
      redemptions: { live: 0, total: 4 },
      receipts: { verified: 9, rejected: 0 },
    });
    apiMock.bulkheadStats.mockResolvedValue({
      served: true,
      pools: [
        {
          name: "outbox-connectors",
          workers: 2,
          capacity: 8,
          queued: 3,
          submitted: 20,
          completed: 17,
          rejected: 0,
          panicked: 0,
          saturation_percent: 38,
        },
      ],
    });
  });

  it("leads with health and one failed-job decision while keeping raw proof out of the default path", async () => {
    const user = userEvent.setup();
    renderOperations();

    expect(await screen.findByRole("heading", { level: 1, name: "Jobs and queues" })).toBeInTheDocument();
    expect(screen.getByText("Whether background work is healthy and what failed.")).toBeInTheDocument();

    const operate = screen.getByTestId("page-depth-operate");
    const primary = within(operate).getByRole("button", { name: "Review failed job" });
    expect(within(operate).getAllByRole("button")).toHaveLength(1);

    expect(await screen.findByRole("heading", { level: 2, name: "Needs attention" })).toBeInTheDocument();
    expect(await screen.findByText("1 failed job needs review.")).toBeInTheDocument();
    expect(await screen.findByText("2 jobs are waiting; the oldest has waited 2h.")).toBeInTheDocument();
    const review = await screen.findByRole("button", { name: "Review Deploy to GitHub Actions" });

    expect(screen.queryByText(failedDelivery.id)).not.toBeInTheDocument();
    expect(screen.queryByText(failedDelivery.destination)).not.toBeInTheDocument();
    await user.click(primary);
    expect(review).toHaveFocus();

    await user.click(review);
    const dialog = await screen.findByRole("dialog", { name: "Failed job: Deploy to GitHub Actions" });
    expect(within(dialog).getByText(failedDelivery.id)).toBeInTheDocument();
    expect(within(dialog).getByText(failedDelivery.destination)).toBeInTheDocument();
    expect(within(dialog).getByText("3")).toBeInTheDocument();
    expect(within(dialog).getByText("repository permission denied")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "View exact event log" })).toHaveAttribute("href", `/audit?q=${encodeURIComponent(failedDelivery.id)}`);
  });

  it("keeps worker limits, all work, rotation records, IDs, attempts, and logs behind named disclosures", async () => {
    const user = userEvent.setup();
    renderOperations();
    await screen.findByRole("heading", { level: 1, name: "Jobs and queues" });

    const pageProof = screen.getByTestId("page-depth-prove");
    expect(pageProof).not.toHaveAttribute("open");
    expect(within(pageProof).getByText(/Worker pools, queue limits, attempts, payload IDs, and logs/)).not.toBeVisible();
    await user.click(within(pageProof).getByText("Show exact evidence"));
    expect(within(pageProof).getByText(/Worker pools, queue limits, attempts, payload IDs, and logs/)).toBeVisible();

    const pools = screen.getByText("Worker pools and queue limits").closest("details");
    const allWork = screen.getByText("All jobs and filters").closest("details");
    const rotations = screen.getByText("Rotation run records").closest("details");
    expect(pools).not.toHaveAttribute("open");
    expect(allWork).not.toHaveAttribute("open");
    expect(rotations).not.toHaveAttribute("open");

    await user.click(within(pools as HTMLElement).getByText("Worker pools and queue limits"));
    expect(await screen.findByText("outbox-connectors")).toBeVisible();
    expect(screen.getByText("8 queued-job limit")).toBeVisible();

    await user.click(within(allWork as HTMLElement).getByText("All jobs and filters"));
    expect(screen.getByLabelText("All jobs")).toBeVisible();
    expect(screen.getByRole("button", { name: "Review Rotate an identity" })).toBeVisible();

    await user.click(within(rotations as HTMLElement).getByText("Rotation run records"));
    expect(screen.getByRole("table", { name: "Rotation runs" })).toBeVisible();
  });

  it("marks an absent rollback reference as not recorded instead of silently hiding the evidence field", async () => {
    const user = userEvent.setup();
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [{ ...failedDelivery, rollback_ref: undefined }],
    });
    renderOperations();

    await user.click(await screen.findByRole("button", { name: "Review Deploy to GitHub Actions" }));
    const dialog = await screen.findByRole("dialog", { name: "Failed job: Deploy to GitHub Actions" });
    expect(within(dialog).getByText("Rollback reference", { exact: true })).toBeInTheDocument();
    expect(within(dialog).getByText("Not recorded", { exact: true })).toBeInTheDocument();
  });

  it("names a generic connector.deploy queue after its human target instead of repeating the machine action", async () => {
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [{ ...failedDelivery, destination: "connector.deploy", target: "github-actions/release" }],
    });
    renderOperations();

    expect(await screen.findByText("Deploy to GitHub Actions", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText("Deploy to Connector Deploy", { exact: true })).not.toBeInTheDocument();
  });

  it("turns a host-and-path target into a clean VPN name and keeps the mobile action short", async () => {
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          ...failedDelivery,
          connector: "manual",
          destination: "connector.deploy",
          target: "vpn-appliance-02:/etc/ssl/vpn.crt",
        },
      ],
    });
    renderOperations();

    expect(await screen.findByText("Deploy to VPN Appliance 02", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText("Deploy to Vpn Appliance 02:", { exact: true })).not.toBeInTheDocument();
    const review = screen.getByRole("button", { name: "Review Deploy to VPN Appliance 02" });
    expect(review).toHaveTextContent("Review");
    expect(review).not.toHaveTextContent("Review Deploy to VPN Appliance 02");
  });

  it("uses a responsive worklist instead of the clipped eight-column default table", async () => {
    renderOperations();

    const worklist = await screen.findByRole("list", { name: "Jobs needing attention" });
    expect(within(worklist).getByText("Deploy to GitHub Actions")).toBeInTheDocument();
    expect(within(worklist).getByText("Deployment failed after 3 attempts.")).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Operations queue" })).not.toBeInTheDocument();
    expect(screen.queryByTestId("data-grid-scroll-viewport")).not.toBeInTheDocument();
  });

  it("keeps an honest empty state and disables an action that has no failed job", async () => {
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
    apiMock.agentJobPosture.mockResolvedValue({
      served: true,
      generated_at: "2026-08-20T23:15:00Z",
      claimable_kinds: [],
      queues: [],
      redemptions: { live: 0, total: 0 },
      receipts: { verified: 0, rejected: 0 },
    });
    apiMock.bulkheadStats.mockResolvedValue({ served: true, pools: [] });

    renderOperations();

    expect(await screen.findByText("No failed or waiting jobs.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review failed job" })).toBeDisabled();
    expect(screen.getByText("Completed work and exact evidence are still available below.")).toBeInTheDocument();
  });

  it("does not call an unserved agent queue healthy", async () => {
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
    apiMock.agentJobPosture.mockResolvedValue({
      served: false,
      generated_at: "2026-08-20T23:15:00Z",
      claimable_kinds: [],
      queues: [],
      redemptions: { live: 0, total: 0 },
      receipts: { verified: 0, rejected: 0 },
    });

    renderOperations();

    expect(await screen.findByText("Agent queue status is unavailable; recent control-plane jobs are still shown.")).toBeInTheDocument();
    expect(screen.queryByText("No failed or waiting jobs.")).not.toBeInTheDocument();
  });

  it("does not claim there are no failures when job history returns 404", async () => {
    apiMock.rotationRuns.mockRejectedValue(new ApiError(404, "rotation history is not served"));
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
    apiMock.approvalRequests.mockResolvedValue([]);
    apiMock.agentJobPosture.mockResolvedValue({
      served: true,
      generated_at: "2026-08-20T23:15:00Z",
      claimable_kinds: [],
      queues: [],
      redemptions: { live: 0, total: 0 },
      receipts: { verified: 0, rejected: 0 },
    });

    renderOperations();

    expect(
      await screen.findByText("Recent job history is unavailable, so trstctl cannot confirm that nothing failed.", {}, { timeout: 3000 }),
    ).toBeInTheDocument();
    expect(screen.queryByText("No failed or waiting jobs.")).not.toBeInTheDocument();
    expect(screen.getByText("Operations unavailable")).toBeInTheDocument();
  });

  it("treats verification, rollback, and dry-run failures as failed jobs", async () => {
    const user = userEvent.setup();
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          ...failedDelivery,
          id: "37a7dd5f-7072-5157-b92c-1b603f73eca8",
          status: "verify_failed",
          reason: "deployed value did not match the expected fingerprint",
        },
      ],
    });

    renderOperations();

    expect(await screen.findByText("1 failed job needs review.")).toBeInTheDocument();
    expect(screen.getByText("Verification failed")).toBeInTheDocument();
    const primary = screen.getByRole("button", { name: "Review failed job" });
    expect(primary).toBeEnabled();
    await user.click(primary);
    const review = screen.getByRole("button", { name: "Review Deploy to GitHub Actions" });
    expect(review).toHaveFocus();
    await user.click(review);
    expect(await screen.findByRole("dialog", { name: "Failed job: Deploy to GitHub Actions" })).toBeInTheDocument();
  });
});
