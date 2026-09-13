import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Notifications } from "@/pages/Notifications";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    notifications: vi.fn(),
    notificationChannels: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    createNotificationRoutingPolicy: vi.fn(),
    testNotificationChannel: vi.fn(),
    markNotificationRead: vi.fn(),
    requeueNotification: vi.fn(),
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

const pendingNotification = {
  id: "101",
  tenant_id: "t1",
  destination: "notification.email",
  kind: "certificate.expiring",
  certificate_id: "cert-pay",
  subject: "payments-api",
  detail: "Certificate expires in 7 days.",
  severity: "warning",
  owner_email: "payments-owner@example.test",
  owner_name: "Payments owners",
  escalation_recipients: [
    { kind: "owner", subject: "owner-pay", display_name: "Payments owners", email: "payments-owner@example.test" },
    { kind: "approver", subject: "ra-one@example.test", display_name: "RA One", email: "ra-one@example.test", roles: ["operator"] },
  ],
  status: "pending",
  attempts: 1,
  created_at: "2026-06-26T10:00:00Z",
};

const deadNotification = {
  id: "202",
  tenant_id: "t1",
  destination: "notification.webhook",
  kind: "webhook.delivery",
  subject: "billing-hook",
  detail: "Webhook failed after retries.",
  severity: "critical",
  status: "dead",
  attempts: 10,
  last_error: "POST 500",
  created_at: "2026-06-26T09:45:00Z",
};

function renderNotifications() {
  return render(
    <AppQueryProvider>
      <MemoryRouter>
        <ToastProvider>
          <Notifications />
        </ToastProvider>
      </MemoryRouter>
    </AppQueryProvider>,
  );
}

describe("C10-3 notifications inbox", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.notifications.mockResolvedValue({ items: [pendingNotification, deadNotification] });
    apiMock.notificationChannels.mockResolvedValue({
      items: [
        { id: "email", label: "Email", category: "smtp", configured: true, delivery: "notification.* outbox fanout" },
        { id: "slack", label: "Slack", category: "chat", configured: true, delivery: "notification.* outbox fanout" },
        { id: "msteams", label: "Microsoft Teams", category: "chat", configured: true, delivery: "notification.* outbox fanout" },
        { id: "sms", label: "SMS", category: "mobile", configured: true, delivery: "notification.* outbox fanout" },
        { id: "siem", label: "SIEM", category: "security", configured: true, delivery: "notification.* outbox fanout" },
      ],
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
    apiMock.createNotificationRoutingPolicy.mockResolvedValue({
      id: "policy-1",
      tenant_id: "t1",
      name: "Expiry escalation",
      scope_kind: "workspace",
      scope_ref: "certificate-lifecycle",
      channels_by_severity: { critical: ["slack"] },
      default_channels: ["email"],
      digest_interval_seconds: 86400,
      digest_timezone: "UTC",
      digest_preview: { interval_seconds: 86400, timezone: "UTC", next_run_at: "2026-06-27T10:00:00Z" },
      created_at: "2026-06-26T10:00:00Z",
      updated_at: "2026-06-26T10:00:00Z",
    });
    apiMock.testNotificationChannel.mockResolvedValue({
      channel_id: "slack",
      destination: "notification.test",
      outbox_id: 303,
      status: "queued",
      credential_ref: "redacted",
      secret_handling: "credential reference redacted",
      idempotency_key: "idem",
      queued_at: "2026-06-26T10:00:00Z",
    });
    apiMock.markNotificationRead.mockResolvedValue({ ...pendingNotification, status: "read", read_at: "2026-06-26T10:05:00Z" });
    apiMock.requeueNotification.mockResolvedValue({ ...deadNotification, status: "pending", attempts: 0, last_error: undefined });
  });

  it("lists notifications, triages dead letters, marks read, requeues, and emits toasts", async () => {
    const user = userEvent.setup();
    renderNotifications();

    expect(await screen.findByRole("heading", { name: "Alerts and delivery" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.notifications).toHaveBeenCalledWith({ limit: 100, cursor: undefined, order: "desc" }));
    await waitFor(() => expect(apiMock.notificationChannels).toHaveBeenCalled());
    await user.click(screen.getByRole("tab", { name: "Channels & test" }));
    expect(screen.getByText("Channel coverage")).toBeInTheDocument();
    expect(screen.getByText("5 configured")).toBeInTheDocument();
    for (const label of ["Email", "Slack", "Microsoft Teams", "SMS", "SIEM"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }

    await user.click(screen.getByRole("tab", { name: "History" }));
    expect(screen.getByText("1 unread")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Type filter" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Status filter" })).toBeInTheDocument();

    const inboxRow = (await screen.findByText("payments-api")).closest("tr")!;
    expect(within(inboxRow).getByText("certificate.expiring")).toBeInTheDocument();
    expect(within(inboxRow).getByText("Owner: payments-owner@example.test")).toBeInTheDocument();
    expect(within(inboxRow).getByText("Approvers: ra-one@example.test")).toBeInTheDocument();
    expect(within(inboxRow).getByText("1 / 10")).toBeInTheDocument();

    await user.click(within(inboxRow).getByRole("button", { name: "Mark notification 101 read" }));
    await waitFor(() => expect(apiMock.markNotificationRead).toHaveBeenCalledWith("101"));
    expect(await screen.findByRole("status", { name: "Notification marked read" })).toBeInTheDocument();
    expect(within(inboxRow).getByText("read")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Delivery failures (1)" }));
    const deadRow = await screen.findByText("billing-hook");
    const deadLetterRow = deadRow.closest("tr")!;
    expect(within(deadLetterRow).getByText("dead")).toBeInTheDocument();
    expect(within(deadLetterRow).getByText("10 / 10")).toBeInTheDocument();
    expect(within(deadLetterRow).getByText("POST 500")).toBeInTheDocument();

    await user.click(within(deadLetterRow).getByRole("button", { name: "Requeue notification 202" }));
    await waitFor(() => expect(apiMock.requeueNotification).toHaveBeenCalledWith("202"));
    expect(await screen.findByRole("status", { name: "Notification requeued" })).toBeInTheDocument();
  });
});
