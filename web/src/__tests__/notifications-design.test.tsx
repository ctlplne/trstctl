import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { messages } from "@/i18n/messages";
import { Notifications } from "@/pages/Notifications";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    notifications: vi.fn(),
    notification: vi.fn(),
    notificationChannels: vi.fn(),
    createNotificationChannel: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    notificationRoutingPreview: vi.fn(),
    createNotificationRoutingPolicy: vi.fn(),
    testNotificationChannel: vi.fn(),
    markNotificationRead: vi.fn(),
    requeueNotification: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const catalog = [
  { id: "email", label: "Email", category: "smtp", configured: false, delivery: "notification.* outbox fanout" },
  { id: "slack", label: "Slack", category: "chat", configured: false, delivery: "notification.* outbox fanout" },
  { id: "msteams", label: "Microsoft Teams", category: "chat", configured: false, delivery: "notification.* outbox fanout" },
  { id: "sms", label: "SMS", category: "mobile", configured: false, delivery: "notification.* outbox fanout" },
  { id: "siem", label: "SIEM", category: "security", configured: false, delivery: "notification.* outbox fanout" },
  { id: "pagerduty", label: "PagerDuty", category: "incident", configured: false, delivery: "notification.* outbox fanout" },
  { id: "opsgenie", label: "OpsGenie", category: "incident", configured: false, delivery: "notification.* outbox fanout" },
  { id: "webhook", label: "Webhook", category: "webhook", configured: false, delivery: "notification.* outbox fanout" },
];

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

describe("Global Alert Center", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.notifications.mockResolvedValue({ items: [] });
    apiMock.notificationChannels.mockResolvedValue({ items: catalog });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
    apiMock.notificationRoutingPreview.mockResolvedValue({
      resolution_order: ["asset", "owner", "workspace", "global"],
      // A stale or partially upgraded server may still encode empty slices as
      // null. The console must degrade to an empty answer, not lose the page.
      effective_channels: null,
      missing_channels: null,
      delivery_ready: false,
      explanation: "No automatic rule matches this asset.",
    });
    apiMock.createNotificationChannel.mockResolvedValue({
      id: "webhook",
      channel_type: "webhook",
      label: "Partner webhook",
      category: "webhook",
      configured: true,
      enabled: true,
      delivery: "tenant-authored notification.* outbox fanout",
      description: "Generic webhook",
      source: "tenant",
      endpoint_configured: true,
      credential_ref: "redacted",
      secret_handling: "credential reference redacted",
    });
  });

  it("makes the five operator jobs first-class and keeps a blank tenant honest", async () => {
    const user = userEvent.setup();
    renderNotifications();
    expect(await screen.findByRole("heading", { level: 1, name: "Alerts and delivery" })).toBeInTheDocument();
    expect(messages["nav.item.notifications"].defaultMessage).toBe("Alerts and delivery");
    const tabs = screen.getByRole("tablist", { name: "Alert Center views" });
    for (const name of ["Needs attention", "Delivery failures", "History", "Routing policies", "Channels & test"])
      expect(within(tabs).getByRole("tab", { name })).toBeInTheDocument();
    expect(within(tabs).getByRole("tab", { name: "Needs attention" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("heading", { name: "Nothing urgent right now" })).toBeInTheDocument();
    expect(screen.getByText(/informational events stay in History/i)).toBeInTheDocument();

    await user.click(within(tabs).getByRole("tab", { name: "Routing policies" }));
    expect(screen.getByText(/asset, then owner, then workspace, then global/i)).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Create routing rule" })).toBeInTheDocument();
    expect(screen.getByLabelText("Rule level")).toHaveValue("workspace");
    expect(screen.getByLabelText("Workspace")).toHaveValue("certificate-lifecycle");
    // A blank tenant cannot manufacture a ready automatic route. The exact
    // draft review stays disabled until at least one configured channel is
    // selected, and no effective-route preview is issued as a substitute.
    expect(screen.getByRole("button", { name: "Review exact route" })).toBeDisabled();
    expect(apiMock.notificationRoutingPreview).not.toHaveBeenCalled();

    await user.click(within(tabs).getByRole("tab", { name: "Channels & test" }));
    expect(screen.getByText(/browser never calls the destination directly/i)).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Queue a safe delivery test" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Queue test" })).toBeDisabled();
  });

  it("groups meaningful risk while informational unread events remain history-only", async () => {
    apiMock.notificationChannels.mockResolvedValue({
      items: catalog.map((channel) => (channel.id === "slack" ? { ...channel, configured: true, enabled: true } : channel)),
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "route-critical",
          tenant_id: "t1",
          name: "Critical events",
          scope_kind: "workspace",
          scope_ref: "certificate-lifecycle",
          channels_by_severity: { critical: ["slack"] },
          default_channels: ["slack"],
          digest_interval_seconds: 3600,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 3600, timezone: "UTC", next_run_at: "2026-08-25T00:00:00Z" },
          created_at: "2026-08-21T00:00:00Z",
          updated_at: "2026-08-21T00:00:00Z",
        },
      ],
    });
    apiMock.notifications.mockResolvedValue({
      items: [
        {
          id: "dead-1",
          tenant_id: "t1",
          destination: "notification.slack",
          kind: "certificate.expiring",
          certificate_id: "cert-payments",
          subject: "payments-api",
          detail: "Checkout TLS expires soon.",
          severity: "critical",
          owner_name: "Platform SRE",
          not_after: "2026-08-25T00:00:00Z",
          status: "dead",
          attempts: 10,
          last_error: "HTTP 503",
          created_at: "2026-08-21T00:00:00Z",
        },
        {
          id: "duplicate-warning",
          tenant_id: "t1",
          destination: "notification.slack",
          kind: "certificate.expiring",
          certificate_id: "cert-payments",
          subject: "payments-api",
          severity: "warning",
          status: "pending",
          attempts: 0,
          created_at: "2026-08-20T00:00:00Z",
        },
        {
          id: "info-1",
          tenant_id: "t1",
          destination: "notification.audit",
          kind: "inventory.sync",
          subject: "inventory complete",
          severity: "informational",
          status: "pending",
          attempts: 0,
          created_at: "2026-08-21T00:00:00Z",
        },
      ],
    });
    const user = userEvent.setup();
    renderNotifications();
    expect(await screen.findByRole("heading", { name: "1 alert chains need attention" })).toBeInTheDocument();
    const alertHeading = screen.getByRole("heading", { level: 3, name: "payments-api" });
    expect(alertHeading.closest("article")).toHaveClass("min-w-0", "max-w-full");
    expect(alertHeading).toHaveClass("[overflow-wrap:anywhere]");
    expect(screen.getByText("Checkout TLS expires soon.")).toHaveClass("[overflow-wrap:anywhere]");
    expect(screen.getByText("Platform SRE")).toBeInTheDocument();
    expect(screen.getByText("Delivery stopped after retries")).toBeInTheDocument();
    expect(screen.queryByText("inventory complete")).not.toBeInTheDocument();
    expect(screen.queryByText("HTTP 503")).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Delivery failures (1)" }));
    expect(await screen.findByText("HTTP 503")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "History" }));
    expect(await screen.findByText("inventory complete")).toBeInTheDocument();
  });

  it("does not call a route ready when it points only to a missing channel", async () => {
    apiMock.notificationChannels.mockResolvedValue({
      items: catalog.map((channel) => (channel.id === "email" ? { ...channel, configured: true, enabled: true } : channel)),
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "route-missing",
          tenant_id: "t1",
          name: "Critical events",
          scope_kind: "global",
          channels_by_severity: { critical: ["slack"] },
          default_channels: ["slack"],
          digest_interval_seconds: 3600,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 3600, timezone: "UTC", next_run_at: "2026-08-25T00:00:00Z" },
          created_at: "2026-08-21T00:00:00Z",
          updated_at: "2026-08-21T00:00:00Z",
        },
      ],
    });
    renderNotifications();
    expect(await screen.findByRole("heading", { level: 2, name: "Routing rules do not reach a ready channel" })).toBeInTheDocument();
    expect(screen.getByText("No ready destination", { exact: true })).toBeInTheDocument();
  });

  it("fails honestly when the tenant-scoped read model cannot load", async () => {
    apiMock.notifications.mockRejectedValue(new Error("queue unavailable"));
    renderNotifications();
    expect(await screen.findByRole("heading", { level: 2, name: "Alert delivery state is unavailable" }, { timeout: 3_000 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add channel" })).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent(/queue unavailable/i);
    expect(screen.queryByText(/0 channels ready/i)).not.toBeInTheDocument();
  });
});
