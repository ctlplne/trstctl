import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { messages } from "@/i18n/messages";
import { Notifications } from "@/pages/Notifications";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    notifications: vi.fn(),
    notification: vi.fn(),
    notificationChannels: vi.fn(),
    createNotificationChannel: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
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
    <MemoryRouter>
      <ToastProvider>
        <Notifications />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("Route 034 alert delivery hierarchy", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.notifications.mockResolvedValue({ items: [] });
    apiMock.notificationChannels.mockResolvedValue({ items: catalog });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
    apiMock.createNotificationChannel.mockResolvedValue({
      id: "webhook",
      channel_type: "webhook",
      label: "Partner webhook",
      category: "webhook",
      configured: true,
      enabled: true,
      delivery: "tenant-authored notification.* outbox fanout",
      description: "Generic HMAC-signed webhook alert delivery",
      source: "tenant",
      endpoint_configured: true,
      credential_ref: "redacted",
      secret_handling: "credential reference redacted",
    });
  });

  it("answers who receives alerts before exposing authoring and delivery machinery", async () => {
    const user = userEvent.setup();
    renderNotifications();

    expect(await screen.findByRole("heading", { level: 1, name: "Alerts and delivery" })).toBeInTheDocument();
    expect(messages["nav.item.notifications"].defaultMessage).toBe("Alerts and delivery");
    expect(screen.getByText("Which events notify which people or systems.", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Routing rules, templates, delivery attempts, webhooks.", { exact: true })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 2, name: "No alert channel is ready" })).toBeInTheDocument();
    expect(screen.getByText(/no external person or system will receive them until you add a channel/i)).toBeInTheDocument();
    expect(screen.getByText("0 channels ready", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("0 routing rules", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("0 failed deliveries", { exact: true })).toBeInTheDocument();

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    expect(within(actions).getByRole("button", { name: "Add channel" })).toBeEnabled();
    expect(document.querySelectorAll("main input, main select, main textarea")).toHaveLength(0);
    expect(screen.queryByRole("form")).not.toBeInTheDocument();

    for (const title of ["Channels and webhooks", "Routing rules and templates", "Delivery attempts and dead letters"]) {
      expect(screen.getByText(title, { exact: true }).closest("details")).not.toHaveAttribute("open");
    }
    expect(screen.queryByText("Channel coverage")).not.toBeInTheDocument();
    expect(screen.queryByText("Routing policies")).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Dead-letter" })).not.toBeInTheDocument();

    await user.click(screen.getByText("Routing rules and templates", { exact: true }));
    expect(await screen.findByRole("form", { name: "Create routing rule" })).toBeInTheDocument();
    expect(screen.getByLabelText("Policy name")).toHaveValue("");
    expect(screen.getByLabelText("Owner reference")).toHaveValue("");
    expect(screen.getByLabelText("Default channels")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();
    expect(screen.getByText("Add and enable a channel before saving a routing rule.", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /^No ready channels$/ })).toBeInTheDocument();
    await user.click(screen.getByText("Routing rules and templates", { exact: true }));

    await user.click(within(actions).getByRole("button", { name: "Add channel" }));
    const dialog = screen.getByRole("dialog", { name: "Add channel" });
    expect(within(dialog).getByRole("heading", { name: "Add channel" })).toHaveFocus();
    expect(within(dialog).getByText(/public HTTPS destination/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/credential reference, not the secret value/i)).toBeInTheDocument();
    const form = within(dialog).getByRole("form", { name: "Add notification channel" });
    await user.selectOptions(within(form).getByLabelText("Channel type"), "webhook");
    await user.type(within(form).getByLabelText("Display label"), "Partner webhook");
    await user.type(within(form).getByLabelText("Endpoint URL"), "https://alerts.example.test/trstctl");
    await user.type(within(form).getByLabelText("Channel credential reference"), "secret://notifications/webhook/hmac-key");
    await user.click(within(form).getByRole("button", { name: "Save channel" }));

    await waitFor(() =>
      expect(apiMock.createNotificationChannel).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "webhook",
          endpoint_url: "https://alerts.example.test/trstctl",
          credential_ref: "secret://notifications/webhook/hmac-key",
        }),
      ),
    );
    expect(screen.queryByRole("dialog", { name: "Add channel" })).not.toBeInTheDocument();
    expect(screen.queryByText("secret://notifications/webhook/hmac-key")).not.toBeInTheDocument();
    expect(await screen.findByText("1 channel ready", { exact: true })).toBeInTheDocument();

    await user.click(screen.getByText("Channels and webhooks", { exact: true }));
    expect(await screen.findByText("Channel coverage")).toBeInTheDocument();
    expect(screen.getAllByText("Partner webhook").length).toBeGreaterThan(0);

    await user.click(screen.getByText("Routing rules and templates", { exact: true }));
    expect(await screen.findByRole("form", { name: "Create routing rule" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Queue a safe delivery test" })).toBeInTheDocument();
    expect(screen.getByText(/one fixed alert envelope.*no tenant-editable template library/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Policy name")).toHaveValue("");
    expect(screen.getByLabelText("Owner reference")).toHaveValue("");
    expect(screen.getByLabelText("Default channels")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();
    expect(screen.getByText("Enter at least one ready channel ID from the list below.", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /^Partner webhook$/ })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Default channels"), "slack");
    expect(screen.getByText("Every channel ID must match a ready channel shown below.", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();
    await user.clear(screen.getByLabelText("Default channels"));
    await user.type(screen.getByLabelText("Default channels"), "webhook");
    await user.type(screen.getByLabelText("Policy name"), "Critical delivery");
    expect(screen.getByText("This rule can reach every destination entered below.", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeEnabled();

    await user.click(screen.getByText("Delivery attempts and dead letters", { exact: true }));
    expect(await screen.findByRole("tab", { name: "Dead-letter" })).toBeInTheDocument();
    expect(screen.getByText("No delivery attempts match", { exact: true })).toBeInTheDocument();
  });

  it("reports a failing delivery path without hiding the configured route", async () => {
    apiMock.notificationChannels.mockResolvedValue({
      items: catalog.map((channel) => (channel.id === "slack" ? { ...channel, configured: true, source: "tenant", enabled: true } : channel)),
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "route-critical",
          tenant_id: "t1",
          name: "Critical events",
          channels_by_severity: { critical: ["slack"] },
          default_channels: ["slack"],
          owner_email: "security@example.test",
          digest_interval_seconds: 3600,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 3600, timezone: "UTC", next_run_at: "2026-08-22T00:00:00Z" },
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
          subject: "payments-api",
          detail: "Delivery failed after retries.",
          severity: "critical",
          status: "dead",
          attempts: 10,
          last_error: "HTTP 503",
          created_at: "2026-08-21T00:00:00Z",
        },
      ],
    });
    renderNotifications();

    expect(await screen.findByRole("heading", { level: 2, name: "1 failed delivery needs attention" })).toBeInTheDocument();
    expect(screen.getByText("1 channel ready", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("1 routing rule", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("1 failed delivery", { exact: true })).toBeInTheDocument();
    expect(screen.getByText((_, element) => element?.textContent === "Critical events → Slack")).toBeInTheDocument();
    expect(screen.queryByText("HTTP 503")).not.toBeInTheDocument();
  });

  it("does not call a routing rule ready when it points only to a missing channel", async () => {
    apiMock.notificationChannels.mockResolvedValue({
      items: catalog.map((channel) => (channel.id === "email" ? { ...channel, configured: true, enabled: true } : channel)),
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "route-missing-slack",
          tenant_id: "t1",
          name: "Critical events",
          channels_by_severity: { critical: ["slack"] },
          default_channels: ["slack"],
          owner_ref: "team/security",
          digest_interval_seconds: 3600,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 3600, timezone: "UTC", next_run_at: "2026-08-22T00:00:00Z" },
          created_at: "2026-08-21T00:00:00Z",
          updated_at: "2026-08-21T00:00:00Z",
        },
      ],
    });
    renderNotifications();

    expect(await screen.findByRole("heading", { level: 2, name: "Routing rules do not reach a ready channel" })).toBeInTheDocument();
    expect(screen.getByText(/every referenced channel is missing or disabled/i)).toBeInTheDocument();
    expect(screen.getByText("No ready destination", { exact: true })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Alerts have a delivery path" })).not.toBeInTheDocument();
  });

  it("states that delivery truth is unknown when the read model cannot load", async () => {
    apiMock.notifications.mockRejectedValue(new Error("queue unavailable"));
    renderNotifications();

    expect(await screen.findByRole("heading", { level: 2, name: "Alert delivery state is unavailable" })).toBeInTheDocument();
    const action = screen.getByRole("button", { name: "Add channel" });
    expect(action).toBeDisabled();
    expect(action).toHaveAccessibleDescription(/reload delivery state before adding a channel/i);
    expect(screen.getByRole("alert")).toHaveTextContent(/queue unavailable/i);
    expect(screen.queryByText(/0 channels ready/i)).not.toBeInTheDocument();
  });
});
