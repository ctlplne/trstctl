import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Notifications } from "@/pages/Notifications";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    notifications: vi.fn(),
    notificationChannels: vi.fn(),
    createNotificationChannel: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    createNotificationRoutingPolicy: vi.fn(),
    testNotificationChannel: vi.fn(),
    markNotificationRead: vi.fn(),
    requeueNotification: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const createdPolicy = {
  id: "11111111-1111-1111-1111-111111111111",
  tenant_id: "t1",
  name: "Expiry escalation",
  channels_by_severity: { critical: ["slack", "webhook"], warning: ["slack"], low: ["email"] },
  default_channels: ["webhook"],
  owner_ref: "team/platform-security",
  owner_email: "platform-security@example.test",
  digest_interval_seconds: 43200,
  digest_timezone: "UTC",
  digest_preview: { interval_seconds: 43200, timezone: "UTC", next_run_at: "2026-06-27T10:00:00Z" },
  created_at: "2026-06-26T10:00:00Z",
  updated_at: "2026-06-26T10:00:00Z",
};

function renderNotifications() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <Notifications />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("DESIGN-003 notification routing authoring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.notifications.mockResolvedValue({ items: [] });
    apiMock.notificationChannels.mockResolvedValue({
      items: [
        { id: "slack", label: "Slack", category: "chat", configured: true, delivery: "notification.* outbox fanout" },
        { id: "webhook", label: "Webhook", category: "webhook", configured: true, delivery: "notification.* outbox fanout" },
        { id: "email", label: "Email", category: "smtp", configured: true, delivery: "notification.* outbox fanout" },
      ],
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
    apiMock.createNotificationChannel.mockResolvedValue({
      id: "webhook",
      channel_type: "webhook",
      label: "Tenant webhook",
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
    apiMock.createNotificationRoutingPolicy.mockResolvedValue(createdPolicy);
    apiMock.testNotificationChannel
      .mockResolvedValueOnce({
        channel_id: "slack",
        destination: "notification.test",
        outbox_id: 8801,
        status: "queued",
        credential_ref: "redacted",
        secret_handling: "credential reference redacted",
        idempotency_key: "idem-slack",
        queued_at: "2026-06-26T10:00:00Z",
      })
      .mockResolvedValueOnce({
        channel_id: "webhook",
        destination: "notification.test",
        outbox_id: 8802,
        status: "queued",
        credential_ref: "redacted",
        secret_handling: "credential reference redacted",
        idempotency_key: "idem-webhook",
        queued_at: "2026-06-26T10:01:00Z",
      });
  });

  it("creates a routing policy, shows it, and queues redacted Slack and webhook tests", async () => {
    const user = userEvent.setup();
    renderNotifications();

    expect(await screen.findByRole("heading", { name: "Channel authoring" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Endpoint URL"), "https://hooks.example.test/trstctl");
    await user.type(screen.getByLabelText("Channel credential reference"), "secret://notifications/webhook/hmac-key");
    await user.click(screen.getByRole("button", { name: /Save channel/ }));
    await waitFor(() => expect(apiMock.createNotificationChannel).toHaveBeenCalled());
    expect(apiMock.createNotificationChannel).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "webhook",
        channel_type: "webhook",
        endpoint_url: "https://hooks.example.test/trstctl",
        credential_ref: "secret://notifications/webhook/hmac-key",
        enabled: true,
      }),
    );
    expect(screen.queryByText("secret://notifications/webhook/hmac-key")).not.toBeInTheDocument();

    expect(await screen.findByRole("heading", { name: "Routing policies" })).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Owner email"));
    await user.type(screen.getByLabelText("Owner email"), "platform-security@example.test");
    await user.selectOptions(screen.getByLabelText("Digest interval"), "43200");
    await user.clear(screen.getByLabelText("Default channels"));
    await user.type(screen.getByLabelText("Default channels"), "webhook");

    await user.click(screen.getByRole("button", { name: /Save policy/ }));
    await waitFor(() => expect(apiMock.createNotificationRoutingPolicy).toHaveBeenCalled());
    expect(apiMock.createNotificationRoutingPolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Expiry escalation",
        owner_email: "platform-security@example.test",
        digest_interval_seconds: 43200,
        default_channels: ["webhook"],
        channels_by_severity: expect.objectContaining({ critical: ["slack", "webhook"], warning: ["slack"] }),
      }),
    );
    expect(await screen.findByText(/platform-security@example\.test/)).toBeInTheDocument();
    expect(screen.getByText(/slack, webhook/)).toBeInTheDocument();

    const credential = screen.getByLabelText("Credential reference");
    await user.selectOptions(screen.getByLabelText("Channel"), "slack");
    await user.type(credential, "secret://notifications/slack/raw-webhook-url");
    await user.click(screen.getByRole("button", { name: /Queue test/ }));
    await waitFor(() =>
      expect(apiMock.testNotificationChannel).toHaveBeenCalledWith(
        "slack",
        expect.objectContaining({ credential_ref: "secret://notifications/slack/raw-webhook-url" }),
      ),
    );
    expect(screen.queryByText("secret://notifications/slack/raw-webhook-url")).not.toBeInTheDocument();
    expect(await screen.findByText("slack #8801 - redacted")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Channel"), "webhook");
    await user.clear(credential);
    await user.type(credential, "secret://notifications/webhook/hmac-key");
    await user.click(screen.getByRole("button", { name: /Queue test/ }));
    await waitFor(() =>
      expect(apiMock.testNotificationChannel).toHaveBeenLastCalledWith(
        "webhook",
        expect.objectContaining({ credential_ref: "secret://notifications/webhook/hmac-key" }),
      ),
    );
    expect(screen.queryByText("secret://notifications/webhook/hmac-key")).not.toBeInTheDocument();
    expect(await screen.findByText("webhook #8802 - redacted")).toBeInTheDocument();
  });
});
