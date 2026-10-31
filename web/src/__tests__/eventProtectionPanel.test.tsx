import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider } from "@/components/ToastProvider";
import { EventProtectionPanel } from "@/components/EventProtectionPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    eventProtectionStatus: vi.fn(),
    previewEventProtection: vi.fn(),
    enableEventProtection: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const notEnabled = {
  state: "not_enabled",
  registration_identity: "registration-1",
  custody_configured: true,
  legacy_events_readable: true,
  next_step: "Preview, then enable, with the retention window your policy requires.",
};

function plan(blockers: string[]) {
  return {
    capability: "event_protection",
    operation: "enable",
    ready: blockers.length === 0,
    effect_free: true,
    request_fingerprint: "fingerprint",
    required_permission: "privacy:write",
    normalized_request: { registration_identity: "registration-1", retention: "720h0m0s" },
    operation_id: "operation-1",
    custody_configured: true,
    blockers,
    warnings: ["Events recorded before the key is active stay readable; protection never rewrites them."],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["Appends one tenant.event_protection.requested control event naming the registration and retention."],
    execute_external_effects: [],
    recovery_steps: [],
    verification_steps: [],
  };
}

function renderPanel() {
  return render(
    <ToastProvider>
      <EventProtectionPanel />
    </ToastProvider>,
  );
}

describe("A233 event-field protection panel", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
  });

  it("loads only when opened, previews without writing, then enables the exact reviewed request", async () => {
    apiMock.eventProtectionStatus.mockResolvedValueOnce(notEnabled).mockResolvedValueOnce({
      ...notEnabled,
      state: "preparing",
      operation_id: "operation-1",
      retention: "720h0m0s",
      next_step: "A bounded worker is preparing the tenant key; writes are refused until it is active.",
    });
    apiMock.previewEventProtection.mockResolvedValue(plan([]));
    apiMock.enableEventProtection.mockResolvedValue({
      operation_id: "operation-1",
      registration_identity: "registration-1",
      retention: "720h0m0s",
      state: "preparing",
    });
    const user = userEvent.setup();
    renderPanel();
    expect(apiMock.eventProtectionStatus).not.toHaveBeenCalled();

    await user.click(screen.getByText("Event-field protection (crypto-shred)"));
    expect(await screen.findByText("Not enabled")).toBeInTheDocument();
    expect(screen.getByText("registration-1")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Retention window"), "720h");
    await user.click(screen.getByRole("button", { name: "Preview" }));
    expect(await screen.findByText("What enabling will do")).toBeInTheDocument();
    expect(apiMock.previewEventProtection).toHaveBeenCalledWith({ registration_identity: "registration-1", retention: "720h" });
    expect(apiMock.enableEventProtection).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Enable protection" }));
    await waitFor(() => expect(apiMock.enableEventProtection).toHaveBeenCalledWith({ registration_identity: "registration-1", retention: "720h" }));
    expect(await screen.findByText("Preparing the tenant key")).toBeInTheDocument();
    expect(apiMock.eventProtectionStatus).toHaveBeenCalledTimes(2);
  });

  it("keeps enable disabled while the preview names a blocker", async () => {
    apiMock.eventProtectionStatus.mockResolvedValue(notEnabled);
    apiMock.previewEventProtection.mockResolvedValue(plan(["custody_not_configured: an operator sets privacy.event_protection.key_directory"]));
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByText("Event-field protection (crypto-shred)"));
    await user.type(await screen.findByLabelText("Retention window"), "1h");
    await user.click(screen.getByRole("button", { name: "Preview" }));
    expect(await screen.findByText(/custody_not_configured/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enable protection" })).toBeDisabled();
    expect(apiMock.enableEventProtection).not.toHaveBeenCalled();
  });
});
