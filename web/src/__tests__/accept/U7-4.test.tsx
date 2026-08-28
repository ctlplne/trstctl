import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { issuers: vi.fn(), managedKeyCustody: vi.fn(), previewManagedKeyGeneration: vi.fn(), generateManagedKey: vi.fn(), rotateManagedKey: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.issuers.mockReset().mockResolvedValue([]);
  apiMock.managedKeyCustody.mockReset().mockResolvedValue({
    enabled: true,
    lifecycle_attached: true,
    ready: true,
    configured_provider: "aws",
    configuration_mode: "startup_static",
    secret_delivery: "file_reference_only",
    restart_required: false,
    security_boundary: "AWS retains the private key.",
    blockers: [],
    providers: [{ id: "aws", label: "AWS KMS", custody: "AWS retains the private key.", requirements: [] }],
  });
  apiMock.previewManagedKeyGeneration.mockReset().mockResolvedValue({
    ready: true,
    effect_free: true,
    provider: "aws",
    provider_label: "AWS KMS",
    algorithm: "ECDSA-P256",
    configuration_mode: "startup_static",
    restart_required: false,
    extractable: false,
    private_key_location: "AWS KMS",
    required_permission: "keys:write",
    approval_required: false,
    requirements: [],
    preview_writes: [],
    preview_external_effects: [],
    execution_writes: ["One tenant-scoped managed-key event."],
    execution_external_effects: ["One durable signer command."],
    proof: ["Public-key fingerprint"],
    blockers: [],
  });
  apiMock.generateManagedKey.mockReset().mockResolvedValue({ algorithm: "ECDSA-P256", key_id: "key-1", public_der: "DER", state: "active", version: 1 });
  apiMock.rotateManagedKey.mockReset().mockResolvedValue({ algorithm: "ECDSA-P256", key_id: "key-1", public_der: "DER2", state: "active", version: 2 });
});

describe("U7-4 ceremony + KMS custody console", () => {
  it("generates a managed key and rotates it through the served custody endpoints", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/ca-hierarchy?tab=custody"]}>
        <ToastProvider>
          <CAHierarchy />
        </ToastProvider>
      </MemoryRouter>,
    );
    await user.click(await screen.findByRole("button", { name: "Review generation plan" }));
    await user.click(await screen.findByRole("button", { name: "Continue to generation" }));
    await user.click(await screen.findByRole("button", { name: "Generate managed key" }));
    await waitFor(() => expect(apiMock.generateManagedKey).toHaveBeenCalled());

    const rotate = await screen.findByRole("button", { name: "Rotate key key-1" });
    await user.click(rotate);
    await waitFor(() => expect(apiMock.rotateManagedKey).toHaveBeenCalledWith("key-1"));
  });
});
