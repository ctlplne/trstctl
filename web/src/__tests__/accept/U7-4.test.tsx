import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { issuers: vi.fn(), generateManagedKey: vi.fn(), rotateManagedKey: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.issuers.mockReset().mockResolvedValue([]);
  apiMock.generateManagedKey.mockReset().mockResolvedValue({ algorithm: "ECDSA-P256", key_id: "key-1", public_der: "DER", state: "active", version: 1 });
  apiMock.rotateManagedKey.mockReset().mockResolvedValue({ algorithm: "ECDSA-P256", key_id: "key-1", public_der: "DER2", state: "active", version: 2 });
});

describe("U7-4 ceremony + KMS custody console", () => {
  it("generates a managed key and rotates it through the served custody endpoints", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <CAHierarchy />
        </ToastProvider>
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: "Generate managed key" }));
    await waitFor(() => expect(apiMock.generateManagedKey).toHaveBeenCalled());

    const rotate = await screen.findByRole("button", { name: "Rotate key key-1" });
    await user.click(rotate);
    await waitFor(() => expect(apiMock.rotateManagedKey).toHaveBeenCalledWith("key-1"));
  });
});
