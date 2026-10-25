// SPDX-License-Identifier: BUSL-1.1

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({
  controlPlaneKeygen: vi.fn(),
  putControlPlaneKeygen: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => true }));

import { ControlPlaneKeygenPanel } from "@/components/ControlPlaneKeygenPanel";

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ControlPlaneKeygenPanel />
    </QueryClientProvider>,
  );
}

describe("ControlPlaneKeygenPanel", () => {
  beforeEach(() => {
    apiMock.controlPlaneKeygen.mockReset();
    apiMock.putControlPlaneKeygen.mockReset();
  });

  it("shows who decided, what renewals depend on it, and changes it only with a reason", async () => {
    apiMock.controlPlaneKeygen.mockResolvedValue({
      decided: true,
      enabled: true,
      source: "operator",
      reason: "a legacy batch job still needs it",
      set_by: "alice@customer.test",
      set_at: "2026-10-25T03:00:00Z",
      control_plane_identities: 3,
      paths: ["identity issuance without a CSR"],
      guidance: "With control-plane key generation off, an identity issuance without a CSR is refused.",
    });
    apiMock.putControlPlaneKeygen.mockResolvedValue({ decided: true, enabled: false, control_plane_identities: 3, paths: [], guidance: "" });
    const user = userEvent.setup();
    renderPanel();

    expect(await screen.findByText(/On: the control plane may generate subject keys/)).toBeInTheDocument();
    expect(screen.getByText(/alice@customer.test/)).toBeInTheDocument();
    expect(screen.getByText(/3 active certificates have keys the control plane generated/)).toBeInTheDocument();
    const turnOff = screen.getByRole("button", { name: "Turn off" });
    expect(turnOff).toBeDisabled();
    await user.type(screen.getByLabelText("Reason for the change"), "every workload brings a CSR now");
    await user.click(turnOff);
    await waitFor(() =>
      expect(apiMock.putControlPlaneKeygen).toHaveBeenCalledWith({ enabled: false, reason: "every workload brings a CSR now" }, expect.any(String)),
    );
    expect(await screen.findByText("Control-plane key generation is off for this tenant.")).toBeInTheDocument();
  });

  it("says a tenant that predates the switch has not decided yet", async () => {
    apiMock.controlPlaneKeygen.mockResolvedValue({ decided: false, enabled: true, control_plane_identities: 0, paths: [], guidance: "" });
    renderPanel();
    expect(await screen.findByText(/Not decided yet/)).toBeInTheDocument();
  });
});
