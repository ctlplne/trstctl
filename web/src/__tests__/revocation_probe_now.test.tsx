// SPDX-License-Identifier: BUSL-1.1

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const apiMock = vi.hoisted(() => ({ probeRevocationHealth: vi.fn() }));
const canMock = vi.hoisted(() => ({ value: true }));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => canMock.value }));

import { RevocationProbeNow } from "@/pages/certificates/RevocationProbeNow";

describe("RevocationProbeNow", () => {
  beforeEach(() => {
    apiMock.probeRevocationHealth.mockReset();
    canMock.value = true;
  });

  it("queues a fresh probe, and says when one this minute is already queued", async () => {
    apiMock.probeRevocationHealth
      .mockResolvedValueOnce({ queued: true, bucket: "manual:2026-10-25T08:30:00Z", guidance: "" })
      .mockResolvedValueOnce({ queued: false, bucket: "manual:2026-10-25T08:30:00Z", guidance: "" });
    const user = userEvent.setup();
    render(<RevocationProbeNow />);

    await user.click(screen.getByRole("button", { name: "Probe endpoints now" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/queued for the network relay/);
    expect(apiMock.probeRevocationHealth).toHaveBeenCalledWith(expect.any(String));

    await user.click(screen.getByRole("button", { name: "Probe endpoints now" }));
    expect(await screen.findByText(/already queued/)).toBeInTheDocument();
  });

  it("is not offered without certs:write", () => {
    canMock.value = false;
    render(<RevocationProbeNow />);
    expect(screen.queryByRole("button", { name: "Probe endpoints now" })).not.toBeInTheDocument();
  });
});
