import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import SecretSharingWorkflow from "@/pages/secrets/SecretSharingWorkflow";
import { ApiError } from "@/lib/api";

const { redeem } = vi.hoisted(() => ({ redeem: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, redeemShare: redeem } };
});

function openSharing() {
  render(
    <SecretSharingWorkflow
      approvalItems={[]}
      approvalBusyKey={null}
      canRetryApproval={() => false}
      onApprove={() => {}}
      onRetryApproval={() => {}}
      blocked={false}
    />,
  );
  return userEvent.setup();
}

describe("one-time share redemption recovery", () => {
  beforeEach(() => {
    redeem.mockReset();
    localStorage.clear();
    sessionStorage.clear();
  });
  afterEach(cleanup);

  it.each([new TypeError("response lost"), new ApiError(502, "upstream interrupted")])(
    "recovers the exact request after an ambiguous result: %s",
    async (error) => {
      redeem.mockRejectedValueOnce(error).mockResolvedValueOnce({ value: "recovered-fixture-value" });
      const user = openSharing();
      await user.type(screen.getByLabelText("Share token"), "fixture-share-token");
      await user.click(screen.getByRole("button", { name: "Redeem share" }));
      expect(redeem.mock.calls[0]?.[1]).toEqual(expect.any(String));
      expect(await screen.findByText(/The server may have consumed the share/)).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Retry same redemption" }));
      expect(await screen.findByText("recovered-fixture-value")).toBeInTheDocument();
      expect(redeem.mock.calls[1]).toEqual(redeem.mock.calls[0]);
      expect(localStorage.length).toBe(0);
      expect(sessionStorage.length).toBe(0);
    },
  );

  it("uses a new request when the token changes after an ambiguous result", async () => {
    redeem.mockRejectedValueOnce(new TypeError("response lost")).mockResolvedValueOnce({ value: "second-fixture-value" });
    const user = openSharing();
    const token = screen.getByLabelText("Share token");
    await user.type(token, "first-fixture-token");
    await user.click(screen.getByRole("button", { name: "Redeem share" }));
    await screen.findByText(/The server may have consumed the share/);
    await user.clear(token);
    await user.type(token, "second-fixture-token");
    expect(screen.queryByText(/The server may have consumed the share/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Redeem share" }));
    expect(await screen.findByText("second-fixture-value")).toBeInTheDocument();
    expect(redeem.mock.calls[1]?.[0]).toEqual({ token: "second-fixture-token" });
    expect(redeem.mock.calls[1]?.[1]).not.toBe(redeem.mock.calls[0]?.[1]);
  });

  it("keeps a definite refusal visible without offering ambiguous recovery", async () => {
    redeem.mockRejectedValue(new ApiError(404, JSON.stringify({ detail: "share not found or already consumed" })));
    const user = openSharing();
    await user.type(screen.getByLabelText("Share token"), "consumed-fixture-token");
    await user.click(screen.getByRole("button", { name: "Redeem share" }));
    expect(await screen.findByText("share not found or already consumed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry same redemption" })).not.toBeInTheDocument();
  });
});
