import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ApiError } from "@/lib/api";
import { TOTPSeedReplacePanel } from "@/pages/secrets/TOTPSeedReplacePanel";

const { replace } = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, replaceTOTPProviderSeed: replace } };
});

describe("TOTP provider seed replacement (A239-L5)", () => {
  afterEach(() => {
    cleanup();
    replace.mockReset();
  });

  it("sends the new seed and its current code, then says which version holds it", async () => {
    replace.mockResolvedValue({ name: "ops/break-glass-mfa", version: 2 });
    render(<TOTPSeedReplacePanel provider="mfa" />);
    const button = screen.getByRole("button", { name: "Replace seed" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/New seed/), { target: { value: "GEZDGNBVGY3TQOJQ" } });
    fireEvent.change(screen.getByLabelText(/Current code from the new seed/), { target: { value: "123456" } });
    fireEvent.click(button);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("mfa", { seed: "GEZDGNBVGY3TQOJQ", code: "123456" }));
    expect(await screen.findByText("The seed is now version 2 of ops/break-glass-mfa; the next lease's code comes from it.")).toBeInTheDocument();
    expect((screen.getByLabelText(/New seed/) as HTMLInputElement).value).toBe("");
    expect(screen.getByLabelText(/New seed/)).toHaveAttribute("type", "password");
  });

  it("shows the server's refusal and keeps the inputs", async () => {
    replace.mockRejectedValue(new ApiError(422, "the code is not the new seed's current code; check the seed and the authenticator's clock"));
    render(<TOTPSeedReplacePanel provider="mfa" />);
    fireEvent.change(screen.getByLabelText(/New seed/), { target: { value: "GEZDGNBVGY3TQOJQ" } });
    fireEvent.change(screen.getByLabelText(/Current code from the new seed/), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Replace seed" }));
    expect(await screen.findByText("The seed was not replaced")).toBeInTheDocument();
    expect(screen.getByText(/the code is not the new seed's current code/)).toBeInTheDocument();
    expect((screen.getByLabelText(/Current code from the new seed/) as HTMLInputElement).value).toBe("000000");
  });
});
