import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { GrantSecretVerification } from "@/pages/secrets/GrantSecretVerification";

const { read } = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, getSecretWithToken: read } };
});

describe("exact workload secret verification", () => {
  beforeEach(() => {
    read.mockReset();
  });
  afterEach(cleanup);

  it("refuses a response for a different secret without displaying its value", async () => {
    read.mockResolvedValue({ name: "demo/first", version: 1, value: "DO-NOT-RENDER" });
    render(<GrantSecretVerification token="fixture-bearer" secretNames={["demo/first", "qa/password"]} onDismiss={() => {}} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Secret to verify"), "qa/password");
    await user.click(screen.getByRole("button", { name: "Verify scoped read" }));
    expect(await screen.findByText(/The response named a different secret/)).toBeInTheDocument();
    expect(screen.queryByText(/Scoped read passed/)).not.toBeInTheDocument();
    expect(screen.queryByText("DO-NOT-RENDER")).not.toBeInTheDocument();
    expect(read).toHaveBeenCalledWith("qa/password", "fixture-bearer");
  });

  it("does not carry a pending result into a replacement credential", async () => {
    let finish!: (value: { name: string; value: string; version: number }) => void;
    read.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const props = { secretNames: ["qa/password"], onDismiss: () => {} };
    const view = render(<GrantSecretVerification {...props} token="first-fixture-bearer" />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Secret to verify"), "qa/password");
    await user.click(screen.getByRole("button", { name: "Verify scoped read" }));
    view.rerender(<GrantSecretVerification {...props} token="replacement-fixture-bearer" />);
    await act(async () => finish({ name: "qa/password", value: "DO-NOT-RENDER", version: 1 }));
    expect(screen.queryByText(/Scoped read passed/)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Secret to verify")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Verify scoped read" })).toBeDisabled();
  });
});
