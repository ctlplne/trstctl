import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "@/lib/api";
import { DecoySecretWorkflow, decoyValue } from "@/pages/secrets/DecoySecretWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: { createSecret: vi.fn(), registerDecoySecret: vi.fn(), listDecoySecrets: vi.fn(), retireDecoySecret: vi.fn() },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const triggered = {
  id: "d1",
  kind: "secret",
  name: "payments db password bait",
  placement: "payments repo",
  secret_name: "prod/payments/db-password",
  state: "triggered",
  created_at: "2026-11-01T00:00:00Z",
  triggered_at: "2026-11-01T01:00:00Z",
  trigger_subject: "ci-runner-7",
};

describe("Q6 decoy secrets", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
    apiMock.listDecoySecrets.mockResolvedValue({ items: [triggered], next_cursor: "" });
  });

  it("generates realistic values that differ every time", () => {
    expect(decoyValue("password")).toMatch(/^[A-Za-z0-9]{24}$/);
    expect(decoyValue("api_key")).toMatch(/^key_[A-Za-z0-9]{40}$/);
    expect(decoyValue("connection_string")).toMatch(/^postgres:\/\/svc_[a-z0-9]{6}:[A-Za-z0-9]{24}@db-[a-z0-9]{4}\.internal:5432\/app$/);
    expect(decoyValue("password")).not.toBe(decoyValue("password"));
  });

  it("plants through the normal create path, then registers, and shows who read it first", async () => {
    apiMock.createSecret.mockResolvedValue({ name: "prod/billing/stripe-like-key" });
    apiMock.registerDecoySecret.mockResolvedValue({ ...triggered, id: "d2", state: "active" });
    const user = userEvent.setup();
    render(<DecoySecretWorkflow />);
    expect(await screen.findByText("First read by ci-runner-7 at", { exact: false })).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Secret path" }), "prod/billing/api-key");
    await user.selectOptions(screen.getByRole("combobox", { name: "Value shape" }), "api_key");
    await user.type(screen.getByRole("textbox", { name: "Label" }), "billing key bait");
    await user.type(screen.getByRole("textbox", { name: "Where you plant it" }), "wiki page");
    await user.click(screen.getByRole("button", { name: "Plant decoy secret" }));
    expect(apiMock.createSecret).toHaveBeenCalledWith({ name: "prod/billing/api-key", value: expect.stringMatching(/^key_/) });
    expect(apiMock.registerDecoySecret).toHaveBeenCalledWith({ secret_name: "prod/billing/api-key", name: "billing key bait", placement: "wiki page" });
  });

  it("never registers over a real secret and does not plant twice on retry", async () => {
    apiMock.createSecret.mockRejectedValueOnce(new ApiError(409, '{"detail":"exists"}'));
    const user = userEvent.setup();
    render(<DecoySecretWorkflow />);
    await user.type(screen.getByRole("textbox", { name: "Secret path" }), "prod/payments/api-key");
    await user.type(screen.getByRole("textbox", { name: "Label" }), "x");
    await user.type(screen.getByRole("textbox", { name: "Where you plant it" }), "y");
    await user.click(screen.getByRole("button", { name: "Plant decoy secret" }));
    // The list refresh that lands after the failure must not erase it.
    await screen.findByText("First read by ci-runner-7 at", { exact: false });
    expect(await screen.findByText(/a decoy never replaces a real secret/)).toBeInTheDocument();
    expect(apiMock.registerDecoySecret).not.toHaveBeenCalled();

    apiMock.createSecret.mockResolvedValueOnce({ name: "prod/new/bait" });
    apiMock.registerDecoySecret.mockRejectedValueOnce(new Error("network"));
    apiMock.registerDecoySecret.mockResolvedValueOnce({ ...triggered, id: "d3" });
    await user.clear(screen.getByRole("textbox", { name: "Secret path" }));
    await user.type(screen.getByRole("textbox", { name: "Secret path" }), "prod/new/bait");
    await user.click(screen.getByRole("button", { name: "Plant decoy secret" }));
    await user.click(screen.getByRole("button", { name: "Plant decoy secret" }));
    expect(apiMock.createSecret).toHaveBeenCalledTimes(2);
    expect(apiMock.registerDecoySecret).toHaveBeenCalledTimes(2);
  });

  it("is hidden from anyone who cannot plant decoys", () => {
    can.value = false;
    const { container } = render(<DecoySecretWorkflow />);
    expect(container).toBeEmptyDOMElement();
    expect(apiMock.listDecoySecrets).not.toHaveBeenCalled();
  });
});
