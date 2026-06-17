import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities } from "@/pages/Identities";
// The real ApiError class (the vi.mock below spreads the real module and only
// replaces `api`), used to simulate a 429 with a Retry-After hint (SURFACE-007).
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    issuers: vi.fn(),
    owners: vi.fn(),
    issueCertificate: vi.fn(),
    transitionIdentity: vi.fn(),
    approveIdentityAction: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderIdentities() {
  return render(
    <MemoryRouter>
      <Identities />
    </MemoryRouter>,
  );
}

describe("lifecycle actions from the UI", () => {
  beforeEach(() => {
    apiMock.issuers.mockReset().mockResolvedValue([{ id: "iss-1", kind: "x509_ca", name: "LE" }]);
    apiMock.owners.mockReset().mockResolvedValue([{ id: "own-1", kind: "workload", name: "team" }]);
    // Fixtures use `status` — the field the SERVED Identity contract (OpenAPI) carries
    // and that identityState() reads (SURFACE-005: the FE no longer guesses `state`).
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "new-1", name: "svc", status: "issued" });
    apiMock.transitionIdentity.mockReset().mockResolvedValue({ id: "x", name: "x", status: "x" });
    apiMock.approveIdentityAction.mockReset().mockResolvedValue({ resource: "req-1", action: "issue", approver: "ra", approvals: 1 });
    apiMock.identities.mockReset();
  });

  it("offers the state-appropriate action and calls the transition endpoint", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "requested-svc", status: "requested" },
      { id: "iss-1", name: "issued-svc", status: "issued" },
      { id: "dep-1", name: "deployed-svc", status: "deployed" },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    // A requested identity can be issued.
    const reqRow = (await screen.findByText("requested-svc")).closest("tr")!;
    await user.click(within(reqRow).getByRole("button", { name: /^issue$/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything()));

    // An issued identity can be deployed or revoked.
    const issRow = screen.getByText("issued-svc").closest("tr")!;
    await user.click(within(issRow).getByRole("button", { name: /deploy/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("iss-1", "deployed", expect.anything()));

    // A deployed identity can be renewed.
    const depRow = screen.getByText("deployed-svc").closest("tr")!;
    await user.click(within(depRow).getByRole("button", { name: /renew/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-1", "renewing", expect.anything()));
  });

  it("revokes an identity only after the user confirms (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "to-revoke", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("to-revoke")).closest("tr")!;
    // Clicking Revoke must NOT immediately call the destructive transition — it opens
    // a confirmation dialog that names the credential.
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    // The dialog names the credential (it appears in both the heading and the body).
    expect(within(dialog).getAllByText(/to-revoke/).length).toBeGreaterThan(0);
    expect(within(dialog).getByRole("heading")).toHaveTextContent(/revoke.*to-revoke/i);

    // Confirming runs the revoke.
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-9", "revoked", expect.anything()));
  });

  it("cancelling the confirmation does not revoke (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "keep-me", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("keep-me")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("surfaces a 429 rate-limit with a Retry-After hint (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "svc", status: "requested" }]);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(new ApiError(429, "rate limited", 12));
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("svc")).closest("tr")!;
    // Issue is non-destructive, so it runs without confirmation and hits the 429.
    await user.click(within(row).getByRole("button", { name: /^issue$/i }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/rate limited/i);
    expect(alert).toHaveTextContent(/12s/);
  });

  it("creates (issues) a new identity from the page", async () => {
    apiMock.identities.mockResolvedValue([]);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /issue certificate|new identity/i }));
    await user.type(screen.getByLabelText(/name/i), "svc");
    await user.click(screen.getByRole("button", { name: /create|issue/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith(expect.objectContaining({ name: "svc" })));
  });

  it("records a dual-control approval from the identity row", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "needs-approval", status: "requested" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("needs-approval")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /approve issue/i }));

    await waitFor(() => expect(apiMock.approveIdentityAction).toHaveBeenCalledWith("req-1", "issue"));
    expect(await screen.findByRole("status")).toHaveTextContent("issue approval recorded");
  });
});
