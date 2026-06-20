import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { ApiError } from "@/lib/api";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    profiles: vi.fn(),
    identities: vi.fn(),
    createIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

const activeProfile = {
  id: "prof-1",
  name: "web-server",
  version: 2,
  active: true,
  created_by: "ra@example.test",
  spec: { max_validity: "2160h", allowed_ekus: ["serverAuth"] },
};

describe("self-service credential requests", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.profiles.mockResolvedValue([activeProfile]);
    apiMock.identities.mockResolvedValue([]);
  });

  it("routes to a focused requester portal, submits a profile-bound request, and tracks accepted status", async () => {
    const requested = {
      id: "req-1",
      tenant_id: "t1",
      name: "payments-api",
      kind: "x509_certificate",
      owner_id: "dev-1",
      status: "requested",
      created_at: "2026-06-20T04:00:00Z",
      attributes: {
        requester: "dev@example.test",
        profile_name: "web-server",
        profile_version: 2,
        approvals: "0/2",
        purpose: "staging TLS",
      },
    };
    apiMock.createIdentity.mockResolvedValue(requested);
    const user = userEvent.setup();
    renderAt("/request");

    expect(await screen.findByRole("heading", { name: "Request a credential" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Request credential/i })).toHaveAttribute("href", "/request");
    await waitFor(() => expect(screen.getByLabelText("Profile")).toHaveDisplayValue("web-server v2 active"));
    expect(screen.getByLabelText("Owner id")).toHaveValue("dev-1");

    await user.type(screen.getByLabelText("Credential name"), "payments-api");
    await user.type(screen.getByLabelText("Business purpose"), "staging TLS");
    await user.click(screen.getByRole("button", { name: "Submit request" }));

    await waitFor(() =>
      expect(apiMock.createIdentity).toHaveBeenCalledWith({
        kind: "x509_certificate",
        name: "payments-api",
        owner_id: "dev-1",
        attributes: {
          requester: "dev@example.test",
          profile_name: "web-server",
          profile_version: 2,
          purpose: "staging TLS",
        },
      }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Request accepted for payments-api. It is awaiting approval; no certificate has been minted yet.",
    );
    expect(screen.getByRole("row", { name: /payments-api.*Awaiting approval 0 of 2.*requested/i })).toBeInTheDocument();
    expect(screen.queryByText(/has been issued/i)).not.toBeInTheDocument();
  });

  it("lists only the current requester's items with honest request status", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "mine-1",
        tenant_id: "t1",
        name: "checkout-api",
        kind: "x509_certificate",
        owner_id: "dev-1",
        status: "requested",
        attributes: { requester: "dev@example.test", profile_name: "web-server", profile_version: 2, approvals: "1/2" },
      },
      {
        id: "mine-2",
        tenant_id: "t1",
        name: "billing-api",
        kind: "x509_certificate",
        owner_id: "dev-1",
        status: "issued",
        attributes: { requester: "dev@example.test", profile_name: "web-server", profile_version: 2, approvals: "2/2" },
      },
      {
        id: "other-1",
        tenant_id: "t1",
        name: "other-team",
        kind: "x509_certificate",
        owner_id: "owner-2",
        status: "requested",
        attributes: { requester: "other@example.test", profile_name: "web-server", approvals: "0/2" },
      },
    ]);

    renderAt("/request");

    expect(await screen.findByRole("row", { name: /checkout-api.*Awaiting approval 1 of 2/i })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /billing-api.*Issued/i })).toBeInTheDocument();
    expect(screen.queryByText("other-team")).not.toBeInTheDocument();
  });

  it("covers empty and problem states without exposing the operator identity table", async () => {
    apiMock.profiles.mockResolvedValueOnce([]);
    const empty = renderAt("/request");
    expect(await screen.findByText("No active profiles")).toBeInTheDocument();
    expect(await screen.findByText("No requests yet")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Identities" })).not.toBeInTheDocument();
    empty.unmount();

    apiMock.profiles.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "profile store unavailable" })));
    apiMock.identities.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "identity list unavailable" })));
    renderAt("/request");

    expect(await screen.findByText("profile store unavailable")).toBeInTheDocument();
    expect(await screen.findByText("identity list unavailable")).toBeInTheDocument();
  });

  it("keeps the requester portal accessible", async () => {
    const { container } = renderAt("/request");
    await screen.findByRole("heading", { name: "Request a credential" });
    await waitFor(() => expect(screen.getByLabelText("Profile")).toHaveDisplayValue("web-server v2 active"));
    expect(await axe(container)).toHaveNoViolations();
  });
});
