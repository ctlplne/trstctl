import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider, useAuth } from "@/auth/AuthProvider";
import { Login } from "@/pages/Login";
import { UnauthorizedError } from "@/lib/apiTransport";

const { bootstrapMock } = vi.hoisted(() => ({
  bootstrapMock: { me: vi.fn(), authMethods: vi.fn(), logout: vi.fn() },
}));
vi.mock("@/lib/bootstrapApi", async (orig) => ({
  ...(await orig<typeof import("@/lib/bootstrapApi")>()),
  bootstrapApi: bootstrapMock,
}));

function SessionOrLogin() {
  const auth = useAuth();
  if (auth.loading) return <p>Resolving fixture session</p>;
  if (auth.user)
    return (
      <>
        <p>{auth.user.subject}</p>
        <button onClick={() => void auth.logout()}>Fixture logout</button>
      </>
    );
  return <Login />;
}
const originalLocation = window.location;
const assign = vi.fn();
function renderLogin(entry = "/login") {
  render(
    <AuthProvider>
      <MemoryRouter initialEntries={[entry]}>
        <SessionOrLogin />
      </MemoryRouter>
    </AuthProvider>,
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "location", { configurable: true, value: { ...originalLocation, assign } });
  bootstrapMock.me.mockRejectedValue(new UnauthorizedError());
  bootstrapMock.authMethods.mockResolvedValue({ oidc: false, saml: false, ldap: false });
  bootstrapMock.logout.mockResolvedValue(undefined);
});
afterEach(() => {
  Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
});

describe("configured browser login methods", () => {
  it("starts SAML at the configured endpoint with the requested return target", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: false, saml: true, ldap: false });
    const query = new URLSearchParams({ return_to: "/certificates?expiry=30d#inventory" }).toString();
    renderLogin(`/login?${query}`);
    await userEvent.click(await screen.findByRole("button", { name: "Continue with SAML" }));
    expect(assign).toHaveBeenCalledWith(`/auth/saml/login?${query}`);
  });
  it("offers SAML when it is the only configured method", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: false, saml: true, ldap: false });
    renderLogin();
    expect(await screen.findByRole("button", { name: "Continue with SAML" })).toBeEnabled();
    expect(screen.queryByText("Browser sign-in is not configured")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue with SSO" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Directory username")).not.toBeInTheDocument();
  });
  it("offers an accessible directory form when LDAP is the only configured method", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: false, saml: false, ldap: true });
    renderLogin();
    expect(await screen.findByLabelText("Directory username")).toHaveAttribute("autocomplete", "username");
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");
    expect(screen.getByLabelText("Password")).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByRole("button", { name: "Sign in with LDAP" })).toBeEnabled();
    expect(screen.queryByText("Browser sign-in is not configured")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue with SSO" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue with SAML" })).not.toBeInTheDocument();
  });
  it("keeps all enabled methods available in a mixed configuration", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: true, saml: true, ldap: true });
    renderLogin();
    expect(await screen.findByRole("button", { name: "Continue with SAML" })).toBeEnabled();
    expect(await screen.findByLabelText("Directory username")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Continue with SSO" })).toBeEnabled();
  });
  it("shows configuration guidance and no real login actions when all methods are disabled", async () => {
    renderLogin();
    expect(await screen.findByText("Browser sign-in is not configured")).toBeInTheDocument();
    for (const name of ["Continue with SSO", "Continue with SAML", "Sign in with LDAP"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    expect(screen.queryByLabelText("Directory username")).not.toBeInTheDocument();
  });
  it("does not evict a valid session when public method discovery fails", async () => {
    bootstrapMock.authMethods.mockRejectedValue(new Error("fixture discovery unavailable"));
    bootstrapMock.me.mockResolvedValue({ subject: "fixture-operator", tenant_id: "fixture-tenant", roles: ["admin"], permissions: ["*"] });
    renderLogin();
    expect(await screen.findByText("fixture-operator")).toBeInTheDocument();
    expect(screen.queryByText("Browser sign-in is not configured")).not.toBeInTheDocument();
    expect(bootstrapMock.logout).not.toHaveBeenCalled();
  });
  it("preserves SAML and LDAP choices after a real session logout", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: false, saml: true, ldap: true });
    bootstrapMock.me.mockResolvedValue({ subject: "fixture-operator", tenant_id: "fixture-tenant", roles: ["admin"], permissions: ["*"] });
    renderLogin();
    await userEvent.click(await screen.findByRole("button", { name: "Fixture logout" }));
    expect(bootstrapMock.logout).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("button", { name: "Continue with SAML" })).toBeEnabled();
    expect(await screen.findByLabelText("Directory username")).toBeEnabled();
    expect(screen.queryByText("Browser sign-in is not configured")).not.toBeInTheDocument();
  });
});
