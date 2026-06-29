import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider, beginLogin, useAuth } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import { ApiError, type Me } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    logout: vi.fn(),
    certificates: vi.fn(),
    certificatePage: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
    owners: vi.fn(),
    identities: vi.fn(),
    auditEvents: vi.fn(),
    risk: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
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

function AuthProbe() {
  const auth = useAuth();
  if (auth.loading) return <p role="status">loading</p>;
  if (auth.error) return <p role="alert">{auth.error}</p>;
  return <p>{auth.user?.subject ?? "anonymous"}</p>;
}

function sessionForRole(role: "viewer" | "auditor" | "ra-officer"): Me {
  const base = { subject: `${role}-1`, tenant_id: "t1", email: `${role}@example.test`, roles: [role] };
  switch (role) {
    case "viewer":
      return {
        ...base,
        permissions: [
          "owners:read",
          "issuers:read",
          "identities:read",
          "certs:read",
          "privacy:read",
          "graph:read",
          "risk:read",
          "agents:read",
          "discovery:read",
          "nhi:read",
          "notifications:read",
          "connectors:read",
          "lifecycle:read",
          "incidents:read",
          "access:read",
          "profiles:read",
          "secrets:read",
          "keys:read",
        ],
      };
    case "auditor":
      return { ...base, permissions: ["audit:read"] };
    case "ra-officer":
      return { ...base, permissions: ["profiles:read", "profiles:write", "certs:read", "certs:request"] };
  }
}

describe("auth + dashboards", () => {
  beforeEach(() => {
    apiMock.me.mockReset();
    apiMock.logout.mockReset();
    apiMock.certificates.mockReset();
    apiMock.certificatePage.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
    apiMock.identities.mockReset();
    apiMock.auditEvents.mockReset();
    apiMock.risk.mockReset();
    apiMock.certificates.mockResolvedValue([]);
    apiMock.logout.mockResolvedValue(undefined);
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.identities.mockResolvedValue([]);
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
  });

  it("redirects an unauthenticated visitor to the login page", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    apiMock.me.mockRejectedValue(new UnauthorizedError());

    renderAt("/");

    await waitFor(() => expect(screen.getByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument());
  });

  it("allows local dev preview without storing an auth token", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    apiMock.me.mockRejectedValue(new UnauthorizedError());
    const user = userEvent.setup();

    renderAt("/");

    await user.click(await screen.findByRole("button", { name: /Preview UI without backend/i }));

    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Backend-to-GUI coverage" })).not.toBeInTheDocument();
    expect(localStorage.getItem("token")).toBeNull();
    expect(sessionStorage.length).toBe(0);
  });

  it("surfaces non-auth session failures and can begin OIDC login", async () => {
    apiMock.me.mockRejectedValue(new Error("backend offline"));

    render(
      <AuthProvider>
        <AuthProbe />
      </AuthProvider>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Error: backend offline");

    const originalLocation = window.location;
    const assign = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...originalLocation, assign },
    });

    try {
      beginLogin();
      expect(assign).toHaveBeenCalledWith("/auth/login");
    } finally {
      Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
    }
  });

  it("shows the dashboard once authenticated", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([{ id: "c1", tenant_id: "t1", subject: "CN=svc", status: "active", fingerprint: "fp1" }]);
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "svc-approval", kind: "x509_certificate", status: "requested" },
      { id: "ret-1", name: "svc-retired", kind: "x509_certificate", status: "retired" },
    ]);
    apiMock.risk.mockResolvedValue([
      { credential_id: "c1", subject: "CN=svc", kind: "certificate", score: 92, exposure: 2, owner_active: false },
      { credential_id: "c2", subject: "CN=worker", kind: "certificate", score: 74, exposure: 1, owner_active: true },
    ]);

    renderAt("/");

    await waitFor(() => expect(screen.getByRole("heading", { name: "Dashboard" })).toBeInTheDocument());
    expect(screen.getByText("u@example.test")).toBeInTheDocument(); // the session principal

    const dash = screen.getByRole("region", { name: "Dashboard" });
    expect(within(dash).getByRole("link", { name: /Issue credential/i })).toHaveAttribute("href", "/request");
    expect(within(dash).getByText(/Identities \(NHI\)/)).toBeInTheDocument();
    expect(within(dash).getByText(/High-risk/)).toBeInTheDocument();
    expect(within(dash).getByText(/Issuance trend/)).toBeInTheDocument();
    expect(within(dash).getByText(/Algorithm mix/)).toBeInTheDocument();
    expect(within(dash).getByText(/Rotate first/)).toBeInTheDocument();
    // Rotate-first uses served risk data (highest score first).
    expect(await within(dash).findByText("CN=svc")).toBeInTheDocument();
    expect(apiMock.risk).toHaveBeenCalledWith({ sort: "score" });
  });

  it("signs out through the served logout endpoint and returns to login", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    const user = userEvent.setup();

    renderAt("/");

    expect(await screen.findByTestId("current-user")).toHaveTextContent("u@example.test");

    await user.click(screen.getByRole("button", { name: "Sign out" }));

    await waitFor(() => expect(apiMock.logout).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument();
    expect(screen.queryByTestId("current-user")).not.toBeInTheDocument();
  });

  it("sends a fresh, empty tenant to first-run setup instead of demo data", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    // certificates/identities/risk default to [] in beforeEach -> empty REAL tenant.
    // A brand-new authenticated tenant is routed to onboarding, not shown demo numbers.

    renderAt("/");

    const dash = await screen.findByRole("region", { name: "Dashboard" });
    expect(within(dash).getByText(/Welcome to trstctl/)).toBeInTheDocument();
    expect(within(dash).getByRole("link", { name: /Set up trstctl/ })).toBeInTheDocument();
    // No demo numbers for a real, empty tenant.
    expect(within(dash).queryByText(/Issuance trend/)).not.toBeInTheDocument();
  });

  it("renders the certificate inventory in a table", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1" });
    apiMock.certificatePage.mockResolvedValue({
      items: [
        { id: "c1", subject: "CN=payments.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" },
        { id: "c2", subject: "CN=web.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp2" },
      ],
    });

    renderAt("/certificates");

    await waitFor(() => expect(screen.getByText("CN=payments.example.com")).toBeInTheDocument());
    expect(screen.getByText("CN=web.example.com")).toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: undefined });
  });

  it("shapes navigation for viewer sessions without advertising privileged actions", async () => {
    apiMock.me.mockResolvedValue(sessionForRole("viewer"));
    apiMock.certificatePage.mockResolvedValue({ items: [] });

    renderAt("/certificates");

    expect(await screen.findByRole("heading", { name: "Certificates" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getByRole("link", { name: /Certificates/i })).toHaveAttribute("href", "/certificates");
    expect(within(nav).getByRole("link", { name: /Discovery/i })).toHaveAttribute("href", "/discovery");
    expect(within(nav).queryByRole("link", { name: /Request credential/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Approvals/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /^Audit$/i })).not.toBeInTheDocument();
  });

  it("shapes navigation for auditor sessions around audit evidence only", async () => {
    apiMock.me.mockResolvedValue(sessionForRole("auditor"));
    apiMock.auditEvents.mockResolvedValue([]);

    renderAt("/audit");

    expect(await screen.findByRole("heading", { name: "Audit" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getByRole("link", { name: /^Audit$/i })).toHaveAttribute("href", "/audit");
    expect(within(nav).queryByRole("link", { name: /Certificates/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Discovery/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Request credential/i })).not.toBeInTheDocument();
  });

  it("shapes RA officer navigation and command actions around certificate requests", async () => {
    apiMock.me.mockResolvedValue(sessionForRole("ra-officer"));
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    const user = userEvent.setup();

    renderAt("/certificates");

    expect(await screen.findByRole("heading", { name: "Certificates" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getByRole("link", { name: /Request credential/i })).toHaveAttribute("href", "/request");
    expect(within(nav).getByRole("link", { name: /Certificates/i })).toHaveAttribute("href", "/certificates");
    expect(within(nav).queryByRole("link", { name: /Discovery/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /^Audit$/i })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Open command palette/i }));
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    expect(within(dialog).getByRole("button", { name: /Issue credential/i })).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /Run discovery scan/i })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /Connect issuer/i })).not.toBeInTheDocument();
  });

  it("keeps backend 403 handling for direct denied routes", async () => {
    apiMock.me.mockResolvedValue(sessionForRole("viewer"));
    apiMock.auditEvents.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: "missing audit:read" })));

    renderAt("/audit");

    expect(await screen.findByText("Your session cannot read tenant audit evidence.")).toBeInTheDocument();
    expect(apiMock.auditEvents).toHaveBeenCalledWith({ limit: 50 });
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).queryByRole("link", { name: /^Audit$/i })).not.toBeInTheDocument();
  });

  it("lands the certificate inventory on an expiry-filtered worklist from the URL", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1" });
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", tenant_id: "t1", subject: "CN=soon.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
    });

    renderAt("/certificates?expiry=30d");

    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: expect.any(String) }));
    expect(await screen.findByText("CN=soon.example.com")).toBeInTheDocument();
  });
});
