import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    certificates: vi.fn(),
    certificatePage: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
    owners: vi.fn(),
    identities: vi.fn(),
    auditEvents: vi.fn(),
    risk: vi.fn(),
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

describe("auth + dashboards", () => {
  beforeEach(() => {
    apiMock.me.mockReset();
    apiMock.certificates.mockReset();
    apiMock.certificatePage.mockReset();
    apiMock.getCertificate.mockReset();
    apiMock.ingestCertificate.mockReset();
    apiMock.identities.mockReset();
    apiMock.auditEvents.mockReset();
    apiMock.risk.mockReset();
    apiMock.certificates.mockResolvedValue([]);
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.identities.mockResolvedValue([]);
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
  });

  it("redirects an unauthenticated visitor to the login page", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    apiMock.me.mockRejectedValue(new UnauthorizedError());

    renderAt("/");

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument(),
    );
  });

  it("allows local dev preview without storing an auth token", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    apiMock.me.mockRejectedValue(new UnauthorizedError());
    const user = userEvent.setup();

    renderAt("/");

    await user.click(await screen.findByRole("button", { name: /Preview UI without backend/i }));

    expect(await screen.findByRole("heading", { name: "Backend-to-GUI coverage" })).toBeInTheDocument();
    expect(screen.getAllByTestId("feature-row")).toHaveLength(78);
    expect(localStorage.getItem("token")).toBeNull();
    expect(sessionStorage.length).toBe(0);
  });

  it("shows the action-first dashboard once authenticated", async () => {
    const soon = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([{ id: "c1", tenant_id: "t1", subject: "CN=svc", status: "active", fingerprint: "fp1" }]);
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", tenant_id: "t1", subject: "CN=svc", status: "active", fingerprint: "fp1", not_after: soon }],
    });
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "svc-approval", kind: "x509_certificate", status: "requested" },
      { id: "ret-1", name: "svc-retired", kind: "x509_certificate", status: "retired" },
    ]);
    apiMock.risk.mockResolvedValue([
      { credential_id: "c1", subject: "CN=svc", kind: "certificate", score: 92, exposure: 2, owner_active: false },
      { credential_id: "c2", subject: "CN=worker", kind: "certificate", score: 74, exposure: 1, owner_active: true },
    ]);
    apiMock.auditEvents.mockResolvedValue([
      { sequence: 1, type: "identity.issued", tenant_id: "t1", time: "2026-06-18T12:00:00Z" },
      { sequence: 2, type: "identity.renewed", tenant_id: "t1", time: "2026-06-18T13:00:00Z" },
      { sequence: 3, type: "identity.revoked", tenant_id: "t1", time: "2026-06-18T14:00:00Z" },
    ]);

    renderAt("/");

    await waitFor(() => expect(screen.getByRole("heading", { name: /Overview/i })).toBeInTheDocument());
    expect(screen.getByText("u@example.test")).toBeInTheDocument(); // the session principal
    const triage = await screen.findByRole("region", { name: /Operator triage/i });
    const quickActions = screen.getByRole("region", { name: "Quick actions" });

    expect(within(quickActions).getByRole("link", { name: "Issue or request credential" })).toHaveAttribute("href", "/request");
    expect(within(quickActions).getByRole("link", { name: "Open approvals" })).toHaveAttribute("href", "/approvals");
    expect(within(quickActions).getByRole("link", { name: "Export audit evidence" })).toHaveAttribute("href", "/audit");
    expect(within(triage).queryByText(/GUI coverage/i)).not.toBeInTheDocument();
    expect(within(triage).getByRole("link", { name: /Review 1 expiring soon certificate/i })).toHaveAttribute(
      "href",
      "/certificates?expiry=30d",
    );
    expect(within(triage).getByRole("link", { name: /Review 1 pending approval/i })).toHaveAttribute(
      "href",
      "/approvals",
    );
    expect(within(triage).getByRole("link", { name: /Review 2 high-risk credentials/i })).toHaveAttribute(
      "href",
      "/risk?sort=score",
    );
    expect(within(triage).getByRole("link", { name: /Review 1 orphaned credential/i })).toHaveAttribute(
      "href",
      "/risk?q=orphaned",
    );
    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 50, expiringBefore: expect.any(String) }),
    );
    expect(apiMock.risk).toHaveBeenCalledWith({ sort: "score" });
    expect(within(triage).getByText("Delivery status not served")).toBeInTheDocument();
    expect(within(triage).getByText(/FE-PTR-OUTBOX/)).toBeInTheDocument();
    expect(within(triage).queryByText(/failed deliveries: \d/i)).not.toBeInTheDocument();
    expect(apiMock.auditEvents).toHaveBeenCalledWith({ limit: 200 });
    const trend = screen.getByRole("region", { name: "Lifecycle trend" });
    expect(within(trend).getByText(/Issued 1, renewed 1, revoked 1/)).toBeInTheDocument();
    expect(within(trend).getByRole("img", { name: /Lifecycle trend chart: issued 1, renewed 1, revoked 1/i })).toBeInTheDocument();
  });

  it("renders an empty lifecycle trend from an empty served audit window", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.auditEvents.mockResolvedValue([]);

    renderAt("/");

    const trend = await screen.findByRole("region", { name: "Lifecycle trend" });
    expect(within(trend).getByText("No lifecycle events in the served audit window.")).toBeInTheDocument();
    expect(within(trend).getByRole("img", { name: /Lifecycle trend chart: issued 0, renewed 0, revoked 0/i })).toBeInTheDocument();
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

  it("lands the certificate inventory on an expiry-filtered worklist from the URL", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1" });
    apiMock.certificatePage.mockResolvedValue({
      items: [
        { id: "c1", tenant_id: "t1", subject: "CN=soon.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" },
      ],
    });

    renderAt("/certificates?expiry=30d");

    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: expect.any(String) }),
    );
    expect(await screen.findByText("CN=soon.example.com")).toBeInTheDocument();
  });
});
