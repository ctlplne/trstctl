import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider, beginLogin, useAuth } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import { ToastProvider } from "@/components/ToastProvider";
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
    contextualRiskPriorities: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    secretPage: vi.fn(),
    incidentExecutions: vi.fn(),
    transitionIdentity: vi.fn(),
    endpointVerifications: vi.fn(),
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
        <ToastProvider>
          <MemoryRouter initialEntries={[path]}>
            <AppRoutes />
          </MemoryRouter>
        </ToastProvider>
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

function PreviewRaceProbe() {
  const auth = useAuth();
  return (
    <>
      <button type="button" onClick={auth.startPreview}>
        Start preview
      </button>
      <p>{auth.user?.subject ?? (auth.loading ? "loading" : "anonymous")}</p>
    </>
  );
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

function contextualRiskFixture(critical: number, high: number) {
  const urgent = critical + high;
  return {
    capability: "CAP-POST-05",
    generated_at: "2026-08-13T15:00:00Z",
    coverage: ["credential_risk_scores", "contextual_priorities"],
    summary: {
      total_analyzed: urgent,
      priorities: urgent,
      critical,
      high,
      medium: 0,
      low: 0,
      high_blast_radius: 0,
      weak_crypto_context: 0,
      orphaned: 0,
      near_expiry: 0,
      recommendations: urgent,
    },
    urgent_summary: {
      status: "complete",
      scope: "All served credential-risk and contextual-priority projections for this tenant; totals deduplicate credential_id.",
      included_projections: ["credential_risk_scores", "contextual_priorities"],
      unique_analyzed: urgent,
      urgent,
      critical,
      high,
      credential_risk: { analyzed: 0, critical: 0, high: 0 },
      contextual_priorities: { analyzed: urgent, critical, high },
    },
    priorities: [],
  };
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
    apiMock.contextualRiskPriorities.mockReset();
    apiMock.certificates.mockResolvedValue([]);
    apiMock.logout.mockResolvedValue(undefined);
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.identities.mockResolvedValue([]);
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
    apiMock.contextualRiskPriorities.mockResolvedValue(contextualRiskFixture(0, 0));
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    // D2: nothing observed by default, so the verified tile stays absent.
    apiMock.endpointVerifications.mockReset();
    apiMock.endpointVerifications.mockResolvedValue({
      items: [],
      summary: { endpoints: 0, verified: 0, diverged: 0, unreachable: 0, verified_percent: 0 },
      guidance: "",
    });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
    apiMock.secretPage.mockResolvedValue({ items: [] });
    apiMock.incidentExecutions.mockResolvedValue({ items: [] });
    apiMock.transitionIdentity.mockReset();
    apiMock.transitionIdentity.mockResolvedValue({ id: "i1", name: "renewed", kind: "x509_certificate", status: "renewing" });
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
    expect(screen.getByTestId("preview-read-only-banner")).toHaveTextContent(
      "Read-only sample workspace. Changes are disabled and nothing leaves this browser.",
    );
    expect(screen.queryByRole("heading", { name: "Backend-to-GUI coverage" })).not.toBeInTheDocument();
    expect(localStorage.getItem("token")).toBeNull();
    expect(sessionStorage.length).toBe(0);

    await user.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument();
    expect(apiMock.logout).not.toHaveBeenCalled();
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

  it("does not let a late session response replace an explicitly started preview", async () => {
    let resolveSession: ((user: Me) => void) | undefined;
    apiMock.me.mockReturnValue(
      new Promise<Me>((resolve) => {
        resolveSession = resolve;
      }),
    );
    const user = userEvent.setup();

    render(
      <AuthProvider>
        <PreviewRaceProbe />
      </AuthProvider>,
    );

    await user.click(screen.getByRole("button", { name: "Start preview" }));
    expect(screen.getByText("dev-preview")).toBeInTheDocument();

    await act(async () => {
      resolveSession?.({ subject: "late-session", tenant_id: "t1", email: "late@example.test" });
      await Promise.resolve();
    });
    expect(screen.getByText("dev-preview")).toBeInTheDocument();
    expect(screen.queryByText("late-session")).not.toBeInTheDocument();
  });

  it("shows the dashboard once authenticated", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
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
    expect(within(dash).getByText(/Urgent risk/)).toBeInTheDocument();
    // Real mode shows the served daily issuance chart, never the demo monthly trend (S-N0 / DA-01).
    expect(within(dash).getByText(/Issuance rate/)).toBeInTheDocument();
    expect(within(dash).queryByText(/Issuance trend/)).not.toBeInTheDocument();
    expect(within(dash).getByText(/Algorithm mix/)).toBeInTheDocument();
    expect(within(dash).getByText(/Rotate first/)).toBeInTheDocument();
    // Rotate-first uses served risk data (highest score first).
    expect(await within(dash).findByText("CN=svc")).toBeInTheDocument();
    expect(apiMock.risk).toHaveBeenCalledWith({ sort: "score" });
  });

  it("signs out through the served logout endpoint and returns to login", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    const user = userEvent.setup();

    renderAt("/");

    expect(await screen.findByTestId("current-user")).toHaveTextContent("u@example.test");

    await user.click(screen.getByRole("button", { name: "Sign out" }));

    await waitFor(() => expect(apiMock.logout).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("button", { name: /Sign in with SSO/i })).toBeInTheDocument();
    expect(screen.queryByTestId("current-user")).not.toBeInTheDocument();
  });

  it("keeps the authenticated shell mounted and reports a failed served logout", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.logout.mockRejectedValue(new Error("logout offline"));
    const user = userEvent.setup();

    renderAt("/");

    await user.click(await screen.findByRole("button", { name: "Sign out" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Sign-out failed");
    expect(screen.getByTestId("current-user")).toHaveTextContent("u@example.test");
    expect(screen.getByRole("button", { name: "Sign out" })).toBeEnabled();
  });

  it("sends a fresh, empty tenant to first-run setup instead of demo data", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    // certificates/identities/risk default to [] in beforeEach -> empty REAL tenant.
    // A brand-new authenticated tenant is routed to onboarding, not shown demo numbers.

    renderAt("/");

    const dash = await screen.findByRole("region", { name: "Dashboard" });
    // First data-dependent read is a findBy (web/DESIGN.md S-C3): react-query
    // delivers results on a macrotask, so the header region appears before the
    // gate settles — awaiting the CTA is the settle point.
    expect(await within(dash).findByText(/Welcome to trstctl/)).toBeInTheDocument();
    expect(within(dash).getByRole("link", { name: /Set up trstctl/ })).toBeInTheDocument();
    // No demo numbers for a real, empty tenant.
    expect(within(dash).queryByText(/Issuance trend/)).not.toBeInTheDocument();
  });

  it("renders the certificate inventory in a table", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1" });
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
    // S-C1: Discovery lives in the Posture & response space — for a viewer the
    // rail advertises that space, while privileged rows stay hidden.
    const rail = screen.getByRole("navigation", { name: /Spaces/i });
    expect(within(rail).getByRole("button", { name: "Posture & response" })).toBeInTheDocument();
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

  // ---------------------------------------------------------------- S-N0 ----
  // Dashboard integrity: no fabricated demo values in real mode; the four
  // action KPIs are wired to served data (02-findings DA-01 / DA-12 / DA-28).

  function dayFromNow(days: number): string {
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  }

  function seededTenant() {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([
      { id: "c1", tenant_id: "t1", subject: "CN=soon", status: "active", fingerprint: "f1", key_algorithm: "RSA-2048", not_after: dayFromNow(3) },
      { id: "c2", tenant_id: "t1", subject: "CN=later", status: "active", fingerprint: "f2", key_algorithm: "ECDSA P-256", not_after: dayFromNow(20) },
      { id: "c3", tenant_id: "t1", subject: "CN=pqc", status: "active", fingerprint: "f3", key_algorithm: "ML-DSA-65", not_after: dayFromNow(120) },
    ]);
    apiMock.identities.mockResolvedValue([{ id: "i1", name: "svc", kind: "x509_certificate", status: "issued" }]);
    apiMock.risk.mockResolvedValue([
      { credential_id: "c1", subject: "CN=soon", kind: "certificate", score: 92, exposure: 2, owner_active: false },
      { credential_id: "c2", subject: "CN=later", kind: "certificate", score: 20, exposure: 1, owner_active: true },
    ]);
    apiMock.contextualRiskPriorities.mockResolvedValue(contextualRiskFixture(1, 0));
    apiMock.secretPage.mockResolvedValue({ items: [{ name: "demo/a" }, { name: "demo/b" }] });
    apiMock.incidentExecutions.mockResolvedValue({
      items: [
        { id: "x1", status: "executing", phase: "scope" },
        { id: "x2", status: "completed", phase: "done" },
      ],
    });
    apiMock.auditEvents.mockResolvedValue([{ id: "e1", sequence: 1, tenant_id: "t1", type: "identity.transition", time: dayFromNow(0) }]);
  }

  function kpiTile(dash: HTMLElement, label: RegExp): HTMLElement {
    const labelNode = within(dash).getByText(label);
    const tile = labelNode.closest("a") ?? labelNode.closest("div.group");
    if (!tile) throw new Error(`no KPI tile container for ${label}`);
    return tile as HTMLElement;
  }

  it("wires the four action KPIs to served data in real mode (S-N0)", async () => {
    seededTenant();

    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });

    // Expiring ≤7d: exactly one fixture cert expires within 7 days.
    const expiring = kpiTile(dash, /Expiring ≤7d/);
    await waitFor(() => expect(within(expiring).getByText("1")).toBeInTheDocument());
    expect(expiring).toHaveAttribute("href", "/certificates?expiry=7d");

    // Canonical urgent risk: one deduplicated row across all projections.
    const urgentRisk = kpiTile(dash, /Urgent risk/);
    await waitFor(() => expect(within(urgentRisk).getByText("1")).toBeInTheDocument());

    // Open incidents: one non-completed execution, served.
    const incidents = kpiTile(dash, /Open incidents/);
    await waitFor(() => expect(within(incidents).getByText("1")).toBeInTheDocument());
    expect(incidents).toHaveAttribute("href", "/incidents");

    // Future-ready: one PQC-family key algorithm among served certs.
    const pqc = kpiTile(dash, /Future-ready/);
    await waitFor(() => expect(within(pqc).getByText("1")).toBeInTheDocument());

    // Secrets KPI comes from the served secret store, not a stub.
    const secrets = kpiTile(dash, /^Secrets$/);
    await waitFor(() => expect(within(secrets).getByText("2")).toBeInTheDocument());
  });

  it("AUD-67 reports contextual critical work when certificate risk is empty", async () => {
    apiMock.me.mockResolvedValue(sessionForRole("viewer"));
    apiMock.risk.mockResolvedValue([]);
    apiMock.contextualRiskPriorities.mockResolvedValue(contextualRiskFixture(3, 0));

    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });
    await waitFor(() => expect(apiMock.contextualRiskPriorities).toHaveBeenCalledTimes(1));
    const urgent = kpiTile(dash, /Urgent risk/);
    await waitFor(() => expect(within(urgent).getByText("3")).toBeInTheDocument());
    expect(within(urgent).getByText(/all risk projections/i)).toBeInTheDocument();
  });

  it("AUD-67 reports an unavailable urgent summary instead of a safe zero", async () => {
    apiMock.me.mockResolvedValue(sessionForRole("viewer"));
    apiMock.contextualRiskPriorities.mockRejectedValue(new Error("contextual projection failed"));

    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });
    const urgent = kpiTile(dash, /Urgent risk/);
    await waitFor(() => expect(within(urgent).getByText(/summary unavailable/i)).toBeInTheDocument(), { timeout: 3_000 });
    expect(within(urgent).getByText("—")).toBeInTheDocument();
    expect(within(urgent).queryByText("0")).not.toBeInTheDocument();
  });

  it("renders no fabricated demo markers in real mode (S-N0)", async () => {
    seededTenant();

    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });
    await within(dash).findByText(/Algorithm mix/);

    // Demo-dataset fingerprints from lib/demoData must not appear for a live tenant.
    expect(within(dash).queryByText(/97 this month/)).not.toBeInTheDocument();
    expect(within(dash).queryByText(/crt_8f21/)).not.toBeInTheDocument();
    expect(within(dash).queryByText(/1,033/)).not.toBeInTheDocument();
    expect(within(dash).queryByText(/Issuance trend/)).not.toBeInTheDocument();

    // Recent activity is the served audit stream.
    expect(await within(dash).findByText("identity.transition")).toBeInTheDocument();
    expect(apiMock.auditEvents).toHaveBeenCalledWith({ limit: 6 });
  });

  it("keeps the algorithm-mix donut internally consistent in real mode (S-N0)", async () => {
    seededTenant();

    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });
    await within(dash).findByText(/Algorithm mix/);

    // Legend entries come from served certs; center count equals their total (3).
    expect(await within(dash).findByText("RSA-2048")).toBeInTheDocument();
    expect(within(dash).getByText("ECDSA P-256")).toBeInTheDocument();
    expect(within(dash).getByText("ML-DSA-65")).toBeInTheDocument();
    // The demo legend's fabricated totals must be gone.
    expect(within(dash).queryByText("742")).not.toBeInTheDocument();
    expect(within(dash).queryByText("368")).not.toBeInTheDocument();
  });

  it("renders preview through the same populated read-model panels as a tenant (S-N0)", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    seededTenant();
    apiMock.me.mockRejectedValue(new UnauthorizedError());
    const user = userEvent.setup();

    renderAt("/");
    await user.click(await screen.findByRole("button", { name: /Preview UI without backend/i }));

    const dash = await screen.findByRole("region", { name: "Dashboard" });
    expect(await within(dash).findByText(/Non-human identity inventory/)).toBeInTheDocument();
    expect(within(dash).getByText(/Algorithm mix/)).toBeInTheDocument();
    expect(within(dash).queryByText(/Issuance trend/)).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------- C-D1 ----
  // 47-day readiness on the global home (07-closeout plan): the panel renders
  // from the certs + rotation runs the dashboard already fetches, and its
  // at-risk number is a door into the Certificates renewal-readiness tab.

  it("renders the 47-day readiness panel from served data on the global home (C-D1)", async () => {
    seededTenant();
    // c2 (f2) is rotation-managed; c1 (f1, expires in 3d) and c3 (f3, 120d)
    // are manual → auto 1/3 = 33%, manual-at-risk (≤47d) = c1 only.
    apiMock.rotationRuns.mockResolvedValue({
      items: [{ id: "r1", status: "succeeded", successor_fingerprint: "f2" }],
    });

    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });

    expect(await within(dash).findByText("47-day renewal readiness")).toBeInTheDocument();
    await waitFor(() => expect(within(dash).getByText("33%")).toBeInTheDocument());
    expect(within(dash).getByText(/1 manual certs expiring within 47 days/)).toBeInTheDocument();
    // The panel links into the certificates readiness tab (numbers are doors).
    const link = within(dash).getByRole("link", { name: /View in Certificates/ });
    expect(link).toHaveAttribute("href", "/certificates?tab=renewal");
  });

  it("renders served-shape readiness evidence in preview (C-D1)", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    seededTenant();
    apiMock.me.mockRejectedValue(new UnauthorizedError());
    const user = userEvent.setup();

    renderAt("/");
    await user.click(await screen.findByRole("button", { name: /Preview UI without backend/i }));

    const dash = await screen.findByRole("region", { name: "Dashboard" });
    expect(await within(dash).findByText("47-day renewal readiness")).toBeInTheDocument();
  });

  // ---------------------------------------------------------------- S-N1 ----
  // The expiring worklist must not dead-end: managed rows carry Renew wired to
  // the identity lifecycle transition; unmanaged rows degrade honestly
  // (02-findings DA-05, upgraded to Blocker in the 2026-07-13 live pass).

  it("offers Renew on managed certificate rows and starts the identity renewal (S-N1)", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1" });
    apiMock.certificatePage.mockResolvedValue({
      items: [
        { id: "c1", tenant_id: "t1", subject: "CN=payments-api.example.test", issuer: "CN=CA", status: "active", fingerprint: "f1" },
        { id: "c2", tenant_id: "t1", subject: "CN=orphan.example.test", issuer: "CN=orphan.example.test", status: "active", fingerprint: "f2" },
        { id: "c3", tenant_id: "t1", subject: "CN=gone.example.test", issuer: "CN=CA", status: "revoked", fingerprint: "f3" },
      ],
    });
    apiMock.identities.mockResolvedValue([
      { id: "id-1", name: "payments-api.example.test", kind: "x509_certificate", status: "deployed", owner_id: "o1", target_id: "t" },
    ]);
    const user = userEvent.setup();

    renderAt("/certificates");
    await screen.findByText("CN=payments-api.example.test");

    // Managed row: Renew is present and dispatches the lifecycle transition.
    const renew = await screen.findByRole("button", { name: /Renew payments-api\.example\.test/i });
    await user.click(renew);
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("id-1", "renewing", expect.stringContaining("certificate inventory")));

    // Unmanaged active row degrades honestly to a replace path, not silence.
    expect(screen.getByRole("link", { name: /Replace via request/i })).toHaveAttribute("href", "/request");

    // Revoked rows get no lifecycle affordance.
    expect(screen.queryByRole("button", { name: /Renew gone\.example\.test/i })).not.toBeInTheDocument();
  });

  it("lands the certificate inventory on an expiry-filtered worklist from the URL", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1" });
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", tenant_id: "t1", subject: "CN=soon.example.com", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
    });

    renderAt("/certificates?expiry=30d");

    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalledWith({ limit: 20, expiringBefore: expect.any(String) }));
    expect(await screen.findByText("CN=soon.example.com")).toBeInTheDocument();
  });

  // The verified tile is a percentage of OBSERVED endpoints, and it does not
  // appear at all until something has been observed (epic D2).
  //
  // "100%" over zero endpoints is the most misleading number this page could
  // show — an all-clear that nothing earned — and an estate nobody has probed
  // is exactly the estate most likely to have a listener quietly serving last
  // year's certificate.
  it("hides the verified tile until endpoints have actually been observed", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1" });
    apiMock.certificates.mockResolvedValue([
      { id: "c1", tenant_id: "t1", subject: "CN=api.example.test", issuer: "CN=CA", status: "active", fingerprint: "fp1" },
    ]);
    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });
    await waitFor(() => expect(apiMock.endpointVerifications).toHaveBeenCalled());
    expect(within(dash).queryByText(/endpoints verified/i)).toBeNull();
  });

  it("shows the verified percentage and leads with divergence once endpoints are observed", async () => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1" });
    // A non-empty tenant, so the dashboard renders its KPI row rather than the
    // first-run wizard.
    apiMock.certificates.mockResolvedValue([
      { id: "c1", tenant_id: "t1", subject: "CN=api.example.test", issuer: "CN=CA", status: "active", fingerprint: "fp1" },
    ]);
    apiMock.endpointVerifications.mockResolvedValue({
      items: [],
      summary: { endpoints: 4, verified: 3, diverged: 1, unreachable: 0, verified_percent: 75 },
      guidance: "",
    });
    renderAt("/");
    const dash = await screen.findByRole("region", { name: "Dashboard" });

    expect(await within(dash).findByText(/endpoints verified/i)).toBeInTheDocument();
    expect(within(dash).getByText("75")).toBeInTheDocument();
    // The divergence count is the subtitle, because one endpoint serving the
    // wrong certificate is the thing to act on — not the 75%.
    expect(within(dash).getByText("1 diverged")).toBeInTheDocument();
  });
});
