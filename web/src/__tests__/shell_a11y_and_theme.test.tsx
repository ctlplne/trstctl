import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";
import { Platform } from "@/pages/Platform";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    certificates: vi.fn(),
    certificatePage: vi.fn(),
    identities: vi.fn(),
    owners: vi.fn(),
    risk: vi.fn(),
    secretPage: vi.fn(),
    accessRoles: vi.fn(),
    oidcMappingStatus: vi.fn(),
    members: vi.fn(),
    upsertMember: vi.fn(),
    offboardMember: vi.fn(),
    apiTokens: vi.fn(),
    createAPIToken: vi.fn(),
    revokeAPIToken: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderShell(initialEntries = ["/"]) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<h1>Overview</h1>} />
              <Route path="certificates" element={<h1>Certificates</h1>} />
              <Route path="identities" element={<h1>Identities</h1>} />
              <Route path="platform" element={<Platform />} />
              <Route path="secrets" element={<h1>Secrets</h1>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function resizeViewport(width: number) {
  Object.defineProperty(window, "innerWidth", {
    configurable: true,
    value: width,
    writable: true,
  });
  window.dispatchEvent(new Event("resize"));
}

describe("app shell accessibility and theme", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificatePage.mockResolvedValue({
      items: [
        {
          id: "cert-1",
          subject: "payments-api",
          fingerprint: "SHA256:abc123",
          status: "active",
          tenant_id: "t1",
        },
      ],
    });
    apiMock.identities.mockResolvedValue([
      {
        id: "id-1",
        kind: "workload_identity",
        name: "payments-worker",
        owner_id: "owner-1",
        status: "issued",
        tenant_id: "t1",
      },
    ]);
    apiMock.secretPage.mockResolvedValue({ items: [{ name: "payments/db/password", version: 3 }] });
    apiMock.accessRoles.mockResolvedValue({
      items: [
        { name: "operator", permissions: ["access:read", "access:write", "certs:issue"] },
        { name: "ra-officer", permissions: ["profiles:read", "profiles:write", "certs:request"] },
      ],
    });
    apiMock.oidcMappingStatus.mockResolvedValue({
      enabled: true,
      tenant_claim: "org",
      groups_claim: "groups",
      claim_is_tenant: false,
      allow_default_tenant: false,
      tenant_mappings: [{ group: "pki-approvers", tenant_id: "t1", roles: ["operator"] }],
    });
    apiMock.members.mockResolvedValue({
      items: [
        {
          tenant_id: "t1",
          subject: "issuer",
          roles: ["operator"],
          source: "manual",
          status: "active",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        {
          tenant_id: "t1",
          subject: "approver-one",
          roles: ["operator"],
          source: "manual",
          status: "offboarded",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-02T00:00:00Z",
          offboarded_at: "2026-01-02T00:00:00Z",
        },
      ],
    });
    apiMock.apiTokens.mockResolvedValue({
      items: [
        { id: "tok-1", tenant_id: "t1", subject: "issuer", scopes: ["identities:write", "certs:issue"], created_at: "2026-01-01T00:00:00Z" },
        {
          id: "tok-2",
          tenant_id: "t1",
          subject: "approver-one",
          scopes: ["certs:issue"],
          created_at: "2026-01-01T00:00:00Z",
          revoked_at: "2026-01-02T00:00:00Z",
        },
      ],
    });
    apiMock.upsertMember.mockResolvedValue({
      tenant_id: "t1",
      subject: "new-approver",
      roles: ["operator"],
      source: "manual",
      status: "active",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    });
    apiMock.offboardMember.mockResolvedValue({
      member: {
        tenant_id: "t1",
        subject: "approver-one",
        roles: ["operator"],
        source: "manual",
        status: "offboarded",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-02T00:00:00Z",
      },
      revoked_token_count: 1,
      rotation_evidence: "active API tokens for the offboarded subject were revoked",
    });
    apiMock.createAPIToken.mockResolvedValue({
      id: "tok-new",
      tenant_id: "t1",
      subject: "new-approver",
      scopes: ["certs:issue"],
      created_at: "2026-01-01T00:00:00Z",
      token: "trst_test_token",
    });
    apiMock.logout.mockReset();
    apiMock.logout.mockResolvedValue(undefined);
    document.documentElement.classList.remove("dark");
    localStorage.clear();
    resizeViewport(1024);
  });

  it("has no axe accessibility violations", async () => {
    const { container } = renderShell();
    await waitFor(() => screen.getByText("u@example.test"));
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("exposes navigation and main landmarks and a skip link", async () => {
    renderShell();
    await screen.findByText("u@example.test");
    expect(screen.getByRole("navigation", { name: /Primary/i })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Skip to main content/i })).toBeInTheDocument();
  });

  it("navigation links are keyboard reachable", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");
    await user.tab(); // skip link
    await user.tab(); // theme toggle
    const dashboardLink = screen.getByRole("link", { name: /Dashboard/i });
    dashboardLink.focus();
    expect(dashboardLink).toHaveFocus();
  });

  it("collapses primary navigation into a labeled mobile drawer", async () => {
    const user = userEvent.setup();
    resizeViewport(380);
    const { container } = renderShell();
    await screen.findByText("u@example.test");

    expect(screen.queryByRole("navigation", { name: /Primary/i })).not.toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveClass("min-w-0");
    const toggle = screen.getByRole("button", { name: "Open primary navigation" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const drawer = screen.getByRole("dialog", { name: "Primary navigation" });
    expect(within(drawer).getByRole("navigation", { name: /Primary/i })).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: /Dashboard/i })).toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: "Close primary navigation" })).toBeInTheDocument();
    expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(380);

    const results = await axe(container);
    expect(results).toHaveNoViolations();

    await user.click(within(drawer).getByRole("button", { name: "Close primary navigation" }));
    expect(screen.queryByRole("dialog", { name: "Primary navigation" })).not.toBeInTheDocument();
  });

  it("shows tenant context without a fake tenant switch", async () => {
    renderShell();
    await screen.findByText("u@example.test");

    const tenant = screen.getByLabelText("Tenant context");
    expect(tenant).toHaveTextContent("t1");
    expect(tenant).toHaveTextContent(/Tenant switching isn't available yet/i);
    expect(screen.getByRole("button", { name: /Tenant switching isn't available yet/i })).toBeDisabled();
  });

  it("keeps operators in the shell and announces served logout failures", async () => {
    const user = userEvent.setup();
    apiMock.logout.mockRejectedValueOnce(new Error("network down"));
    renderShell();
    await screen.findByText("u@example.test");

    const signOut = screen.getByRole("button", { name: "Sign out" });
    await user.click(signOut);

    expect(apiMock.logout).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("alert")).toHaveTextContent("Sign-out failed");
    expect(screen.getByRole("button", { name: "Sign out" })).toBeEnabled();
    expect(screen.getByText("u@example.test")).toBeInTheDocument();
  });

  it("opens the command palette from Cmd-K, searches inventory, and navigates on Enter", async () => {
    const user = userEvent.setup();
    const { container } = renderShell();
    await screen.findByText("u@example.test");

    fireEvent.keyDown(document, { key: "k", metaKey: true });

    let palette = await screen.findByRole("dialog", { name: "Command palette" });
    let search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });
    expect(search).toHaveFocus();
    await user.type(search, "payments");

    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalled());
    expect(within(palette).getByRole("button", { name: /payments-api.*Certificate/i })).toBeInTheDocument();
    expect(within(palette).getByRole("button", { name: /payments-worker.*Identity/i })).toBeInTheDocument();
    expect(within(palette).getByRole("button", { name: /payments\/db\/password.*Secret/i })).toBeInTheDocument();

    const close = within(palette).getByRole("button", { name: "Close command palette" });
    close.focus();
    await user.tab({ shift: true });
    const focusableButtons = within(palette).getAllByRole("button");
    expect(focusableButtons[focusableButtons.length - 1]).toHaveFocus();

    expect(await axe(container)).toHaveNoViolations();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open command palette" }));
    palette = await screen.findByRole("dialog", { name: "Command palette" });
    search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });
    await user.type(search, "platform");
    await user.keyboard("{Enter}");

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
  });

  it("opens the keyboard shortcuts overlay from ? and the help button", async () => {
    const user = userEvent.setup();
    const { container } = renderShell();
    await screen.findByText("u@example.test");

    await user.keyboard("?");

    let overlay = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(overlay).getByText("Open command palette")).toBeInTheDocument();
    expect(within(overlay).getByText("Show keyboard shortcuts")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Keyboard shortcuts" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open keyboard shortcuts" }));
    overlay = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(overlay).getByText("Close open overlay")).toBeInTheDocument();
  });

  it("exposes grouped non-certificate navigation domains", async () => {
    renderShell();
    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: /Primary/i });

    for (const group of [
      "Inventory & Discovery",
      "Issuance & CAs",
      "Protocols",
      "Secrets",
      "Connectors & Plugins",
      "Risk & Insight",
      "Incidents & JIT",
      "Governance",
      "Platform",
    ]) {
      expect(within(nav).getAllByText(group).length).toBeGreaterThan(0);
    }

    for (const link of ["Discovery", "SPIFFE", "Native secrets", "Connectors", "Incidents", "RBAC", "Platform"]) {
      expect(within(nav).getByRole("link", { name: new RegExp(link) })).toBeInTheDocument();
    }
  });

  it("exposes task worklists and full operate observe disclose nav treatments", async () => {
    renderShell();
    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: /Primary/i });
    const taskList = within(nav).getByRole("list", { name: "Needs action worklists" });

    expect(within(nav).getByText("Needs action")).toBeInTheDocument();
    expect(within(taskList).getByRole("link", { name: /Expiring soon.*30-day certificate worklist.*Operate/i })).toHaveAttribute(
      "href",
      "/certificates?expiry=30d",
    );
    expect(within(taskList).getByRole("link", { name: /Pending approvals.*dual-control issue and revoke inbox.*Operate/i })).toHaveAttribute(
      "href",
      "/approvals?status=pending",
    );
    expect(within(taskList).getByRole("link", { name: /Highest risk.*risk-prioritized rotation list.*Observe/i })).toHaveAttribute("href", "/risk?sort=score");

    expect(within(nav).getAllByText("Operate").length).toBeGreaterThan(0);
    expect(within(nav).getAllByText("Observe").length).toBeGreaterThan(0);
    expect(within(nav).getAllByText("Disclose").length).toBeGreaterThan(0);
    expect(within(nav).getByRole("link", { name: /RBAC.*Disclose/i })).toBeInTheDocument();
    expect(within(nav).queryByText(/^map$/i)).not.toBeInTheDocument();
  });

  it("routes to the platform posture page from grouped navigation", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");

    await user.click(screen.getByRole("link", { name: /^Platform\s+Observe$/i }));

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
    expect(screen.getByText(/Tenant boundary/i)).toBeInTheDocument();
    expect(screen.getByText(/Platform status endpoint not served yet/i)).toBeInTheDocument();
  });

  it("renders tenant context from the served session without an editable tenant input", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText("Tenant ID from session")).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByText("t1")).toBeInTheDocument();
    expect(screen.getByText(/browser never chooses a tenant id/i)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /tenant/i })).not.toBeInTheDocument();
  });

  it("shows served access administration and the required-scope map", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect((await screen.findAllByText("operator")).length).toBeGreaterThan(0);
    expect(screen.getByText("ra-officer")).toBeInTheDocument();
    expect(screen.getByText("pki-approvers")).toBeInTheDocument();
    expect(screen.getAllByText("approver-one").length).toBeGreaterThan(0);
    expect(screen.getAllByText("offboarded").length).toBeGreaterThan(0);
    expect(screen.getAllByText("revoked").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Offboard" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mint" })).toBeInTheDocument();
    expect(screen.getAllByText("access:write").length).toBeGreaterThan(0);
    expect(screen.getAllByText("certs:issue").length).toBeGreaterThan(0);
    expect(screen.getByText("graph:read")).toBeInTheDocument();
    expect(screen.getByText("secrets:write")).toBeInTheDocument();
    expect(screen.getAllByText("/platform").length).toBeGreaterThan(0);
    expect(screen.getByText(/without tenant existence details/i)).toBeInTheDocument();
  });

  it("renders the static API spec view and copies tokenless curl examples", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText(/47 served REST paths/i)).toBeInTheDocument();
    expect(screen.getByText("/api/v1/secrets/store/{name}")).toBeInTheDocument();
    expect(screen.getByText("/api/v1/graph/query")).toBeInTheDocument();
    expect(screen.getByText("Spec view")).toBeInTheDocument();
    expect(screen.getByText(/static spec view until a live `\/api\/v1\/openapi\.json` is published/i)).toBeInTheDocument();
    const firstCurl = screen.getAllByText(/^curl -X GET/)[0].textContent || "";
    expect(firstCurl).not.toMatch(/Authorization|Bearer|token/i);

    fireEvent.click(screen.getAllByRole("button", { name: "Copy curl" })[0]);

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(expect.stringMatching(/^curl -X GET https:\/\/trstctl\.example\.test\/api\/v1\/access\/roles$/));
    });
    expect(writeText.mock.calls[0][0]).not.toMatch(/Authorization|Bearer|token/i);
    expect(screen.getByText("Copied without token material.")).toBeInTheDocument();
  });

  it("shows honest auth and transport status without exposing key material", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText(/Plaintext local preview/i)).toBeInTheDocument();
    expect(screen.getByText(/No private cert\/key bytes are exposed/i)).toBeInTheDocument();
    expect(screen.getByText(/OIDC mapping status and API-token administration/i)).toBeInTheDocument();
    expect(screen.getByText(/browser session and CSRF posture/i)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE/)).not.toBeInTheDocument();
  });

  it("renders token-safe CLI companion commands that match served command groups", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByRole("heading", { name: "CLI companion" })).toBeInTheDocument();
    expect(screen.getByText("trstctl-cli certificates list --limit 50 --format json")).toBeInTheDocument();
    expect(screen.getByText("trstctl-cli audit export --limit 500 --output audit-evidence.jws")).toBeInTheDocument();
    expect(screen.getByText("trstctl-cli graph blast-radius cert:payments-api --format json")).toBeInTheDocument();
    expect(screen.getByText("trstctl-cli agents enroll-token --format json")).toBeInTheDocument();
    expect(document.body.textContent).toMatch(/TRSTCTL_TOKEN.*already set in the shell/i);
    expect(document.body.textContent).not.toMatch(/Authorization: Bearer|trst_[A-Za-z0-9]/);
  });

  it("renders runtime, plugin, and passive federation disclosures without live platform actions", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByRole("heading", { name: "Single-binary runtime" })).toBeInTheDocument();
    expect(screen.getByText("Runtime status JSON not served yet")).toBeInTheDocument();
    expect(screen.getByText(/signer child supervision aren't shown in the console yet/i)).toBeInTheDocument();
    expect(screen.getByText("Signer supervision")).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Plugin SDK and capability sandbox" })).toBeInTheDocument();
    expect(screen.getByText("connector-f5.wasm")).toBeInTheDocument();
    expect(screen.getByText("net.dial:f5.example.test")).toBeInTheDocument();
    expect(screen.getByText(/unsigned plugin would fail closed/i)).toBeInTheDocument();
    expect(screen.getByText(/The plugin runtime is served, but plugin administration is not/i)).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Cross-cluster federation" })).toBeInTheDocument();
    expect(screen.getByText("Passive-read-state model")).toBeInTheDocument();
    expect(screen.getByText("served worker")).toBeInTheDocument();
    expect(screen.getAllByText(/one writable region per tenant/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /activate|enable plugin|install plugin|join cluster|federate/i })).not.toBeInTheDocument();
  });

  it("defaults to the system theme and toggles to dark", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");
    // System default with light OS preference -> not dark.
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    // Toggle: system -> light -> dark.
    const toggle = screen.getByRole("button", { name: /Theme:/i });
    await user.click(toggle); // -> light
    await user.click(toggle); // -> dark
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("trstctl-theme")).toBe("dark");
  });
});
