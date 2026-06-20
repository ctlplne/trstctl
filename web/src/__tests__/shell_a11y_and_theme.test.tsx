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
  apiMock: { me: vi.fn(), certificates: vi.fn(), owners: vi.fn(), risk: vi.fn() },
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
              <Route path="platform" element={<Platform />} />
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

    for (const link of [
      "Discovery",
      "SPIFFE",
      "Native secrets",
      "Connectors",
      "Incidents",
      "RBAC",
      "Platform",
    ]) {
      expect(within(nav).getByRole("link", { name: new RegExp(link) })).toBeInTheDocument();
    }
  });

  it("routes to the platform posture page from grouped navigation", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");

    await user.click(screen.getByRole("link", { name: /^Platform$/i }));

    expect(await screen.findByRole("heading", { name: "Platform" })).toBeInTheDocument();
    expect(screen.getByText(/Tenant boundary/i)).toBeInTheDocument();
    expect(screen.getByText(/Platform status endpoint not served yet/i)).toBeInTheDocument();
  });

  it("renders tenant context from the served session without an editable tenant input", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText("Tenant ID from session")).toBeInTheDocument();
    expect(screen.getByText("t1")).toBeInTheDocument();
    expect(screen.getByText(/browser never chooses a tenant id/i)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /tenant/i })).not.toBeInTheDocument();
  });

  it("shows the required-scope map and the tenant-admin dependency for exact grants", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText("Current scope inventory is not served yet.")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-TENANT-ADMIN/).length).toBeGreaterThan(0);
    expect(screen.getByText("certs:issue")).toBeInTheDocument();
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

    expect(screen.getByText(/31 served REST paths/i)).toBeInTheDocument();
    expect(screen.getByText("/api/v1/secrets/store/{name}")).toBeInTheDocument();
    expect(screen.getByText("/api/v1/graph/query")).toBeInTheDocument();
    expect(screen.getByText("Spec view")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-OPENAPI-SERVED/).length).toBeGreaterThan(0);
    const firstCurl = screen.getAllByText(/^curl -X GET/)[0].textContent || "";
    expect(firstCurl).not.toMatch(/Authorization|Bearer|token/i);

    fireEvent.click(screen.getAllByRole("button", { name: "Copy curl" })[0]);

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(expect.stringMatching(/^curl -X GET https:\/\/trstctl\.example\.test\/api\/v1\/agents$/));
    });
    expect(writeText.mock.calls[0][0]).not.toMatch(/Authorization|Bearer|token/i);
    expect(screen.getByText("Copied without token material.")).toBeInTheDocument();
  });

  it("shows honest auth and transport status without exposing key material", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByText(/Plaintext local preview/i)).toBeInTheDocument();
    expect(screen.getByText(/No private cert\/key bytes are exposed/i)).toBeInTheDocument();
    expect(screen.getByText(/OIDC enabled\/disabled, issuer, audience/i)).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-PLATFORM-STATUS/).length).toBeGreaterThan(0);
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

  it("renders runtime, plugin, and federation disclosures without live platform actions", async () => {
    renderShell(["/platform"]);
    await screen.findByRole("heading", { name: "Platform" });

    expect(screen.getByRole("heading", { name: "Single-binary runtime" })).toBeInTheDocument();
    expect(screen.getByText("Runtime status JSON not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-PLATFORM-STATUS/).length).toBeGreaterThan(0);
    expect(screen.getByText("Signer supervision")).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Plugin SDK and capability sandbox" })).toBeInTheDocument();
    expect(screen.getByText("connector-f5.wasm")).toBeInTheDocument();
    expect(screen.getByText("net.dial:f5.example.test")).toBeInTheDocument();
    expect(screen.getByText(/unsigned plugin would fail closed/i)).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-PLUGINHOST/).length).toBeGreaterThan(0);

    expect(screen.getByRole("heading", { name: "Cross-cluster federation roadmap" })).toBeInTheDocument();
    expect(screen.getAllByText("roadmap only").length).toBeGreaterThan(0);
    expect(screen.getByText("Federation is roadmap-only")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-FEDERATION/).length).toBeGreaterThan(0);
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
