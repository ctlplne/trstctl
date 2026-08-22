import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import type { Me } from "@/lib/api";

/** S-C1 space switcher (supersedes the S-B2 chips). The icon rail owns space
 * switching: activating a space navigates to its landing route, the URL is the
 * single source of truth for the active space, and the sidebar shows only the
 * active space's groups. A permission-limited user only sees spaces containing
 * at least one route they may read. */

const { apiMock } = vi.hoisted(() => ({
  apiMock: new Proxy({} as Record<string, ReturnType<typeof vi.fn>>, {
    get: (target, prop: string) => {
      if (!target[prop]) {
        target[prop] = vi.fn().mockResolvedValue(Object.assign([] as unknown[], { items: [], events: [], summary: {}, coverage: [] }));
      }
      return target[prop];
    },
  }),
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const FULL_PERMISSIONS = [
  "access:read",
  "agents:read",
  "agents:write",
  "audit:read",
  "certs:issue",
  "certs:read",
  "certs:request",
  "connectors:read",
  "discovery:read",
  "graph:read",
  "identities:read",
  "incidents:read",
  "issuers:read",
  "keys:write",
  "lifecycle:read",
  "notifications:read",
  "owners:read",
  "policy:read",
  "privacy:read",
  "profiles:read",
  "risk:read",
  "secrets:read",
  "secrets:write",
];

function session(permissions: string[]): Me {
  return { subject: "op", tenant_id: "t1", email: "op@example.test", permissions } as Me;
}

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

describe("space switcher (S-C1)", () => {
  beforeEach(() => {
    localStorage.clear();
    apiMock.me.mockResolvedValue(session(FULL_PERMISSIONS));
  });

  it("derives the active space from the URL and scopes the sidebar to it", async () => {
    renderAt("/certificates");
    const nav = await screen.findByRole("navigation", { name: /Primary/i });
    const rail = screen.getByRole("navigation", { name: /Spaces/i });

    // The rail exposes Home plus the five spaces.
    for (const space of ["Home", "Certificates & PKI", "Secrets", "Workload & SSH", "Posture & response", "Platform"]) {
      expect(within(rail).getByRole("button", { name: space })).toBeInTheDocument();
    }

    // On a certificates route, the Certificates & PKI space is active and its
    // sidebar shows the certificate authority and rule workspaces.
    expect(within(rail).getByRole("button", { name: "Certificates & PKI" })).toHaveAttribute("aria-current", "true");
    expect(within(nav).getByRole("link", { name: /Certificate authorities/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /Certificate rules/i })).toBeInTheDocument();

    // Other spaces' surfaces stay out of the sidebar — the space owns it.
    expect(within(nav).queryByRole("link", { name: /Credential graph/i })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Workloads/i })).not.toBeInTheDocument();
  });

  it("navigates to the chosen space's landing route when switching", async () => {
    const user = userEvent.setup();
    renderAt("/certificates");
    await screen.findByRole("navigation", { name: /Primary/i });
    const rail = screen.getByRole("navigation", { name: /Spaces/i });

    await user.click(within(rail).getByRole("button", { name: "Workload & SSH" }));

    // The URL is the source of truth: switching lands on the space's first
    // permitted route and the sidebar re-scopes.
    await screen.findByRole("heading", { level: 1, name: "Workloads" });
    const nav = screen.getByRole("navigation", { name: /Primary/i });
    await waitFor(() => expect(within(nav).getByRole("link", { name: /SSH access/i })).toBeInTheDocument());
    expect(within(nav).queryByRole("link", { name: /Certificate authorities/i })).not.toBeInTheDocument();
    expect(within(rail).getByRole("button", { name: "Workload & SSH" })).toHaveAttribute("aria-current", "true");
  });

  it("marks the owning space active when deep-linking a space route", async () => {
    renderAt("/ssh");
    await screen.findByRole("navigation", { name: /Primary/i });
    const rail = screen.getByRole("navigation", { name: /Spaces/i });
    await waitFor(() => expect(within(rail).getByRole("button", { name: "Workload & SSH" })).toHaveAttribute("aria-current", "true"));
  });

  it("shows Home (primary items + worklists) outside any space", async () => {
    renderAt("/");
    const nav = await screen.findByRole("navigation", { name: /Primary/i });
    const rail = screen.getByRole("navigation", { name: /Spaces/i });

    expect(within(rail).getByRole("button", { name: "Home" })).toHaveAttribute("aria-current", "true");
    expect(within(nav).getByRole("link", { name: /Guided setup/i })).toBeInTheDocument();
    expect(within(nav).getByRole("list", { name: "Needs action worklists" })).toBeInTheDocument();
    // Space-owned rows do not leak onto the Home sidebar.
    expect(within(nav).queryByRole("link", { name: /Certificate authorities/i })).not.toBeInTheDocument();
  });

  it("hides spaces the session cannot use and keeps permitted ones", async () => {
    // No secrets:write — that scope would light up Workload & SSH via /workloads.
    apiMock.me.mockResolvedValue(session(["secrets:read", "risk:read", "graph:read", "audit:read"]));
    renderAt("/");
    await screen.findByRole("navigation", { name: /Primary/i });
    const rail = screen.getByRole("navigation", { name: /Spaces/i });

    expect(within(rail).getByRole("button", { name: "Secrets" })).toBeInTheDocument();
    expect(within(rail).getByRole("button", { name: "Posture & response" })).toBeInTheDocument();
    // No certificate-issuance space for a session lacking certs:*/issuers:*.
    expect(within(rail).queryByRole("button", { name: "Certificates & PKI" })).not.toBeInTheDocument();
    // Workload & SSH needs certs/identities scopes this session lacks.
    expect(within(rail).queryByRole("button", { name: "Workload & SSH" })).not.toBeInTheDocument();
  });
});
