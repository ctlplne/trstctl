import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import type { Me } from "@/lib/api";

/** S-B2 module switcher + scoped rail. The rail's middle band is scoped by a
 * product module; global planes (Identities, Graph, Risk, Audit, …) stay
 * visible regardless of the active module. Deep-linking a module route selects
 * that module; a permission-limited user only sees modules they can use. */

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
  "access:read", "agents:read", "agents:write", "audit:read", "certs:issue", "certs:read", "certs:request",
  "connectors:read", "discovery:read", "graph:read", "identities:read", "incidents:read", "issuers:read",
  "keys:write", "lifecycle:read", "notifications:read", "owners:read", "policy:read", "privacy:read",
  "profiles:read", "risk:read", "secrets:read", "secrets:write",
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

describe("module switcher (S-B2)", () => {
  beforeEach(() => {
    localStorage.clear();
    apiMock.me.mockResolvedValue(session(FULL_PERMISSIONS));
  });

  it("renders the module switcher and scopes the rail band to the active module", async () => {
    renderAt("/certificates");
    const nav = await screen.findByRole("navigation", { name: /Primary/i });

    // Switcher exposes the curated modules as tabs.
    const switcher = within(nav).getByRole("tablist", { name: /Module/i });
    expect(within(switcher).getByRole("tab", { name: /Certificates & PKI/i })).toBeInTheDocument();
    expect(within(switcher).getByRole("tab", { name: /Secrets/i })).toBeInTheDocument();
    expect(within(switcher).getByRole("tab", { name: /Fleet/i })).toBeInTheDocument();

    // On a certificates route, the Certificates & PKI module is active and its
    // band shows CA hierarchy / Certificate profiles.
    expect(within(switcher).getByRole("tab", { name: /Certificates & PKI/i })).toHaveAttribute("aria-selected", "true");
    expect(within(nav).getByRole("link", { name: /CA hierarchy/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /Certificate profiles/i })).toBeInTheDocument();

    // Global planes stay visible regardless of module.
    expect(within(nav).getByRole("link", { name: /Credential graph/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /^Audit$/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /Identities/i })).toBeInTheDocument();
  });

  it("switches the band without navigating when a different module is chosen", async () => {
    const user = userEvent.setup();
    renderAt("/certificates");
    const nav = await screen.findByRole("navigation", { name: /Primary/i });
    const switcher = within(nav).getByRole("tablist", { name: /Module/i });

    await user.click(within(switcher).getByRole("tab", { name: /Fleet/i }));

    // Fleet band appears (Workloads); certificates-only routes leave the band.
    await waitFor(() => expect(within(nav).getByRole("link", { name: /Workloads/i })).toBeInTheDocument());
    expect(within(nav).queryByRole("link", { name: /CA hierarchy/i })).not.toBeInTheDocument();
    // Switching is chrome only — the route did not change.
    expect(screen.getByRole("heading", { level: 1, name: "Certificates" })).toBeInTheDocument();
  });

  it("auto-selects the owning module when deep-linking a module route", async () => {
    renderAt("/ssh");
    const nav = await screen.findByRole("navigation", { name: /Primary/i });
    const switcher = within(nav).getByRole("tablist", { name: /Module/i });
    await waitFor(() => expect(within(switcher).getByRole("tab", { name: /^SSH$/i })).toHaveAttribute("aria-selected", "true"));
  });

  it("shows a secrets-only operator just their permitted modules plus global planes", async () => {
    // Rendered from the dashboard: the switcher is route-independent, and this
    // avoids exercising a data-heavy product page under the smoke mock.
    apiMock.me.mockResolvedValue(session(["secrets:read", "secrets:write", "identities:read", "risk:read", "graph:read", "audit:read"]));
    renderAt("/");
    const nav = await screen.findByRole("navigation", { name: /Primary/i });
    const switcher = within(nav).getByRole("tablist", { name: /Module/i });

    expect(within(switcher).getByRole("tab", { name: /Secrets/i })).toBeInTheDocument();
    // No certificate-issuance or signing module for a session lacking certs:*/keys:write.
    expect(within(switcher).queryByRole("tab", { name: /Certificates & PKI/i })).not.toBeInTheDocument();
    expect(within(switcher).queryByRole("tab", { name: /Signing/i })).not.toBeInTheDocument();
    // Global planes the session can read remain.
    expect(within(nav).getByRole("link", { name: /Credential graph/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /^Audit$/i })).toBeInTheDocument();
  });
});
