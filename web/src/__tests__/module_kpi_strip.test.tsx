import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import type { Me } from "@/lib/api";

/** S-B3: each module home shows a thin, SERVED KPI strip above its object list,
 * every number deep-linking into a filtered list or a sub-surface. Numbers must
 * come from the API — never demo data (S-N0 principle). */

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

function session(): Me {
  return {
    subject: "op",
    tenant_id: "t1",
    email: "op@example.test",
    permissions: [
      "certs:read",
      "certs:issue",
      "certs:request",
      "issuers:read",
      "profiles:read",
      "identities:read",
      "risk:read",
      "secrets:read",
      "secrets:write",
    ],
  } as Me;
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

describe("module KPI strip (S-B3)", () => {
  beforeEach(() => {
    localStorage.clear();
    apiMock.me.mockResolvedValue(session());
  });

  it("renders served certificate KPIs that deep-link into filtered inventory", async () => {
    apiMock.certificateHealth.mockResolvedValue({
      generated_at: new Date().toISOString(),
      expiring: [],
      expiring_path: "/certificates?expiry=30d",
      inventory_path: "/certificates",
      expiry_buckets: [],
      source_breakdown: [],
      summary: { active: 42, discovered_count: 0, expired: 0, expiring_30d: 5, expiring_7d: 2, expiring_90d: 0, external_source_count: 0, health: "warning" },
    });
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", tenant_id: "t1", subject: "CN=svc.example.test", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
    });

    renderAt("/certificates");

    const strip = await screen.findByRole("region", { name: /Certificates & PKI module metrics/i });
    // Served numbers, not fabricated.
    const expiring30 = within(strip).getByRole("link", { name: /Expiring ≤30d/ });
    expect(within(expiring30).getByText("5")).toBeInTheDocument();
    expect(expiring30).toHaveAttribute("href", "/certificates?expiry=30d");

    const expiring7 = within(strip).getByRole("link", { name: /Expiring ≤7d/i });
    expect(within(expiring7).getByText("2")).toBeInTheDocument();
    expect(expiring7).toHaveAttribute("href", "/certificates?expiry=7d");

    const active = within(strip).getByRole("link", { name: /Active/i });
    expect(within(active).getByText("42")).toBeInTheDocument();

    // A navigational KPI to the CA hierarchy (no fabricated number).
    expect(within(strip).getByRole("link", { name: /CA hierarchy/i })).toHaveAttribute("href", "/ca-hierarchy");
  });

  it("does not render the strip before served health is available", async () => {
    apiMock.certificateHealth.mockRejectedValue(new Error("no health yet"));
    apiMock.certificatePage.mockResolvedValue({
      items: [{ id: "c1", tenant_id: "t1", subject: "CN=svc.example.test", issuer: "CN=CA", status: "active", fingerprint: "fp1" }],
    });

    renderAt("/certificates");
    await screen.findByRole("heading", { level: 1, name: "Certificates" });
    await waitFor(() => expect(screen.getByText("CN=svc.example.test")).toBeInTheDocument());
    // Inventory renders, but with no served health the KPI strip stays absent.
    expect(screen.queryByRole("region", { name: /Certificates & PKI module metrics/i })).not.toBeInTheDocument();
  });

  it("renders the reusable strip: every number links, and no demo data leaks", async () => {
    // Direct component contract (the Secrets page integration mounts the same
    // component; exercised here without a data-heavy page under the smoke mock).
    const { ModuleKpiStrip } = await import("@/components/ModuleKpiStrip");
    const { IntlProvider } = await import("@/i18n/I18nProvider");
    render(
      <IntlProvider>
        <MemoryRouter>
          <ModuleKpiStrip
            ariaLabel="Secrets module metrics"
            kpis={[
              { id: "stored", label: "Stored secrets", value: 3, to: "/secrets" },
              { id: "engines", label: "Engines", value: "View →", to: "/secrets/engines" },
              { id: "sync", label: "Sync targets", value: "View →", to: "/secrets/sync" },
            ]}
          />
        </MemoryRouter>
      </IntlProvider>,
    );

    const strip = screen.getByRole("region", { name: /Secrets module metrics/i });
    const stored = within(strip).getByRole("link", { name: /Stored secrets/i });
    expect(within(stored).getByText("3")).toBeInTheDocument();
    expect(stored).toHaveAttribute("href", "/secrets");
    expect(within(strip).getByRole("link", { name: /Engines/i })).toHaveAttribute("href", "/secrets/engines");
    // Every KPI is a link (the dashboard-number-as-filter pattern).
    expect(within(strip).getAllByRole("link")).toHaveLength(3);
  });
});
