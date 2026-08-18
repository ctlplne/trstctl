import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import { moduleScopeTerm } from "@/lib/navigation";
import type { Me } from "@/lib/api";

/** S-B4: the audit stream is a single shared plane with per-module lenses.
 * ?module=<id> scopes it via the existing free-text query; the scope is a
 * clearable chip, never a sticky invisible filter. One stream, N lenses — not
 * per-module audit silos (03 §2, the DigiCert anti-pattern). */

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
  } as Record<string, ReturnType<typeof vi.fn>>,
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function session(): Me {
  return { subject: "auditor", tenant_id: "t1", email: "auditor@example.test", permissions: ["audit:read"] } as Me;
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

describe("audit module scope (S-B4)", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue(session());
    apiMock.auditEvents.mockResolvedValue([
      { id: "e1", sequence: 1, tenant_id: "t1", type: "secret.rotate", time: new Date().toISOString(), hash: "abc123def456" },
    ]);
  });

  it("maps each space to a stable scope term", () => {
    expect(moduleScopeTerm("secrets")).toBe("secret");
    expect(moduleScopeTerm("certificates")).toBe("cert");
    expect(moduleScopeTerm("workload")).toBe("ssh");
    expect(moduleScopeTerm("posture")).toBe("incident");
    expect(moduleScopeTerm("platform")).toBe("agent");
    expect(moduleScopeTerm("nope")).toBeUndefined();
  });

  it("scopes the shared audit stream from ?module and shows a clearable chip", async () => {
    renderAt("/audit?module=secrets");

    await screen.findByRole("heading", { level: 1, name: "Audit" });
    // The scope is applied to the served query as the module's term.
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalledWith(expect.objectContaining({ q: "secret" })));

    // A visible, clearable chip names the scope.
    const chip = screen.getByTestId("audit-module-scope");
    expect(within(chip).getByText(/Scoped to Secrets/i)).toBeInTheDocument();

    // Clearing removes the scope and reloads the full (unscoped) stream.
    apiMock.auditEvents.mockClear();
    await userEvent.setup().click(within(chip).getByRole("button", { name: /Clear module scope/i }));
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalled());
    expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]?.q).toBeUndefined();
    expect(screen.queryByTestId("audit-module-scope")).not.toBeInTheDocument();
  });

  it("shows no scope chip on the unscoped audit surface", async () => {
    renderAt("/audit");
    await screen.findByRole("heading", { level: 1, name: "Audit" });
    expect(screen.queryByTestId("audit-module-scope")).not.toBeInTheDocument();
  });
});
