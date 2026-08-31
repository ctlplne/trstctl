import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { ToastProvider } from "@/components/ToastProvider";
import { AppRoutes } from "@/App";
import { moduleScopeTerm } from "@/lib/navigation";
import { ApiError, type AuditEvent, type AuditBundle, type Me } from "@/lib/api";

/** S-B4: the audit stream is a single shared plane with per-module lenses.
 * ?module=<id> selects a server-owned tool predicate, separate from free text;
 * this replaces the g102 live defect that searched only for "ssh". The scope is a
 * clearable chip, never a sticky invisible filter. One stream, N lenses — not
 * per-module audit silos (03 §2, the DigiCert anti-pattern). */

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
    downloadAuditExport: vi.fn(),
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
            <NavigationProbe />
            <AppRoutes />
          </MemoryRouter>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function NavigationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <output data-testid="audit-location">{location.search}</output>
      <button onClick={() => navigate(-1)}>Back in audit history</button>
    </>
  );
}

describe("audit module scope (S-B4)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.me.mockResolvedValue(session());
    apiMock.auditEvents.mockResolvedValue([
      { id: "e1", sequence: 1, tenant_id: "t1", type: "secret.rotate", time: new Date().toISOString(), hash: "abc123def456" },
    ]);
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed" });
    apiMock.downloadAuditExport.mockResolvedValue("trstctl-audit.ndjson");
  });

  it("retains the legacy risk-search terms separately from audit membership", () => {
    expect(moduleScopeTerm("secrets")).toBe("secret");
    expect(moduleScopeTerm("certificates")).toBe("cert");
    expect(moduleScopeTerm("workload")).toBe("ssh");
    expect(moduleScopeTerm("posture")).toBe("sign");
    expect(moduleScopeTerm("platform")).toBe("incident");
    expect(moduleScopeTerm("nope")).toBeUndefined();
  });

  it("scopes the shared audit stream from ?module and shows a clearable chip", async () => {
    renderAt("/audit?module=secrets");

    await screen.findByRole("heading", { level: 1, name: "Change history" });
    await waitFor(() => expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]).toEqual({ tool: "secrets", limit: 50 }));

    // A visible, clearable chip names the scope.
    const chip = screen.getByTestId("audit-module-scope");
    expect(within(chip).getByText(/Scoped to Secrets/i)).toBeInTheDocument();

    // Clearing removes the scope and reloads the full (unscoped) stream.
    apiMock.auditEvents.mockClear();
    await userEvent.setup().click(within(chip).getByRole("button", { name: /Clear module scope/i }));
    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenCalled());
    expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]?.q).toBeUndefined();
    expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]?.tool).toBeUndefined();
    expect(screen.queryByTestId("audit-module-scope")).not.toBeInTheDocument();
  });

  it.each([
    ["discovery", "discover"],
    ["certificates", "certificates"],
    ["workload", "workloads_machines"],
    ["posture", "software_trust"],
    ["platform", "operations"],
  ])("maps %s to the explicit %s server predicate", async (module, tool) => {
    renderAt(`/audit?module=${module}&q=payments`);
    await waitFor(() => expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]).toEqual({ tool, q: "payments", limit: 50 }));
  });

  it("clears only the tool, preserves other filters, and restores the scope on browser back", async () => {
    const user = userEvent.setup();
    renderAt("/audit?module=workload&q=payments&type=attestation.verified&limit=2");
    const expected = { tool: "workloads_machines", q: "payments", type: "attestation.verified", limit: 2 };
    await waitFor(() => expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]).toEqual(expected));
    await user.click(screen.getByRole("button", { name: /Clear module scope/i }));
    await waitFor(() => expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]).toEqual({ q: "payments", type: "attestation.verified", limit: 2 }));
    expect(screen.getByTestId("audit-location")).not.toHaveTextContent("module=");
    await user.click(screen.getByRole("button", { name: "Back in audit history" }));
    await waitFor(() => expect(screen.getByTestId("audit-module-scope")).toHaveTextContent("Workloads"));
    expect(screen.getByLabelText("Search activity")).toHaveValue("payments");
  });

  it("resets visible and served scope together", async () => {
    renderAt("/audit?module=workload&q=payments&limit=2");
    await screen.findByRole("button", { name: "Reset" });
    await userEvent.setup().click(screen.getByRole("button", { name: "Reset" }));
    await waitFor(() => expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]).toEqual({ limit: 50 }));
    expect(screen.queryByTestId("audit-module-scope")).not.toBeInTheDocument();
    expect(screen.getByTestId("audit-location")).toBeEmptyDOMElement();
  });

  it("uses the same applied tool, text and as-of boundary for signed and stream exports", async () => {
    const user = userEvent.setup();
    renderAt("/audit?module=workload&q=payments&as_of=12&limit=2");
    const expected = { tool: "workloads_machines", q: "payments", asOf: 12, limit: 2 };
    await waitFor(() => expect(apiMock.auditEvents.mock.calls.at(-1)?.[0]).toEqual(expected));
    await user.click(screen.getByText("Signatures and evidence export"));
    await user.click(screen.getByRole("button", { name: "Export evidence" }));
    await waitFor(() => expect(apiMock.exportAudit.mock.calls.at(-1)?.[0]).toEqual(expected));
    await user.selectOptions(screen.getByLabelText("Export format"), "ndjson");
    await user.click(screen.getByRole("button", { name: "Export evidence" }));
    await waitFor(() => expect(apiMock.downloadAuditExport.mock.calls.at(-1)?.slice(0, 2)).toEqual([expected, "ndjson"]));
  });

  it("shows no scope chip on the unscoped audit surface", async () => {
    renderAt("/audit");
    await screen.findByRole("heading", { level: 1, name: "Change history" });
    expect(screen.queryByTestId("audit-module-scope")).not.toBeInTheDocument();
  });

  it("ignores the old tool's late read after the operator clears its scope", async () => {
    let resolveOld!: (rows: AuditEvent[]) => void;
    apiMock.auditEvents.mockImplementationOnce(
      () =>
        new Promise<AuditEvent[]>((resolve) => {
          resolveOld = resolve;
        }),
    );
    renderAt("/audit?module=workload");
    await screen.findByTestId("audit-module-scope");
    const oldSignal = apiMock.auditEvents.mock.calls[0][1] as AbortSignal;
    await userEvent.setup().click(screen.getByRole("button", { name: "Clear module scope" }));
    await screen.findByText("secret.rotate");
    expect(oldSignal.aborted).toBe(true);
    await act(async () => {
      resolveOld([{ id: "late", sequence: 2, tenant_id: "t1", type: "attestation.verified", time: new Date().toISOString() }]);
    });
    expect(screen.queryByText("attestation.verified")).not.toBeInTheDocument();
    expect(screen.getByText("secret.rotate")).toBeInTheDocument();
  });

  it("cancels a pending signed export instead of displaying it under a different tool", async () => {
    let resolveOld!: (bundle: AuditBundle) => void;
    apiMock.exportAudit.mockImplementationOnce(
      () =>
        new Promise<AuditBundle>((resolve) => {
          resolveOld = resolve;
        }),
    );
    const user = userEvent.setup();
    renderAt("/audit?module=workload");
    await screen.findByText("secret.rotate");
    await user.click(screen.getByText("Signatures and evidence export"));
    await user.click(screen.getByRole("button", { name: "Export evidence" }));
    const oldSignal = apiMock.exportAudit.mock.calls[0][1] as AbortSignal;
    await user.click(screen.getByRole("button", { name: "Clear module scope" }));
    expect(oldSignal.aborted).toBe(true);
    await act(async () => {
      resolveOld({ format: "jws", bundle: "old-scoped-evidence" } as AuditBundle);
    });
    expect(screen.queryByText("jws: old-scoped-evidence")).not.toBeInTheDocument();
  });

  it("does not export an earlier successful scope after the new query fails", async () => {
    const user = userEvent.setup();
    renderAt("/audit?module=workload");
    await screen.findByText("secret.rotate");
    apiMock.auditEvents.mockRejectedValue(new ApiError(503, JSON.stringify({ detail: "audit dependency unavailable" })));
    await user.click(screen.getByRole("button", { name: "Clear module scope" }));
    await screen.findByRole("heading", { name: "Change history is unavailable" });
    await user.click(screen.getByText("Signatures and evidence export"));
    expect(screen.getByRole("button", { name: "Export evidence" })).toBeDisabled();
    expect(apiMock.exportAudit).not.toHaveBeenCalled();
  });
});
