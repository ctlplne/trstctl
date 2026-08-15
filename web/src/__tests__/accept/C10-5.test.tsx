import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    certificates: vi.fn(),
    identities: vi.fn(),
    risk: vi.fn(),
    rotationRuns: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderDashboard(mode: "dark" | "light") {
  document.documentElement.classList.toggle("dark", mode === "dark");
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("C10-5 dashboard trend charts", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    document.documentElement.classList.remove("dark");
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "operator", tenant_id: "t1", email: "ops@example.test" });
    apiMock.certificates.mockResolvedValue([
      {
        id: "c1",
        tenant_id: "t1",
        subject: "CN=api-1",
        status: "active",
        fingerprint: "sha256:1",
        created_at: "2026-06-01T00:00:00Z",
        not_after: "2026-07-08T00:00:00Z",
        key_algorithm: "ECDSA-P256",
      },
      {
        id: "c2",
        tenant_id: "t1",
        subject: "CN=api-2",
        status: "active",
        fingerprint: "sha256:2",
        created_at: "2026-06-08T00:00:00Z",
        not_after: "2026-08-20T00:00:00Z",
        key_algorithm: "RSA-2048",
      },
      {
        id: "c3",
        tenant_id: "t1",
        subject: "CN=api-3",
        status: "active",
        fingerprint: "sha256:3",
        created_at: "2026-06-08T01:00:00Z",
        not_after: "2026-10-20T00:00:00Z",
        key_algorithm: "ECDSA-P256",
      },
    ]);
    apiMock.identities.mockResolvedValue([{ id: "id-1", name: "api", kind: "x509_certificate", owner_id: "owner-1", status: "issued" }]);
    apiMock.risk.mockResolvedValue([]);
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "run-1",
          tenant_id: "t1",
          identity_id: "id-1",
          status: "succeeded",
          trigger: "scheduler",
          created_at: "2026-06-08T00:00:00Z",
          updated_at: "2026-06-08T00:02:00Z",
        },
        {
          id: "run-2",
          tenant_id: "t1",
          identity_id: "id-2",
          status: "failed",
          trigger: "expiry-window",
          created_at: "2026-06-09T00:00:00Z",
          updated_at: "2026-06-09T00:02:00Z",
        },
      ],
    });
  });

  it.each(["light", "dark"] as const)("renders served dashboard trend charts in %s mode", async (mode) => {
    renderDashboard(mode);

    const dash = await screen.findByRole("region", { name: "Dashboard" });
    expect(await within(dash).findByRole("img", { name: "Certificate issuance rate by day" })).toBeInTheDocument();
    expect(await within(dash).findByRole("img", { name: "Renewal job success and failure trend" })).toBeInTheDocument();
    expect(await within(dash).findByRole("img", { name: "Certificate expirations over the next 90 days" })).toBeInTheDocument();
    expect(within(dash).getAllByText("Jun 8").length).toBeGreaterThan(0);
    expect(within(dash).getByText("succeeded")).toBeInTheDocument();
    expect(within(dash).getByText("failed")).toBeInTheDocument();
    await waitFor(() => expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 100 }));
  });
});
