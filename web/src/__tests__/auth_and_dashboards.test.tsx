import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn(), certificates: vi.fn(), owners: vi.fn(), risk: vi.fn() },
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
    apiMock.risk.mockReset();
    apiMock.certificates.mockResolvedValue([]);
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

  it("shows the dashboard once authenticated", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([{ id: "c1", subject: "CN=svc" }]);
    apiMock.risk.mockResolvedValue([
      { credential_id: "c1", subject: "CN=svc", kind: "certificate", score: 73, exposure: 2, owner_active: false },
    ]);

    renderAt("/");

    await waitFor(() => expect(screen.getByRole("heading", { name: /Overview/i })).toBeInTheDocument());
    expect(screen.getByText("u@example.test")).toBeInTheDocument(); // the session principal
    await waitFor(() => expect(screen.getByTestId("cert-count")).toHaveTextContent("1"));
  });

  it("renders the certificate inventory in a table", async () => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1" });
    apiMock.certificates.mockResolvedValue([
      { id: "c1", subject: "CN=payments.example.com", issuer: "CN=CA", status: "active" },
      { id: "c2", subject: "CN=web.example.com", issuer: "CN=CA", status: "active" },
    ]);

    renderAt("/certificates");

    await waitFor(() => expect(screen.getByText("CN=payments.example.com")).toBeInTheDocument());
    expect(screen.getByText("CN=web.example.com")).toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
  });
});
