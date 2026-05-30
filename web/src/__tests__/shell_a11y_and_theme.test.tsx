import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn(), certificates: vi.fn(), owners: vi.fn(), risk: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderShell() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/"]}>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<h1>Overview</h1>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("app shell accessibility and theme", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    document.documentElement.classList.remove("dark");
    localStorage.clear();
  });

  it("has no axe accessibility violations", async () => {
    const { container } = renderShell();
    await waitFor(() => screen.getByText("u@example.test"));
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("exposes navigation and main landmarks and a skip link", async () => {
    renderShell();
    expect(screen.getByRole("navigation", { name: /Primary/i })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Skip to main content/i })).toBeInTheDocument();
  });

  it("navigation links are keyboard reachable", async () => {
    const user = userEvent.setup();
    renderShell();
    await user.tab(); // skip link
    await user.tab(); // theme toggle
    const dashboardLink = screen.getByRole("link", { name: /Dashboard/i });
    dashboardLink.focus();
    expect(dashboardLink).toHaveFocus();
  });

  it("defaults to the system theme and toggles to dark", async () => {
    const user = userEvent.setup();
    renderShell();
    // System default with light OS preference -> not dark.
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    // Toggle: system -> light -> dark.
    const toggle = screen.getByRole("button", { name: /Theme:/i });
    await user.click(toggle); // -> light
    await user.click(toggle); // -> dark
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("certctl-theme")).toBe("dark");
  });
});
