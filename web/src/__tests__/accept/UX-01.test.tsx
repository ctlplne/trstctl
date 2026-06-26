import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    certificates: vi.fn(),
    certificatePage: vi.fn(),
    identities: vi.fn(),
    risk: vi.fn(),
    secretPage: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
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

describe("UX-01 coverage route removal", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([]);
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.identities.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
    apiMock.secretPage.mockResolvedValue({ items: [] });
  });

  it("removes the internal coverage page from routing, navigation, and command jump", async () => {
    const user = userEvent.setup();
    renderAt("/coverage");

    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Backend-to-GUI coverage" })).not.toBeInTheDocument();

    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).queryByRole("link", { name: /coverage/i })).not.toBeInTheDocument();
    for (const link of within(nav).getAllByRole("link")) {
      expect(link).not.toHaveAttribute("href", expect.stringContaining("/coverage"));
    }

    await user.click(screen.getByRole("button", { name: "Open command palette" }));
    const palette = await screen.findByRole("dialog", { name: "Command palette" });
    const search = within(palette).getByRole("searchbox", { name: "Search routes and inventory" });
    await user.type(search, "coverage");

    await waitFor(() => expect(within(palette).queryByRole("button", { name: /coverage/i })).not.toBeInTheDocument());
  });
});
