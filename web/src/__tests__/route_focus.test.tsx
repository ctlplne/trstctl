import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppShell } from "@/components/AppShell";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderShell(initialEntries = ["/"]) {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <ThemeProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={initialEntries}>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<h1>Overview</h1>} />
                <Route path="certificates" element={<h1>Certificates</h1>} />
                <Route path="identities" element={<h1>Identities</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ThemeProvider>
    </IntlProvider>,
  );
}

describe("SPA route focus management (PRODUCT-006)", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.logout.mockResolvedValue(undefined);
    document.title = "";
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024, writable: true });
  });

  it("moves focus to the new page heading after a nav link click", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");

    // Initial mount must not steal focus from the browser/restore behavior.
    expect(document.activeElement).not.toBe(screen.getByRole("heading", { name: "Overview" }));

    await user.click(screen.getByRole("link", { name: /Certificates/i }));

    const heading = await screen.findByRole("heading", { name: "Certificates" });
    const main = screen.getByRole("main");
    await waitFor(() => {
      expect([heading, main]).toContain(document.activeElement);
    });
  });

  it("updates document.title and announces the route in a live region", async () => {
    const user = userEvent.setup();
    renderShell();
    await screen.findByText("u@example.test");

    await user.click(screen.getByRole("link", { name: /Certificates/i }));
    await screen.findByRole("heading", { name: "Certificates" });

    await waitFor(() => expect(document.title).toMatch(/Certificates/));
    expect(document.title).toMatch(/trstctl/);

    const announcer = screen.getByTestId("route-announcer");
    expect(announcer).toHaveAttribute("aria-live", "polite");
    await waitFor(() => expect(announcer).toHaveTextContent(/Certificates/));
  });

  it("falls back to the main landmark when the page has no h1", async () => {
    const user = userEvent.setup();
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <ThemeProvider>
          <AuthProvider>
            <MemoryRouter initialEntries={["/"]}>
              <Routes>
                <Route element={<AppShell />}>
                  <Route index element={<h1>Overview</h1>} />
                  <Route path="identities" element={<p>no heading here</p>} />
                </Route>
              </Routes>
            </MemoryRouter>
          </AuthProvider>
        </ThemeProvider>
      </IntlProvider>,
    );
    await screen.findByText("u@example.test");

    await user.click(screen.getByRole("link", { name: /Identities/i }));
    await screen.findByText("no heading here");

    const main = screen.getByRole("main");
    await waitFor(() => expect(document.activeElement).toBe(main));
  });
});
