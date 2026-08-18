import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, me: apiMock.me, authMethods: apiMock.authMethods } };
});

function renderShell() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter>
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

describe("UX-02 shell metadata declutter", () => {
  beforeEach(() => {
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
  });

  it("hides internal nav metadata and removes the disabled tenant switcher", async () => {
    renderShell();

    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: "Primary" });

    expect(within(nav).queryByText("Operate")).not.toBeInTheDocument();
    expect(within(nav).queryByText("Observe")).not.toBeInTheDocument();
    expect(within(nav).queryByText("Disclose")).not.toBeInTheDocument();

    const hiddenNumericBadges = Array.from(nav.querySelectorAll("[aria-hidden='true']")).filter((element) => /^\d+$/.test(element.textContent?.trim() ?? ""));
    expect(hiddenNumericBadges).toEqual([]);

    expect(screen.getByLabelText("Tenant context")).toHaveTextContent("t1");
    expect(screen.queryByRole("button", { name: /tenant switching|switch unavailable/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/Switch unavailable|Tenant switching isn't available yet/i)).not.toBeInTheDocument();
  });
});
