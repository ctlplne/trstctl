import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppRoutes } from "@/App";
import { AuthProvider } from "@/auth/AuthProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { UnauthorizedError } from "@/lib/apiTransport";

const { bootstrapMock } = vi.hoisted(() => ({ bootstrapMock: { me: vi.fn(), authMethods: vi.fn() } }));
vi.mock("@/lib/bootstrapApi", async (orig) => ({ ...(await orig<typeof import("@/lib/bootstrapApi")>()), bootstrapApi: bootstrapMock }));

beforeEach(() => {
  bootstrapMock.me.mockRejectedValue(new UnauthorizedError());
  bootstrapMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
});

describe("SSO return destination", () => {
  it.each([
    ["/policy?tab=rules&owner=a%20b#history", "/policy?tab=rules&owner=a%20b#history"],
    ["/login?error=tenant_access_not_configured&return_to=%2Fpolicy%23history", "/policy#history"],
    ["/login", ""],
  ])("continues %s through the local SSO entrypoint", async (entry, target) => {
    const originalLocation = window.location;
    const assign = vi.fn();
    Object.defineProperty(window, "location", { configurable: true, value: { ...originalLocation, assign } });
    try {
      render(
        <ThemeProvider>
          <AuthProvider>
            <MemoryRouter initialEntries={[entry]}>
              <AppRoutes />
            </MemoryRouter>
          </AuthProvider>
        </ThemeProvider>,
      );
      await userEvent.click(await screen.findByRole("button", { name: "Continue with SSO" }));
      expect(assign).toHaveBeenCalledWith(target ? `/auth/login?${new URLSearchParams({ return_to: target })}` : "/auth/login");
    } finally {
      Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
    }
  });
});
