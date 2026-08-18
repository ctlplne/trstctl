import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    certificates: vi.fn(),
    identities: vi.fn(),
    risk: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderAt(pathname: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[pathname]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("feature coverage ledger removal", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([]);
    apiMock.identities.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
  });

  it("deletes the internal coverage page and feature-map data module", () => {
    expect(existsSync(path.join(SRC, "pages/FeatureCoverage.tsx"))).toBe(false);
    expect(existsSync(path.join(SRC, "lib/featureCoverage.ts"))).toBe(false);
    expect(existsSync(path.join(SRC, "lib/feature-map-backlog.json"))).toBe(false);
  });

  it("redirects /coverage to the customer dashboard without a coverage nav item", async () => {
    renderAt("/coverage");

    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).queryByRole("link", { name: /coverage/i })).not.toBeInTheDocument();
    expect(screen.queryByText("Backend-to-GUI coverage")).not.toBeInTheDocument();
  });
});
