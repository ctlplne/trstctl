import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import { AppShell } from "@/components/AppShell";
import { LoadingState } from "@/components/StatePrimitives";

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = path.resolve(SRC, "..", "..");

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    certificates: vi.fn(),
    identities: vi.fn(),
    risk: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, me: apiMock.me } };
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

describe("reduced motion and a11y evidence (PRODUCT-005 / COVER-010)", () => {
  beforeEach(() => {
    apiMock.me.mockReset();
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.certificates.mockResolvedValue([]);
    apiMock.identities.mockResolvedValue([]);
    apiMock.risk.mockResolvedValue([]);
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024, writable: true });
  });

  it("ships a global prefers-reduced-motion rule that disables animation/transition", () => {
    const css = readFileSync(path.join(SRC, "index.css"), "utf8");
    expect(css).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/);
    // The rule must actually short-circuit motion, not just exist.
    const block = css.slice(css.indexOf("prefers-reduced-motion"));
    expect(block).toMatch(/animation-duration:\s*0/);
    expect(block).toMatch(/transition-duration:\s*0/);
  });

  it("gates the shared loading spinner behind motion-safe so reduced motion stops it", () => {
    const { container } = render(<LoadingState>Loading rows...</LoadingState>);
    const spinner = container.querySelector("[aria-hidden='true']") as HTMLElement;
    expect(spinner).not.toBeNull();
    // motion-safe: only animates when the user has NOT requested reduced motion.
    expect(spinner.className).toMatch(/motion-safe:animate-spin/);
    // It must not carry an unconditional animate-spin that would ignore the policy.
    expect(spinner.className).not.toMatch(/(^|\s)animate-spin(\s|$)/);
    // The loading status is still announced to assistive tech.
    expect(container.querySelector("[role='status']")).not.toBeNull();
  });

  it("exposes an accessibly-named primary navigation with named links", async () => {
    renderAt("/");
    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: /Primary/i });
    expect(nav).toBeInTheDocument();
    // Primary nav links carry accessible names (text content), not bare icons.
    expect(within(nav).getByRole("link", { name: /Dashboard/i })).toBeInTheDocument();
    // S-A1 moved first-run setup off the rail; Journeys is the always-present
    // guided entry point instead.
    expect(within(nav).getByRole("link", { name: /Journeys/i })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Coverage|Roadmap/i })).not.toBeInTheDocument();
  });

  it("passes axe and keyboard traversal on the default shell route", async () => {
    const user = userEvent.setup();
    const { container } = renderShell();
    await screen.findByRole("heading", { name: "Overview" });

    // axe sweep of the authenticated shell and default product route.
    const results = await axe(container);
    expect(results).toHaveNoViolations();

    const dashboardLink = screen.getByRole("link", { name: /Dashboard/i });
    dashboardLink.focus();
    expect(dashboardLink).toHaveFocus();
    await user.tab();
    await waitFor(() => expect(document.activeElement).not.toBe(dashboardLink));
  });

  it("commits VPAT and manual assistive-technology evidence with a CI receipt upload", () => {
    const vpat = readFileSync(path.join(REPO_ROOT, "docs", "accessibility-vpat.md"), "utf8");
    expect(vpat).toMatch(/VPAT|Voluntary Product Accessibility Template/);
    expect(vpat).toMatch(/screen reader audit/i);
    expect(vpat).toMatch(/manual assistive/i);
    expect(vpat).toMatch(/WCAG 2\.1 AA/i);
    expect(vpat).toMatch(/Retest cadence/i);

    const workflow = readFileSync(path.join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8");
    expect(workflow).toMatch(/Upload accessibility evidence receipt/);
    expect(workflow).toMatch(/a11y-evidence-receipt/);
    expect(workflow).toMatch(/accessibility-evidence-receipt\.json/);
  });
});
