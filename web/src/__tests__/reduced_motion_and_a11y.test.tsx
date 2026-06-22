import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import { LoadingState } from "@/components/StatePrimitives";

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn() },
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

describe("reduced motion and a11y evidence (PRODUCT-005 / COVER-010)", () => {
  beforeEach(() => {
    apiMock.me.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
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
    renderAt("/coverage");
    await screen.findByText("u@example.test");
    const nav = screen.getByRole("navigation", { name: /Primary/i });
    expect(nav).toBeInTheDocument();
    // Primary nav links carry accessible names (text content), not bare icons.
    expect(within(nav).getByRole("link", { name: /Dashboard/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /Coverage|Roadmap/i })).toBeInTheDocument();
  });

  it("passes axe and keyboard traversal on the /coverage route", async () => {
    const user = userEvent.setup();
    const { container } = renderAt("/coverage");
    await screen.findByRole("heading", { name: "Backend-to-GUI coverage" });

    // axe sweep of the operable coverage surface.
    const results = await axe(container);
    expect(results).toHaveNoViolations();

    // The coverage filter controls are keyboard-operable.
    const filterGroup = screen.getByRole("group", { name: /Coverage outcome filter/i });
    const firstFilter = within(filterGroup).getAllByRole("button")[0];
    firstFilter.focus();
    expect(firstFilter).toHaveFocus();
    await user.tab();
    await waitFor(() => expect(document.activeElement).not.toBe(firstFilter));
  });
});
