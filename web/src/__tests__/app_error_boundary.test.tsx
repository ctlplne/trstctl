import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppErrorBoundary } from "@/components/AppErrorBoundary";

function BrokenPage(): never {
  throw new Error("fixture route crashed with tenant-secret-that-must-not-render");
}

describe("application error recovery", () => {
  const preventFixtureErrorReport = (event: ErrorEvent) => event.preventDefault();

  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    window.addEventListener("error", preventFixtureErrorReport);
  });

  afterEach(() => {
    window.removeEventListener("error", preventFixtureErrorReport);
    vi.restoreAllMocks();
  });

  it("contains an unexpected route crash without exposing exception data", async () => {
    const onReload = vi.fn();
    const onHome = vi.fn();
    const user = userEvent.setup();

    render(
      <IntlProvider>
        <AppErrorBoundary onReload={onReload} onHome={onHome}>
          <BrokenPage />
        </AppErrorBoundary>
      </IntlProvider>,
    );

    expect(screen.getByRole("heading", { name: "This page stopped unexpectedly" })).toBeInTheDocument();
    expect(screen.getByText(/did not delete certificates, events, or server data/i)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("tenant-secret-that-must-not-render");
    await user.click(screen.getByRole("button", { name: "Reload page" }));
    await user.click(screen.getByRole("button", { name: "Home" }));
    expect(onReload).toHaveBeenCalledTimes(1);
    expect(onHome).toHaveBeenCalledTimes(1);
  });
});
