import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppShell } from "@/components/AppShell";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { CommandPalette } from "@/components/CommandPalette";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn(), logout: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

// Directional physical utilities that bias one side and break under RTL. We do
// NOT flag symmetric centering (`left-1/2` paired with `-translate-x-1/2`),
// which is direction-neutral and mirror-safe; we flag inline margin/padding,
// text alignment, and physical borders that have logical equivalents.
const DIRECTIONAL_PHYSICAL = /(^|\s)(ml-|mr-|pl-|pr-|text-left|text-right|border-l-|border-r-|(?:focus:)?left-[0-9]|(?:focus:)?right-[0-9])/;

function classNamesIn(container: HTMLElement): string[] {
  const out: string[] = [];
  container.querySelectorAll<HTMLElement>("*").forEach((el) => {
    if (el.className && typeof el.className === "string") out.push(el.className);
  });
  if (container.className && typeof container.className === "string") out.push(container.className);
  return out;
}

function renderShellRTL() {
  return render(
    <IntlProvider initialLocale="ar-XB" initialTimeZone="UTC">
      <ThemeProvider>
        <AuthProvider>
          <MemoryRouter>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<h1>main</h1>} />
              </Route>
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ThemeProvider>
    </IntlProvider>,
  );
}

describe("RTL logical layout (PRODUCT-003)", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.logout.mockResolvedValue(undefined);
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024, writable: true });
  });

  it("drives document.dir from an RTL locale", async () => {
    renderShellRTL();
    await screen.findByText("u@example.test");
    expect(document.documentElement.dir).toBe("rtl");
  });

  it("AppShell shell chrome uses logical start/end classes, not physical left/right", async () => {
    const { container } = renderShellRTL();
    await screen.findByText("u@example.test");

    // Skip link is the first focusable anchor targeting #main; it must be
    // logical-start anchored, not physical-left.
    const skip = container.querySelector('a[href="#main"]') as HTMLElement;
    expect(skip).not.toBeNull();
    expect(skip.className).toMatch(/focus:start-2/);
    expect(skip.className).not.toMatch(/focus:left-2/);

    // The desktop sidebar uses a logical inline-end border (border-e), not border-r.
    const sidebar = container.querySelector("[class*='border-e']");
    expect(sidebar).not.toBeNull();

    for (const cls of classNamesIn(container)) {
      expect(cls, `directional physical class leaked: ${cls}`).not.toMatch(DIRECTIONAL_PHYSICAL);
    }
  });

  it("DataGrid renders logical text-start and end-0 affordances, no physical equivalents", () => {
    const columns: Array<DataGridColumn<{ id: string; name: string }>> = [
      { id: "name", header: "Name", cell: (r) => r.name, sortable: true },
      { id: "id", header: "Id", cell: (r) => r.id },
    ];
    const { container } = render(
      <DataGrid
        ariaLabel="grid"
        rows={[{ id: "1", name: "alpha" }]}
        columns={columns}
        getRowId={(r) => r.id}
        onSort={() => {}}
        sort={{ columnId: "name", direction: "asc" }}
      />,
    );
    const table = container.querySelector("table");
    expect(table?.className).toMatch(/text-start/);
    expect(table?.className).not.toMatch(/text-left/);

    // Open the column chooser so its absolutely-positioned dropdown renders.
    fireEvent.click(screen.getByRole("button", { name: "Columns" }));
    const dropdown = container.querySelector("[class*='end-0']");
    expect(dropdown).not.toBeNull();

    for (const cls of classNamesIn(container)) {
      expect(cls, `directional physical class leaked: ${cls}`).not.toMatch(DIRECTIONAL_PHYSICAL);
    }
  });

  it("CommandPalette search field uses logical padding and start-anchored icon", () => {
    const { container } = render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>,
    );
    const dialog = screen.getByRole("dialog");
    const search = within(dialog).getByRole("searchbox");
    expect(search.className).toMatch(/ps-9/);
    expect(search.className).toMatch(/pe-3/);
    expect(search.className).not.toMatch(/pl-9/);

    // The search icon is logical-start anchored.
    const icon = dialog.querySelector("[class*='start-3']");
    expect(icon).not.toBeNull();

    for (const cls of classNamesIn(container)) {
      // The centered panel uses symmetric left-1/2 + -translate-x-1/2; allow it.
      if (/-translate-x-1\/2/.test(cls)) continue;
      expect(cls, `directional physical class leaked: ${cls}`).not.toMatch(DIRECTIONAL_PHYSICAL);
    }
  });
});
