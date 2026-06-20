import { readFileSync } from "node:fs";
import path from "node:path";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataGrid, type DataGridSort } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { StatusBadge } from "@/components/StatusBadge";
import { describeStatus, expiryBandForDate, riskBand } from "@/lib/statusVocab";

const webRoot = process.cwd();
const css = readFileSync(path.join(webRoot, "src/index.css"), "utf8");
const tailwind = readFileSync(path.join(webRoot, "tailwind.config.js"), "utf8");
const agentsSource = readFileSync(path.join(webRoot, "src/pages/Agents.tsx"), "utf8");
const certsSource = readFileSync(path.join(webRoot, "src/pages/Certificates.tsx"), "utf8");
const riskSource = readFileSync(path.join(webRoot, "src/pages/Risk.tsx"), "utf8");

type Row = { id: string; name: string; status: string; owner: string };

const rows: Row[] = [
  { id: "r1", name: "payments-api", status: "active", owner: "platform" },
  { id: "r2", name: "worker", status: "revoked", owner: "security" },
];

const columns = [
  { id: "name", header: "Name", sortable: true, cell: (row: Row) => row.name },
  {
    id: "status",
    header: "Status",
    cell: (row: Row) => <StatusBadge vocabulary="certificate" value={row.status} />,
  },
  { id: "owner", header: "Owner", hiddenByDefault: true, cell: (row: Row) => row.owner },
];

describe("Clarity/Console design-system foundation", () => {
  it("exposes brand, honesty, risk, density, type, and elevation tokens", () => {
    for (const token of [
      "--brand-accent",
      "--console-accent",
      "--operate",
      "--observe",
      "--disclose",
      "--risk-critical",
      "--risk-high",
      "--risk-medium",
      "--risk-low",
      "--density-compact",
      "--font-size-heading",
      "--elevation-2",
    ]) {
      expect(css).toContain(token);
    }

    for (const themeKey of ["brand", "console", "operate", "observe", "disclose", "risk", "fontSize", "elevation2"]) {
      expect(tailwind).toContain(themeKey);
    }
  });

  it("uses type, density, and elevation tokens in representative card primitives", () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Evidence queue</CardTitle>
        </CardHeader>
        <CardContent>Token-backed card body</CardContent>
      </Card>,
    );

    expect(screen.getByText("Evidence queue")).toHaveClass("text-title");
    expect(screen.getByText("Token-backed card body")).toHaveClass("text-body");
    expect(screen.getByText("Evidence queue").closest(".rounded-panel")).toHaveClass("shadow-elevation1");
  });

  it("renders shared StatusBadge labels from one vocabulary and real token classes", async () => {
    const { container } = render(
      <div>
        <StatusBadge vocabulary="certificate" value="revoked" />
        <StatusBadge vocabulary="expiry" value="critical" />
        <StatusBadge vocabulary="honesty" value="disclose" />
        <StatusBadge vocabulary="risk" value={riskBand(95)} />
      </div>,
    );

    expect(screen.getByText("revoked")).toHaveAttribute("data-status-badge", "certificate");
    expect(screen.getByText("<7d critical")).toHaveClass("text-risk-critical");
    expect(screen.getByText("Disclose")).toHaveClass("text-disclose");
    expect(screen.getByText("Critical")).toHaveClass("text-risk-critical");
    expect(describeStatus("agent", "online")).toMatchObject({ label: "online", tone: "success" });
    expect(expiryBandForDate(new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString())).toBe("critical");

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("removes bespoke status chip definitions and uses StatusBadge in representative pages", () => {
    expect(agentsSource).not.toMatch(/function\s+StatusChip/);
    expect(certsSource).not.toMatch(/function\s+Chip|function\s+statusChip|function\s+expiryBand/);
    for (const source of [agentsSource, certsSource, riskSource]) {
      expect(source).toMatch(/StatusBadge/);
    }
  });
});

describe("shared DataGrid", () => {
  it("renders configured columns, token-backed badges, sorting, and column chooser", async () => {
    const user = userEvent.setup();
    const onSort = vi.fn();
    const { container } = render(
      <MemoryRouter>
        <DataGrid
          ariaLabel="Credential rows"
          rows={rows}
          columns={columns}
          getRowId={(row) => row.id}
          sort={{ columnId: "name", direction: "asc" }}
          onSort={onSort}
        />
      </MemoryRouter>,
    );

    expect(screen.getByRole("table", { name: "Credential rows" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /name/i })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /owner/i })).not.toBeInTheDocument();
    expect(screen.getByText("revoked")).toHaveAttribute("data-status-badge", "certificate");

    await user.click(screen.getByRole("button", { name: /name/i }));
    expect(onSort).toHaveBeenCalledWith({ columnId: "name", direction: "desc" } satisfies DataGridSort);

    await user.click(screen.getByRole("button", { name: /columns/i }));
    await user.click(screen.getByLabelText("Owner"));
    expect(screen.getByRole("columnheader", { name: /owner/i })).toBeInTheDocument();
    expect(screen.getByText("platform")).toBeInTheDocument();

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it("renders the five standard list states through shared primitives", () => {
    for (const [state, primitive] of [
      ["loading", "loading"],
      ["empty", "empty"],
      ["error", "error"],
      ["permission-denied", "permission-denied"],
      ["unavailable", "unavailable"],
    ] as const) {
      const { container, unmount } = render(
        <MemoryRouter>
          <DataGrid
            ariaLabel={`${state} rows`}
            rows={[]}
            columns={columns}
            getRowId={(row) => row.id}
            state={state}
            stateTitle={`${state} title`}
            stateMessage={`${state} message`}
          />
        </MemoryRouter>,
      );
      expect(container.querySelector(`[data-state-primitive="${primitive}"]`)).toBeInTheDocument();
      unmount();
    }
  });

  it("renders a reusable toolbar with search, filters, bulk slot, and the grid column chooser", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <MemoryRouter>
        <ToolbarGridHarness />
      </MemoryRouter>,
    );

    expect(screen.getByRole("searchbox", { name: "Search credential rows" })).toBeInTheDocument();
    expect(screen.getByText("Owner filter")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /bulk rotate/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /columns/i })).toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: "Search credential rows" }), "worker");
    expect(screen.getByText("worker")).toBeInTheDocument();
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /columns/i }));
    await user.click(screen.getByLabelText("Owner"));
    expect(screen.getByRole("columnheader", { name: /owner/i })).toBeInTheDocument();

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});

function ToolbarGridHarness() {
  const [query, setQuery] = useState("");
  const filtered = rows.filter((row) => row.name.toLowerCase().includes(query.toLowerCase()));
  return (
    <DataGrid
      ariaLabel="Toolbar credential rows"
      rows={filtered}
      columns={columns}
      getRowId={(row) => row.id}
      toolbar={({ columnChooser }) => (
        <DataGridToolbar
          searchLabel="Search credential rows"
          searchPlaceholder="Search by name"
          searchValue={query}
          onSearchChange={setQuery}
          filters={<span>Owner filter</span>}
          bulkActions={<ButtonLike>Bulk rotate</ButtonLike>}
          columnChooser={columnChooser}
        />
      )}
    />
  );
}

function ButtonLike({ children }: { children: string }) {
  return <button type="button">{children}</button>;
}

function DrawerHarness() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  return (
    <div>
      <button ref={triggerRef} type="button" onClick={() => setOpen(true)}>
        Open credential detail
      </button>
      <DetailDrawer
        open={open}
        title="payments-api"
        description="Fetched from the served credential detail API."
        actions={<button type="button">Request renewal</button>}
        onClose={() => setOpen(false)}
        returnFocusRef={triggerRef}
      >
        <dl>
          <div>
            <dt>Status</dt>
            <dd>
              <StatusBadge vocabulary="certificate" value="active" />
            </dd>
          </div>
        </dl>
      </DetailDrawer>
    </div>
  );
}

describe("shared DetailDrawer", () => {
  it("opens with resource fields and actions, closes with Escape, and returns focus", async () => {
    const user = userEvent.setup();
    const { container } = render(<DrawerHarness />);
    const trigger = screen.getByRole("button", { name: /open credential detail/i });

    await user.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "payments-api" });
    expect(within(dialog).getByText("Fetched from the served credential detail API.")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /request renewal/i })).toBeInTheDocument();
    expect(within(dialog).getByText("active")).toHaveAttribute("data-status-badge", "certificate");
    expect(within(dialog).getByRole("button", { name: /close/i })).toHaveFocus();

    const results = await axe(container);
    expect(results).toHaveNoViolations();

    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "payments-api" })).not.toBeInTheDocument());
    expect(trigger).toHaveFocus();
  });
});
