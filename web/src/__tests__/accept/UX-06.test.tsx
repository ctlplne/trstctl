import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";

type Row = { id: string; name: string; owner: string };

const rows: Row[] = [{ id: "row-1", name: "payments-api", owner: "platform" }];
const columns: Array<DataGridColumn<Row>> = [
  { id: "name", header: "Name", cell: (row) => row.name },
  { id: "owner", header: "Owner", hiddenByDefault: true, cell: (row) => row.owner },
];

describe("UX-06 DataGrid optional view controls", () => {
  it("keeps saved views and the column chooser behind one calm disclosure when a page opts in", async () => {
    const user = userEvent.setup();
    const plain = render(
      <MemoryRouter>
        <DataGrid ariaLabel="Plain credential rows" rows={rows} columns={columns} getRowId={(row) => row.id} />
      </MemoryRouter>,
    );

    expect(screen.getByRole("table", { name: "Plain credential rows" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /columns/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Saved view name")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save view" })).not.toBeInTheDocument();

    plain.unmount();

    render(
      <MemoryRouter>
        <DataGrid
          ariaLabel="Configured credential rows"
          rows={rows}
          columns={columns}
          getRowId={(row) => row.id}
          showColumnChooser
          viewStorageKey="ux-06-grid"
          toolbar={({ columnChooser, savedViews }) => <DataGridToolbar columnChooser={columnChooser} savedViews={savedViews} />}
        />
      </MemoryRouter>,
    );

    expect(screen.getByRole("table", { name: "Configured credential rows" })).toBeInTheDocument();
    const viewOptions = screen.getByRole("button", { name: "View options" });
    expect(viewOptions).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: /columns/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Saved view name")).not.toBeInTheDocument();

    await user.click(viewOptions);

    expect(viewOptions).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("button", { name: /columns/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Saved view name")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save view" })).toBeInTheDocument();
  });
});
