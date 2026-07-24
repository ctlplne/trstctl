import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { DataGrid, type DataGridSort } from "@/components/DataGrid";
import { CredentialChip } from "@/components/CredentialChip";
import { StatusBadge } from "@/components/StatusBadge";

/** The workhorse list surface: sortable columns, row-open affordance,
 * selection + bulk slot, and the five list states. Fixture rows are plain
 * strings — story copy stays out of the i18n catalog by design. */

type CertRow = {
  id: string;
  subject: string;
  issuer: string;
  status: "issued" | "requested" | "revoked";
  fingerprint: string;
  expiresInDays: number;
};

const rows: CertRow[] = [
  {
    id: "c1",
    subject: "payments.example.com",
    issuer: "trstctl Issuing CA 1",
    status: "issued",
    fingerprint: "SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
    expiresInDays: 61,
  },
  {
    id: "c2",
    subject: "web.example.com",
    issuer: "trstctl Issuing CA 1",
    status: "issued",
    fingerprint: "SHA256:60303ae22b998861bce3b28f33eec1be758a213c",
    expiresInDays: 6,
  },
  {
    id: "c3",
    subject: "spiffe://prod/checkout",
    issuer: "trstctl Workload CA",
    status: "requested",
    fingerprint: "SHA256:fd61a03af4f77d870fc21e05e7e80678095c92d8",
    expiresInDays: 89,
  },
  {
    id: "c4",
    subject: "legacy.example.com",
    issuer: "Corp Root 2019",
    status: "revoked",
    fingerprint: "SHA256:a4e624d686e03ed2767c0abd85c14426b0b1157d",
    expiresInDays: -3,
  },
];

const columns = [
  { id: "subject", header: "Subject", cell: (row: CertRow) => <span className="font-medium">{row.subject}</span>, sortable: true },
  { id: "issuer", header: "Issuer", cell: (row: CertRow) => row.issuer, hiddenByDefault: false },
  { id: "status", header: "Status", cell: (row: CertRow) => <StatusBadge vocabulary="lifecycle" value={row.status} /> },
  { id: "fingerprint", header: "Fingerprint", cell: (row: CertRow) => <CredentialChip value={row.fingerprint} label="fingerprint" /> },
  { id: "expires", header: "Expires", cell: (row: CertRow) => (row.expiresInDays < 0 ? "expired" : `${row.expiresInDays}d`), sortable: true },
];

// Annotated (not `satisfies`) with an instantiation expression: story args
// must type-check against CertRow, and `satisfies` would keep the inferred
// generic signature where Row collapses to unknown.
const meta: Meta<typeof DataGrid<CertRow>> = {
  title: "Components/DataGrid",
  component: DataGrid,
};

export default meta;
type Story = StoryObj<typeof meta>;

const baseArgs = { ariaLabel: "Certificates", rows, columns, getRowId: (row: CertRow) => row.id };

function SortableGrid() {
  const [sort, setSort] = useState<DataGridSort>({ columnId: "expires", direction: "asc" });
  const sorted = [...rows].sort((a, b) => {
    const delta = sort.columnId === "expires" ? a.expiresInDays - b.expiresInDays : a.subject.localeCompare(b.subject);
    return sort.direction === "asc" ? delta : -delta;
  });
  return <DataGrid {...baseArgs} rows={sorted} sort={sort} onSort={setSort} onRowOpen={() => {}} rowActionLabel={(row) => `View ${row.subject}`} />;
}

export const Ready: Story = {
  args: baseArgs,
  render: () => <SortableGrid />,
};

function SelectableGrid() {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set(["c2"]));
  return (
    <DataGrid
      {...baseArgs}
      selection={{ selectedIds, onSelectedIdsChange: setSelectedIds, getRowLabel: (row) => row.subject }}
      bulkSlot={
        selectedIds.size > 0 && (
          <p className="text-body text-muted-foreground">{selectedIds.size} selected — bulk actions render here (renew, assign owner, revoke).</p>
        )
      }
    />
  );
}

export const WithSelection: Story = {
  args: baseArgs,
  render: () => <SelectableGrid />,
};

export const Loading: Story = {
  args: { ...baseArgs, rows: [], state: "loading", stateMessage: "Loading certificates…" },
};

export const Empty: Story = {
  args: {
    ...baseArgs,
    rows: [],
    state: "empty",
    stateTitle: "No certificates yet",
    stateMessage: "Run discovery or add your first certificate to populate the inventory.",
  },
};

export const ErrorRow: Story = {
  name: "Error",
  args: { ...baseArgs, rows: [], state: "error", stateTitle: "Could not load certificates", stateMessage: "The inventory endpoint returned 502." },
};

export const PermissionDenied: Story = {
  args: { ...baseArgs, rows: [], state: "permission-denied", stateMessage: "Your role does not include certificate:read." },
};
