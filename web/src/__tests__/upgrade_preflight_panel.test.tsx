import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { AppQueryProvider } from "@/lib/query";
import type { UpgradePreflight } from "@/lib/api";
import { UpgradePreflightPanel } from "@/components/UpgradePreflightPanel";

const { read } = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, upgradePreflight: read } };
});

const verdict = (): UpgradePreflight => ({
  format: "trstctl.upgrade-preflight.v1",
  generated_at: "2026-11-12T06:00:00Z",
  ready: false,
  schema_version: 446,
  binary_version: 448,
  pending: [
    { version: 447, name: "0447_secret_scoped_sync_approved_mode.sql", destructive: false, transactional: true },
    { version: 448, name: "0448_drop_retired_snapshots.sql", destructive: true, transactional: false },
  ],
  checksum_mismatches: [],
  newer_than_binary: [],
  invalid_indexes: [],
  lock_held: false,
  backup: { configured: true, verified: true, taken_at: "2026-11-10T06:00:00Z", fresh: false },
  blockers: [{ code: "backup_required", detail: "no verified backup from the last 26 hours is visible to restore" }],
  warnings: [{ code: "outside_transaction", detail: "0448_drop_retired_snapshots.sql runs outside a transaction" }],
  rollback: { method: "restore_backup", detail: "destructive: 0448_drop_retired_snapshots.sql." },
});

function show() {
  return render(
    <AppQueryProvider>
      <UpgradePreflightPanel />
    </AppQueryProvider>,
  );
}

describe("upgrade readiness (A246-L1)", () => {
  afterEach(() => {
    cleanup();
    read.mockReset();
  });

  it("shows what an upgrade would apply, what stops it and how it is rolled back", async () => {
    read.mockResolvedValue(verdict());
    show();
    expect(await screen.findByText("Not ready")).toBeInTheDocument();
    expect(screen.getByText("Schema 446, this build 448, 2 migration(s) to apply")).toBeInTheDocument();
    expect(screen.getByText("0448_drop_retired_snapshots.sql")).toBeInTheDocument();
    expect(screen.getByText("destructive")).toBeInTheDocument();
    expect(screen.getByText("outside a transaction")).toBeInTheDocument();
    expect(screen.getByText("backup_required")).toBeInTheDocument();
    expect(screen.getByText("Rolled back by restoring a backup.")).toBeInTheDocument();
    expect(screen.getByText("No verified backup from the last 26 hours is visible here.")).toBeInTheDocument();
  });

  it("says a database at this build's version is ready with nothing to apply", async () => {
    read.mockResolvedValue({
      ...verdict(),
      ready: true,
      schema_version: 448,
      pending: [],
      blockers: [],
      warnings: [],
      backup: { configured: true, verified: true, taken_at: "2026-11-12T05:00:00Z", fresh: true },
      rollback: { method: "none", detail: "this binary applies no migrations: rolling back is running the previous binary" },
    });
    show();
    expect(await screen.findByText("Ready")).toBeInTheDocument();
    expect(screen.getByText("Schema 448, this build 448, 0 migration(s) to apply")).toBeInTheDocument();
    expect(screen.getByText("Nothing to apply.")).toBeInTheDocument();
    expect(screen.getByText("Latest verified backup: 2026-11-12T05:00:00Z.")).toBeInTheDocument();
    expect(screen.queryByText("What stops it")).not.toBeInTheDocument();
  });
});
