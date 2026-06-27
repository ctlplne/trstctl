import { describe, it, expect, beforeEach } from "vitest";
import { readGridPreferences, writeGridPreferences, sanitizeViewMetadata, type SavedGridView } from "@/lib/gridViews";
import { toCSV } from "@/lib/csv";

describe("U8-3 saved views & export", () => {
  beforeEach(() => globalThis.localStorage?.clear());

  it("saves and restores a per-inventory grid view (columns, sort, filter metadata)", () => {
    const view: SavedGridView = {
      id: "v1",
      name: "Expiring ≤30d",
      createdAt: "2026-06-20T00:00:00Z",
      columnOrder: ["subject", "expires"],
      visibleColumnIds: ["subject", "expires"],
      sort: { columnId: "expires", direction: "asc" },
      metadata: { expiry: "30d" },
    };
    writeGridPreferences("certs", { views: [view] });
    const restored = readGridPreferences("certs");
    expect(restored.views).toHaveLength(1);
    expect(restored.views[0]).toMatchObject({ id: "v1", name: "Expiring ≤30d", sort: { columnId: "expires", direction: "asc" } });
  });

  it("never persists sensitive filter metadata into a saved view", () => {
    expect(sanitizeViewMetadata({ env: "prod", token: "trst_abc", note: "ok" })).toEqual({ env: "prod", note: "ok" });
  });

  it("exports rows to CSV with quoting for embedded commas", () => {
    const csv = toCSV(
      ["subject", "status"],
      [
        { subject: "CN=a", status: "active" },
        { subject: "CN=b, OU=eng", status: "revoked" },
      ],
    );
    expect(csv).toBe('subject,status\nCN=a,active\n"CN=b, OU=eng",revoked');
  });
});
