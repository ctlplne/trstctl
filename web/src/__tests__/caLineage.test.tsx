import { describe, expect, it } from "vitest";
import { buildCALineage, flattenCALineage, isOfflineRoot } from "@/pages/cahierarchy/CAHierarchyPageParts";
import type { CAAuthority } from "@/lib/api";

function ca(id: string, overrides: Partial<CAAuthority> = {}): CAAuthority {
  return {
    id,
    tenant_id: "tenant-1",
    common_name: id,
    kind: "intermediate",
    status: "active",
    serial: "01",
    signer_handle: `handle-${id}`,
    certificate_pem: "",
    created_at: "2026-01-01T00:00:00Z",
    max_path_len: 0,
    ...overrides,
  } as CAAuthority;
}

// S-C12: the tree is how an operator answers "what signs what", so its
// rooting, depth, and its refusal to lose or loop on a CA are pinned.
describe("CA lineage", () => {
  it("nests intermediates under their parent with increasing depth", () => {
    const rows = flattenCALineage(
      buildCALineage([ca("root", { kind: "root" }), ca("issuing", { parent_id: "root" }), ca("leaf-ca", { parent_id: "issuing" })]),
    );

    expect(rows.map((row) => [row.authority.id, row.depth])).toEqual([
      ["root", 0],
      ["issuing", 1],
      ["leaf-ca", 2],
    ]);
  });

  it("roots an authority whose parent is not in the served page, rather than dropping it", () => {
    // A missing ancestor must never hide a live CA from the operator.
    const rows = flattenCALineage(buildCALineage([ca("orphan", { parent_id: "not-in-this-page" })]));
    expect(rows).toHaveLength(1);
    expect(rows[0].depth).toBe(0);
  });

  it("supports multiple roots", () => {
    const roots = buildCALineage([ca("root-a", { kind: "root" }), ca("root-b", { kind: "root" })]);
    expect(roots).toHaveLength(2);
  });

  it("terminates on a parent cycle instead of recursing forever", () => {
    const rows = flattenCALineage(buildCALineage([ca("a", { parent_id: "b" }), ca("b", { parent_id: "a" })]));
    // Both CAs still appear exactly once.
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((row) => row.authority.id))).toEqual(new Set(["a", "b"]));
  });

  it("recognizes an offline root by kind", () => {
    expect(isOfflineRoot(ca("r", { kind: "offline_root" }))).toBe(true);
    expect(isOfflineRoot(ca("r", { kind: "root" }))).toBe(false);
  });

  it("returns an empty forest for no authorities", () => {
    expect(buildCALineage([])).toEqual([]);
  });
});
