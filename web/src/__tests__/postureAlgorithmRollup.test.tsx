import { describe, expect, it } from "vitest";
import { rollupByAlgorithm } from "@/pages/Posture";
import type { CBOMAsset } from "@/lib/api";

function asset(overrides: Partial<CBOMAsset> & { id: string }): CBOMAsset {
  return {
    kind: "certificate-key",
    location: "svc.example:443",
    strength: "acceptable",
    quantum_vulnerable: false,
    out_of_policy: false,
    migration_target: "",
    migration_standard: "",
    migration_generation: "migration-required",
    ...overrides,
  } as CBOMAsset;
}

// S-C14: the rollup is where a scan becomes a migration plan, so its grouping,
// ordering, and counting are pinned rather than eyeballed.
describe("CBOM per-algorithm rollup", () => {
  it("groups assets by algorithm and counts exposure per group", () => {
    const rows = rollupByAlgorithm([
      asset({
        id: "a",
        algorithm: "RSA",
        key_bits: 2048,
        quantum_vulnerable: true,
        migration_target: "ML-DSA-65",
        migration_standard: "FIPS 204",
      }),
      asset({
        id: "b",
        algorithm: "RSA",
        key_bits: 2048,
        quantum_vulnerable: true,
        out_of_policy: true,
        migration_target: "ML-DSA-65",
        migration_standard: "FIPS 204",
      }),
      asset({
        id: "c",
        algorithm: "ECDSA",
        key_bits: 256,
        quantum_vulnerable: true,
        migration_target: "ML-DSA-65",
        migration_standard: "FIPS 204",
      }),
    ]);

    expect(rows).toHaveLength(2);
    // Biggest exposure first.
    expect(rows[0].algorithm).toBe("RSA-2048");
    expect(rows[0].total).toBe(2);
    expect(rows[0].quantumVulnerable).toBe(2);
    expect(rows[0].outOfPolicy).toBe(1);
    expect(rows[0].migrationTarget).toBe("ML-DSA-65");
    expect(rows[0].migrationStandard).toBe("FIPS 204");
    expect(rows[1].algorithm).toBe("ECDSA-256");
    expect(rows[1].total).toBe(1);
  });

  it("marks an already post-quantum group as future-ready", () => {
    const rows = rollupByAlgorithm([
      asset({
        id: "pq",
        algorithm: "ML-DSA-65",
        migration_target: "ML-DSA-65",
        migration_standard: "FIPS 204",
        migration_generation: "future-ready",
      }),
    ]);

    expect(rows[0].futureReady).toBe(true);
    expect(rows[0].quantumVulnerable).toBe(0);
  });

  it("keeps hybrid groups migration-required, matching the served posture", () => {
    const rows = rollupByAlgorithm([
      asset({
        id: "hy",
        algorithm: "Hybrid-ML-DSA-44-ECDSA-P256",
        migration_target: "ML-DSA-65",
        migration_standard: "FIPS 204",
        migration_generation: "migration-required",
      }),
    ]);

    expect(rows[0].futureReady).toBe(false);
    expect(rows[0].migrationTarget).toBe("ML-DSA-65");
  });

  it("returns nothing for an empty inventory", () => {
    expect(rollupByAlgorithm([])).toEqual([]);
  });
});
