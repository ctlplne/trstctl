import { describe, it, expect } from "vitest";
import { lockedModuleIds, moduleRequiredFeature } from "@/lib/navigation";

/** S-B5: the locked-module upsell mechanism. trstctl's five modules are all
 * MPL-core, so moduleRequiredFeature is empty and no module ever locks — the
 * upsell row is latent by design. This test pins that contract AND exercises
 * the mechanism with a synthetic map so the code path is covered. */

describe("module lock / upsell mechanism (S-B5)", () => {
  it("locks no module today — all five modules are MPL-core", () => {
    expect(Object.keys(moduleRequiredFeature)).toHaveLength(0);
    // Even with nothing licensed, no core module is locked.
    expect(lockedModuleIds(new Set())).toEqual([]);
    expect(lockedModuleIds(new Set(["fips", "byok"]))).toEqual([]);
  });

  it("locks a module iff its required commercial feature is unlicensed", () => {
    // Exercise the real seam a future commercial space would use, then restore
    // the core-only production map so this test cannot leak state.
    moduleRequiredFeature.workload = "software_trust";
    try {
      expect(lockedModuleIds(new Set(["fips"]))).toContain("workload");
      expect(lockedModuleIds(new Set(["software_trust"]))).not.toContain("workload");
    } finally {
      delete moduleRequiredFeature.workload;
    }
  });
});
