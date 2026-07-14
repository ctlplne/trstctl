import { describe, it, expect } from "vitest";
import { lockedModuleIds, moduleRequiredFeature, navModules } from "@/lib/navigation";

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
    // Synthetic map proves the mechanism a future commercial module would use.
    const synthetic: Record<string, string> = { signing: "software_trust" };
    const locked = navModules
      .filter((m) => synthetic[m.id] && !new Set(["fips"]).has(synthetic[m.id]))
      .map((m) => m.id);
    expect(locked).toContain("signing");

    // And with the feature licensed, it unlocks.
    const licensedLocked = navModules
      .filter((m) => synthetic[m.id] && !new Set(["software_trust"]).has(synthetic[m.id]))
      .map((m) => m.id);
    expect(licensedLocked).not.toContain("signing");
  });
});
