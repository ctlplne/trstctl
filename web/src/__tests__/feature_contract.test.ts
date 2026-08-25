import { describe, expect, it } from "vitest";
import { generate, generateFromCatalog, loadCanonicalCatalog, readGenerated, validateCatalog } from "../../scripts/gen-feature-contracts.mjs";

describe("canonical frontend capability contract", () => {
  it("keeps the committed TypeScript contract byte-identical to the canonical catalog", () => {
    expect(readGenerated()).toBe(generate());
  });

  it("generates all 79 capabilities from schema version 3", () => {
    const catalog = loadCanonicalCatalog();
    expect(catalog.schema_version).toBe(3);
    expect(catalog.items).toHaveLength(79);
    expect(generateFromCatalog(catalog)).toContain('"featureId": "F66"');
    expect(generateFromCatalog(catalog)).toContain('"maturity": "partial_workflow"');
  });

  it.each([
    [
      "unknown tool",
      (catalog: Record<string, unknown>) => (((catalog.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).tool = "ghost_tool"),
    ],
    [
      "unknown stage status",
      (catalog: Record<string, unknown>) =>
        ((
          (((catalog.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).stages as Record<string, unknown>).discover as Record<
            string,
            unknown
          >
        ).status = "looks_good"),
    ],
    [
      "non-product route",
      (catalog: Record<string, unknown>) =>
        (((catalog.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).console_route = "certificates"),
    ],
    [
      "navigation-only operational evidence",
      (catalog: Record<string, unknown>) => {
        const stages = ((catalog.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).stages as Record<
          string,
          Record<string, unknown>
        >;
        stages.verify = { status: "complete", evidence: ["web/src/lib/navigation.ts"] };
      },
    ],
    [
      "missing evidence file",
      (catalog: Record<string, unknown>) => {
        const stages = ((catalog.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).stages as Record<
          string,
          Record<string, unknown>
        >;
        stages.verify = { status: "complete", evidence: ["web/src/pages/DefinitelyMissingParityControl.tsx"] };
      },
    ],
  ])("rejects a deliberately broken %s", (_name, mutate) => {
    const broken = structuredClone(loadCanonicalCatalog()) as Record<string, unknown>;
    mutate(broken);
    expect(() => validateCatalog(broken)).toThrow();
  });

  it("rejects maturity and release decisions that contradict the stage cells", () => {
    const maturityDrift = structuredClone(loadCanonicalCatalog()) as Record<string, unknown>;
    (((maturityDrift.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).maturity as string) = "absent";
    expect(() => validateCatalog(maturityDrift)).toThrow(/computed maturity/i);

    const releaseDrift = structuredClone(loadCanonicalCatalog()) as Record<string, unknown>;
    (((releaseDrift.items as Array<Record<string, unknown>>)[0].contract as Record<string, unknown>).release_blocking as boolean) = true;
    expect(() => validateCatalog(releaseDrift)).toThrow(/release_blocking/i);
  });
});
