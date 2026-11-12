import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";

// Q3: the CycloneDX CBOM export is checked by an independent validator (ajv)
// against the official CycloneDX 1.6 JSON schemas, not by trstctl's own code.
// The Go encoder test writes the golden; the served export test captures what
// the API serves (Q3-L4) and fails when the served shape drifts from it.
const testdata = resolve(process.cwd(), "../internal/cbom/testdata");
const load = (name: string) => JSON.parse(readFileSync(resolve(testdata, name), "utf8")) as Record<string, unknown>;

function validator() {
  const ajv = new Ajv({ schemaId: "auto", unknownFormats: "ignore", allErrors: true });
  ajv.addSchema(load("cyclonedx/spdx.schema.json"));
  ajv.addSchema(load("cyclonedx/jsf-0.82.schema.json"));
  return ajv.compile(load("cyclonedx/bom-1.6.schema.json"));
}

describe("CycloneDX 1.6 CBOM export", () => {
  // Q3-L2: the supplement golden carries certificates, host keys, libraries
  // and observed handshakes beside the inventory's assets.
  it.each(["cyclonedx-export.golden.json", "cyclonedx-export-supplement.golden.json", "cyclonedx-served-export.json"])(
    "%s validates against the official CycloneDX 1.6 schema",
    (name) => {
      const validate = validator();
      const bom = load(name);
      const valid = validate(bom);
      expect(validate.errors ?? []).toEqual([]);
      expect(valid).toBe(true);
      expect(bom.specVersion).toBe("1.6");
    },
  );

  it("rejects a document the schema forbids, so the check is live", () => {
    const validate = validator();
    const bom = load("cyclonedx-export.golden.json");
    const components = bom.components as Array<Record<string, unknown>>;
    const broken = { ...bom, components: [{ ...components[0], cryptoProperties: { assetType: "not-an-asset-type" } }] };
    expect(validate(broken)).toBe(false);
  });
});
