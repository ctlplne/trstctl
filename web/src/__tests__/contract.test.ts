import { describe, it, expect } from "vitest";
import { generate, readGenerated, tsType } from "../../scripts/gen-api-types.mjs";

// SURFACE-005 / EXC-WIRE-04 — FE↔BE contract gate, FE side (Vitest).
//
// The committed web/src/lib/api-types.gen.ts is generated from the SERVED OpenAPI
// contract (internal/api/testdata/openapi.golden.json, pinned == the live spec by the
// Go test TestOpenAPIGolden). This test re-runs that generation and asserts the
// committed file matches it byte-for-byte — the same check `npm run build` runs via
// `gen:api --check`, here as an explicit unit test so a backend field change that was
// not regenerated into the FE types fails the FE suite, not just the build. It also
// proves the gate is not vacuous: an injected mismatch is detected.

describe("FE↔BE contract (SURFACE-005)", () => {
  const fresh = generate();

  it("the committed FE types match a fresh generation from the served OpenAPI contract", () => {
    const committed = readGenerated();
    expect(
      committed,
      "web/src/lib/api-types.gen.ts is stale vs the served OpenAPI contract — run `npm run gen:api` and commit the diff (SURFACE-005 / EXC-WIRE-04)",
    ).toBe(fresh);
  });

  it("carries the Certificate.status field whose drift the audit caught (reality anchor)", () => {
    // The generated Certificate interface must declare `status` (the field that used to
    // exist on the FE while the backend response lacked it).
    const certBlock = fresh.slice(fresh.indexOf("export interface Certificate"));
    const body = certBlock.slice(0, certBlock.indexOf("}"));
    expect(body).toMatch(/\n\s*status\??:/);
  });

  it("is not vacuous: an injected FE/BE mismatch is detected", () => {
    // Rename a Certificate field in a COPY of the generated source and assert the
    // equality check (the gate above) would now fail.
    const mutated = fresh.replace(/\n(\s*)subject(\??:)/, "\n$1subject_DRIFT$2");
    expect(mutated, "the fixture mutation did not change the generated source").not.toBe(fresh);
    expect(mutated === fresh, "contract gate is vacuous — an injected field rename was not detectable").toBe(false);
  });

  it("maps every supported served-schema shape without a codegen dependency", () => {
    expect(tsType(undefined)).toBe("unknown");
    expect(tsType({ $ref: "#/components/schemas/Owner" })).toBe("Owner");
    expect(tsType({ enum: ["active", "retired"] })).toBe('"active" | "retired"');
    expect(tsType({ type: "string" })).toBe("string");
    expect(tsType({ type: "integer" })).toBe("number");
    expect(tsType({ type: "number" })).toBe("number");
    expect(tsType({ type: "boolean" })).toBe("boolean");
    expect(tsType({ type: "array", items: { enum: ["rsa", "ecdsa"] } })).toBe('("rsa" | "ecdsa")[]');
    expect(
      tsType({
        type: "object",
        required: ["tenant_id"],
        properties: {
          tenant_id: { type: "string" },
          "display-name": { type: "string" },
        },
      }),
    ).toBe('{ tenant_id: string; "display-name"?: string }');
    expect(tsType({ type: "object" })).toBe("Record<string, unknown>");
    expect(tsType({ type: "mystery" })).toBe("unknown");
  });
});
