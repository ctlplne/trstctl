import { createPublicKey, verify } from "node:crypto";
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
  it.each(["cyclonedx-export.golden.json", "cyclonedx-export-supplement.golden.json", "cyclonedx-served-export.json", "cyclonedx-export-signed.golden.json"])(
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

  // Q3-L1: the BOM's own JSF signature checked by an independent
  // implementation: RFC 8785 written the way the RFC defines it (ECMAScript's
  // JSON serialization, members in JavaScript's UTF-16 string order) and RS256
  // through node:crypto (OpenSSL), with the key from the pinned JWK set.
  const canonicalize = (value: unknown): string => {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map((name) => `${JSON.stringify(name)}:${canonicalize(object[name])}`)
      .join(",")}}`;
  };
  const verifyJSF = (bom: Record<string, unknown>) => {
    const jwks = load("cyclonedx-export-signed.jwks.json") as { keys: Array<{ kty: string; kid: string; n: string; e: string }> };
    const { value, ...signature } = bom.signature as Record<string, unknown>;
    const pinned = jwks.keys.find((k) => k.kid === signature.keyId);
    if (!pinned || signature.algorithm !== "RS256" || typeof value !== "string") return false;
    expect(signature.publicKey).toEqual({ kty: pinned.kty, n: pinned.n, e: pinned.e });
    const key = createPublicKey({ key: { kty: pinned.kty, n: pinned.n, e: pinned.e }, format: "jwk" });
    return verify("sha256", Buffer.from(canonicalize({ ...bom, signature }), "utf8"), key, Buffer.from(value, "base64url"));
  };

  it("verifies the signed BOM's own JSF signature independently, also after reformatting", () => {
    const bom = load("cyclonedx-export-signed.golden.json");
    expect(verifyJSF(bom)).toBe(true);
    const reformatted = JSON.parse(JSON.stringify(bom, null, 2)) as Record<string, unknown>;
    expect(verifyJSF(reformatted)).toBe(true);
    const components = bom.components as Array<Record<string, unknown>>;
    const changed = { ...bom, components: [{ ...components[0], name: "RSA-4096" }, ...components.slice(1)] };
    expect(verifyJSF(changed)).toBe(false);
  });
});
