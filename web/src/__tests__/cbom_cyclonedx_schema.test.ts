import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { domainToASCII } from "node:url";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";

// Q3: the CycloneDX CBOM export is checked by an independent validator (ajv)
// against the official CycloneDX 1.6 JSON schemas, not by trstctl's own code.
// The Go encoder test writes the golden; the served export test captures what
// the API serves (Q3-L4) and fails when the served shape drifts from it.
const testdata = resolve(process.cwd(), "../internal/cbom/testdata");
const load = (name: string) => JSON.parse(readFileSync(resolve(testdata, name), "utf8")) as Record<string, unknown>;

// Q3-L3: Ajv 6 knows no IRI or IDN format, and ignoring the unknown ones left
// every iri-reference and idn-email in the schema unchecked. They are checked
// through Ajv's own RFC 3986 and RFC 5322 rules ("full" mode): an IRI is a URI
// whose non-ASCII characters map to their UTF-8 percent-encoding (RFC 3987
// section 3.1), and an internationalized address (RFC 6531) has an IDN domain
// checked in its ASCII form (RFC 5890) and a local part that may hold any
// non-ASCII letter. Any other format the schemas name fails the compile.
function strict(format: string) {
  const check = new Ajv({ format: "full" }).compile({ type: "string", format });
  return (value: string) => Boolean(check(value));
}
const uriReference = strict("uri-reference");
const uri = strict("uri");
const email = strict("email");
const hostname = strict("hostname");
const nonASCII = /[^\p{ASCII}]/gu;
const iriToURI = (iri: string) => iri.replace(nonASCII, (c) => encodeURIComponent(c));
const idnFormats: Record<string, (value: string) => boolean> = {
  "iri-reference": (value) => uriReference(iriToURI(value)),
  iri: (value) => uri(iriToURI(value)),
  "idn-hostname": (value) => {
    const ascii = domainToASCII(value);
    return ascii !== "" && hostname(ascii);
  },
  "idn-email": (value) => {
    const at = value.lastIndexOf("@");
    if (at < 1) return false;
    const domain = domainToASCII(value.slice(at + 1));
    return domain !== "" && email(value.slice(0, at).replace(nonASCII, "a") + "@" + domain);
  },
};

function strictAjv() {
  const ajv = new Ajv({ schemaId: "auto", unknownFormats: true, allErrors: true });
  for (const [name, check] of Object.entries(idnFormats)) ajv.addFormat(name, check);
  return ajv;
}

function validator() {
  const ajv = strictAjv();
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

  // Q3-L3: the IRI and IDN formats the schema names are checked, and a format
  // the validator does not know fails rather than passes.
  it("rejects a malformed iri-reference or idn-email and an unknown format (Q3-L3)", () => {
    const validate = validator();
    const bom = load("cyclonedx-export.golden.json");
    const components = bom.components as Array<Record<string, unknown>>;
    const withReference = (url: string) => ({
      ...bom,
      components: [{ ...components[0], externalReferences: [{ type: "website", url }] }, ...components.slice(1)],
    });
    expect(validate(withReference("https://例え.テスト/パス?q=値#frag"))).toBe(true);
    expect(validate(withReference("https://inventory.example.test/a%20b"))).toBe(true);
    expect(validate(withReference("http://[not-an-address/"))).toBe(false);
    expect(validate(withReference("https://inventory.example.test/a b"))).toBe(false);
    const metadata = bom.metadata as Record<string, unknown>;
    const withAuthor = (address: string) => ({ ...bom, metadata: { ...metadata, authors: [{ name: "Owner", email: address }] } });
    expect(validate(withAuthor("dörte@exämple.test"))).toBe(true);
    expect(validate(withAuthor("owner@example.test"))).toBe(true);
    expect(validate(withAuthor("not an address"))).toBe(false);
    expect(validate(withAuthor("owner@-bad-.test"))).toBe(false);
    expect(() => strictAjv().compile({ type: "string", format: "no-such-format" })).toThrow(/unknown format/);
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
