#!/usr/bin/env node
// gen-api-types.mjs — generate the frontend's API types from the SERVED OpenAPI
// contract, so the FE↔BE shape cannot silently drift (SURFACE-005 / EXC-WIRE-04).
//
// Source of truth: internal/api/testdata/openapi.golden.json. That golden is pinned
// by the Go test TestOpenAPIGolden to EQUAL the live spec the binary serves
// (api.New(...).Spec()), so the chain is:
//
//     served spec  ==(TestOpenAPIGolden)==  golden.json  --(this script)-->  api-types.gen.ts  --(tsc)-->  web/src/lib/api.ts
//
// A BE field add/rename/remove changes the served spec; TestOpenAPIGolden forces the
// golden to be regenerated; this script (run in CI via `npm run build`, which calls
// `gen:api -- --check`) then forces api-types.gen.ts to be regenerated, and tsc fails
// the build if web/src/lib/api.ts references a field the generated type no longer has.
// There is no point on that chain where the FE can drift undetected.
//
// Usage:
//   node scripts/gen-api-types.mjs            # (re)write web/src/lib/api-types.gen.ts
//   node scripts/gen-api-types.mjs --check    # verify it is up to date; exit 1 on drift
//
// Deliberately dependency-free (no openapi-typescript/orval) so the contract gate runs
// in `npm ci && npm run build` with nothing else to install — sovereignty/offline.

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(__dirname, "..");
const SPEC = path.resolve(WEB, "..", "internal", "api", "testdata", "openapi.golden.json");
const OUT = path.resolve(WEB, "src", "lib", "api-types.gen.ts");

// tsType maps a (deliberately small) JSON Schema node to a TypeScript type string.
function tsType(schema) {
  if (!schema || typeof schema !== "object") return "unknown";
  if (typeof schema.$ref === "string") {
    // "#/components/schemas/Foo" -> "Foo"
    return schema.$ref.split("/").pop();
  }
  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    return schema.enum.map((v) => JSON.stringify(v)).join(" | ");
  }
  switch (schema.type) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "array":
      {
        const item = tsType(schema.items);
        return item.includes(" | ") ? `(${item})[]` : `${item}[]`;
      }
    case "object":
      if (schema.properties && Object.keys(schema.properties).length > 0) {
        return inlineObject(schema);
      }
      // free-form object (e.g. attributes / data / spec): an index map.
      return "Record<string, unknown>";
    default:
      return "unknown";
  }
}

function inlineObject(schema) {
  const required = new Set(schema.required ?? []);
  const fields = Object.entries(schema.properties)
    .map(([name, prop]) => `${propKey(name)}${required.has(name) ? "" : "?"}: ${tsType(prop)}`)
    .join("; ");
  return `{ ${fields} }`;
}

// propKey quotes a property name only if it is not a plain JS identifier.
function propKey(name) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : JSON.stringify(name);
}

function emitInterface(name, schema) {
  const required = new Set(schema.required ?? []);
  const props = schema.properties ?? {};
  const lines = [`export interface ${name} {`];
  for (const propName of Object.keys(props).sort()) {
    const optional = required.has(propName) ? "" : "?";
    lines.push(`  ${propKey(propName)}${optional}: ${tsType(props[propName])};`);
  }
  lines.push("}");
  return lines.join("\n");
}

function generate() {
  const spec = JSON.parse(readFileSync(SPEC, "utf8"));
  const schemas = spec?.components?.schemas ?? {};
  const names = Object.keys(schemas).sort();

  const header = [
    "// Code generated from the served OpenAPI contract by web/scripts/gen-api-types.mjs.",
    "// DO NOT EDIT by hand. Regenerate with: npm run gen:api",
    "//",
    "// Source: internal/api/testdata/openapi.golden.json (pinned == the served spec by the",
    "// Go test TestOpenAPIGolden). These types are the single FE↔BE contract for the trstctl",
    "// console (SURFACE-005 / EXC-WIRE-04); web/src/lib/api.ts is type-checked against them so",
    "// a backend field change that is not reflected here fails the build instead of silently",
    "// desyncing the SPA.",
    `// OpenAPI: ${spec.openapi}  API: ${spec?.info?.title ?? ""} ${spec?.info?.version ?? ""}`,
    "",
    "/* eslint-disable */",
    "",
  ].join("\n");

  const body = names.map((n) => emitInterface(n, schemas[n])).join("\n\n");
  return header + body + "\n";
}

// generated returns the current contents of the committed generated file (or "").
export function readGenerated() {
  try {
    return readFileSync(OUT, "utf8");
  } catch {
    return "";
  }
}

export { generate, OUT, SPEC, WEB };

function main() {
  const check = process.argv.includes("--check");
  const generated = generate();
  if (check) {
    if (readGenerated() !== generated) {
      console.error(
        `FE↔BE contract drift: ${path.relative(WEB, OUT)} is out of date with the served OpenAPI ` +
          `contract (internal/api/testdata/openapi.golden.json).\n` +
          `Regenerate it with:  npm run gen:api  (or: cd web && node scripts/gen-api-types.mjs)\n` +
          `then review and commit the diff. (SURFACE-005 / EXC-WIRE-04)`,
      );
      process.exit(1);
    }
    console.log(`OK: ${path.relative(WEB, OUT)} matches the served OpenAPI contract.`);
    return;
  }
  writeFileSync(OUT, generated);
  console.log(`wrote ${path.relative(WEB, OUT)} from ${path.relative(WEB, SPEC)}`);
}

// Run as a CLI only when invoked directly (not when imported by a test).
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
