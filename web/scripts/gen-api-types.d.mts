// Type declarations for the dependency-free contract codegen (gen-api-types.mjs), so
// the Vitest contract test (src/__tests__/contract.test.ts) and `npm run typecheck` can
// import its pure functions without an implicit-any error.

/** generate returns the TypeScript source for web/src/lib/api-types.gen.ts, built from
 * the served OpenAPI golden (internal/api/testdata/openapi.golden.json). */
export function generate(): string;

/** readGenerated returns the current contents of the committed generated file, or ""
 * if it does not exist. */
export function readGenerated(): string;

export const OUT: string;
export const SPEC: string;
export const WEB: string;
