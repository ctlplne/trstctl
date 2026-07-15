# @trstctl/sdk — TypeScript client SDK

A typed TypeScript client for the trstctl control-plane REST API. Resource
**types are generated** from the served OpenAPI 3.1 contract; a small,
**dependency-free** runtime adds auth, idempotency, retries, RFC 7807
problem+json errors, and cursor pagination.

- Runtime requirement: a global `fetch` (Node 18+, Deno, or a browser).
- Pinned to `clients/sdk/openapi.json` (== the served spec; see the repo-level
  `clients/sdk/README.md`), so types cannot silently drift from the API.

## Generate the types

The generator is `openapi-typescript` (pure JS, runs via `npx` — nothing to
pre-install). The command is pinned to the published spec:

```bash
# from clients/sdk/typescript
npx openapi-typescript ../openapi.json -o ./src/types.gen.ts
# equivalently:
npm run gen
# or, from the repo root, regenerate every SDK and re-pin the spec:
make sdk
```

`src/index.ts` imports those generated types and exports `TrstctlClient`.

## Install

This SDK lives in-repo. To consume it from another project, either copy the
`typescript/` directory, publish it to your registry, or add it as a path/git
dependency. Then:

```ts
import { TrstctlClient, isProblem } from "@trstctl/sdk";
```

The package metadata is publish-ready for the public registry namespace:

```bash
npm pack --dry-run
npm publish --access public
```

## Test

```bash
npm run typecheck
npm test
```

`npm test` compiles `src/index.ts` and runs the client against a deterministic
`fetch` implementation. The suite covers bearer auth, optional tenant headers,
the owner/identity/certificate helpers, cursor pagination, stable
`Idempotency-Key` reuse across mutation retries, `Retry-After`, and typed
`problem+json` errors.

## Quickstart — getting-started flow

```ts
import { TrstctlClient, isProblem } from "@trstctl/sdk";

const client = new TrstctlClient({
  baseUrl: "https://localhost:8443",
  token: "trst_...",                 // sent as Authorization: Bearer on every call
  // tenant: "1111...",              // optional X-Tenant-ID hint
  // retry: { maxAttempts: 4, baseDelayMs: 200, maxDelayMs: 5000 },
});

// owner -> identity -> transition "issued", each with an auto Idempotency-Key.
const ident = await client.issueFirstCertificate("payments");
console.log(`issued ${ident.id} (${ident.status})`);
```

## Auth

The token is sent as `Authorization: Bearer <token>` on every request. Set
`tenant` to also send `X-Tenant-ID` (a lookup hint for header/dev auth and
machine-login flows).

## Idempotency-Key (AN-5)

Every mutation (`POST`/`PUT`/`DELETE`) carries an `Idempotency-Key`. If you do
not pass one it is auto-generated and **held stable across the SDK's automatic
retries**, so a retried create is exactly-once. Supply your own for
cross-restart stability:

```ts
await client.createOwner({ kind: "workload", name: "payments" }, "my-stable-key");
```

## problem+json errors (RFC 7807)

Non-2xx responses throw a typed `TrstctlProblem`:

```ts
try {
  await client.getIdentity("missing");
} catch (err) {
  if (isProblem(err)) {
    // err.httpStatus, err.type, err.title, err.status, err.detail,
    // err.instance, err.extensions, err.isRateLimited, err.retryAfterSeconds
    console.error(`${err.httpStatus} ${err.title}: ${err.detail}`);
  } else {
    throw err;
  }
}
```

## Retries with backoff

`429`/`502`/`503`/`504` are retried with exponential backoff. A `Retry-After`
header (delta-seconds or HTTP-date) overrides the computed delay. Tune via the
`retry` option; deterministic `4xx` (other than `429`) are not retried.

## Cursor pagination

List endpoints return `{ items, next_cursor }`. The `*` generators follow
`next_cursor` so you can iterate every item:

```ts
for await (const cert of client.certificates({ limit: 50 })) {
  console.log(cert.id, cert.subject);
}
// also: client.owners(), client.identities()
```

Need a single page (and the cursor) instead? Use the `list*` methods:

```ts
const page = await client.listOwners({ limit: 20 });
console.log(page.items, page.next_cursor);
```

---

## Copy-paste (no SDK install)

`src/index.ts` is self-contained and dependency-free (it imports only the
generated `./types.gen.ts`), so you can copy both files into your project
instead of installing the package:

```ts
import { TrstctlClient, isProblem } from "./index"; // copied alongside types.gen.ts

const client = new TrstctlClient({ baseUrl: "https://localhost:8443", token: "trst_..." });
const ident = await client.issueFirstCertificate("payments");
console.log(`issued ${ident.id} (${ident.status})`);
```
