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

## Copy-paste helpers (no SDK install)

If you would rather call the API with raw `fetch` and the generated types only,
this self-contained snippet reproduces the load-bearing behavior (auth,
`Idempotency-Key`, problem+json, `Retry-After`-aware retry, cursor iteration):

```ts
import type { components } from "./types.gen"; // from `npx openapi-typescript ../openapi.json`

type Schemas = components["schemas"];

class TrstctlProblem extends Error {
  constructor(public httpStatus: number, public body: any, public retryAfterSeconds?: number) {
    super(`trstctl: ${httpStatus} ${body?.title ?? ""}${body?.detail ? `: ${body.detail}` : ""}`.trim());
    this.name = "TrstctlProblem";
  }
}

function idemKey(): string {
  return (globalThis as any).crypto?.randomUUID?.() ?? `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function retryAfter(h: string | null): number | undefined {
  if (!h) return undefined;
  const s = Number(h);
  if (Number.isFinite(s)) return Math.max(0, Math.round(s));
  const t = Date.parse(h);
  return Number.isNaN(t) ? undefined : Math.max(0, Math.round((t - Date.now()) / 1000));
}

async function call<T>(baseUrl: string, token: string, method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json, application/problem+json",
    Authorization: `Bearer ${token}`,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["Idempotency-Key"] = idemKey(); // stable across the retries below
  const retryable = new Set([429, 502, 503, 504]);
  let lastErr: unknown;
  for (let attempt = 1; attempt <= 4; attempt++) {
    const res = await fetch(baseUrl.replace(/\/+$/, "") + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (res.ok) return (res.status === 204 ? undefined : await res.json()) as T;
    const ra = retryAfter(res.headers.get("Retry-After"));
    const prob = new TrstctlProblem(res.status, await res.json().catch(() => ({})), ra);
    lastErr = prob;
    if (retryable.has(res.status) && attempt < 4) {
      await new Promise((r) => setTimeout(r, Math.min((ra ?? 0.2 * 2 ** (attempt - 1)) * 1000, 5000)));
      continue;
    }
    throw prob;
  }
  throw lastErr;
}

async function* paginate<T>(baseUrl: string, token: string, path: string, limit = 50): AsyncGenerator<T> {
  let cursor: string | undefined;
  for (;;) {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (cursor) qs.set("cursor", cursor);
    const page = await call<{ items: T[]; next_cursor?: string }>(baseUrl, token, "GET", `${path}?${qs}`);
    for (const item of page.items ?? []) yield item;
    if (!page.next_cursor) return;
    cursor = page.next_cursor;
  }
}

// Getting-started flow:
async function issueFirst(baseUrl: string, token: string, name: string) {
  const owner = await call<Schemas["Owner"]>(baseUrl, token, "POST", "/api/v1/owners", { kind: "workload", name });
  const ident = await call<Schemas["Identity"]>(baseUrl, token, "POST", "/api/v1/identities", { kind: "x509_certificate", name, owner_id: owner.id });
  return call<Schemas["Identity"]>(baseUrl, token, "POST", `/api/v1/identities/${ident.id}/transitions`, { to: "issued" });
}
```
