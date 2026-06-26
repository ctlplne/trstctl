# trstctl client SDKs

Supported client SDKs for the trstctl control-plane REST API, plus the blessed
generator configs that produce them. They are pinned to the **served OpenAPI 3.1
contract** so they cannot silently drift from the API.

```
clients/sdk/
  openapi.json          # the served OpenAPI spec the SDKs are generated from
                        # (pinned == internal/api/testdata/openapi.golden.json
                        #  by the Go test internal/api.TestSDKSpecPinnedToGolden)
  go/                   # Go SDK — its own module, standard library only
  typescript/           # TypeScript SDK — generated types + dependency-free runtime
  python/               # Python SDK — generated TypedDicts + stdlib runtime
```

Each SDK provides, out of the box (so every integrator does not re-implement
them):

- **Auth** — `Authorization: Bearer <token>` on every call; optional
  `X-Tenant-ID` hint for header/dev auth.
- **Idempotency (AN-5)** — an `Idempotency-Key` on every mutation, auto-generated
  if you do not supply one, and held **stable across automatic retries** so a
  retried create is exactly-once on the server.
- **problem+json (RFC 7807)** — non-2xx responses parse into a typed error.
- **Retries with backoff** — `429`/`502`/`503`/`504` retried with exponential
  backoff that **honors `Retry-After`**.
- **Cursor pagination** — list endpoints return `{ items, next_cursor }`; the
  SDK iterators follow `next_cursor`.

## Pinned to the served contract (no silent drift)

```
live ServeMux
  ==(internal/api.TestOpenAPIGolden)==>   internal/api/testdata/openapi.golden.json
  ==(internal/api.TestSDKSpecPinnedToGolden)==> clients/sdk/openapi.json
  --(scripts/gen-sdk.sh / make sdk)-->    Go SDK + TypeScript SDK + Python SDK
```

If the backend changes a field, the golden changes, `TestSDKSpecPinnedToGolden`
goes red until you re-run `make sdk`, and the regenerated types make `go build` /
`tsc` flag any code that used a now-missing field.

## Regenerate

```bash
make sdk         # re-pin clients/sdk/openapi.json + regenerate every SDK
make sdk-check   # CI: fail if the SDKs are out of sync with the served contract
make sdk-test    # build + test the Go and Python SDKs
```

---

## Go SDK (`go/`)

Module: `trstctl.com/sdk/go`. **Imports nothing outside the standard library**,
so it never pulls the control plane's dependency graph into your build. It is a
separate module from the server, so the server's `go.mod`/`go.sum` are untouched.

The supported surface is the hand-written, dependency-free client
(`client.go`, `resources.go`, `iterator.go`). `oapi-codegen.yaml` is a blessed
config that can emit the full model set for forks that accept the extra
dependency (opt-in; see the file and `TRSTCTL_SDK_GO_MODELS=1 make sdk`).

```go
import (
    "context"
    "log"
    "time"

    trstctl "trstctl.com/sdk/go/trstctl"
)

client := trstctl.New("https://localhost:8443", "trst_...",
    trstctl.WithTenant("11111111-1111-1111-1111-111111111111"), // optional X-Tenant-ID
    trstctl.WithRetry(trstctl.RetryPolicy{MaxAttempts: 4, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second}),
)
ctx := context.Background()

// Getting-started flow in one call: owner -> identity -> transition "issued".
ident, err := client.IssueFirstCertificate(ctx, "payments")
if err != nil {
    if prob, ok := trstctl.AsProblem(err); ok { // problem+json -> typed error
        log.Fatalf("%d %s: %s", prob.HTTPStatus, prob.Title, prob.Detail)
    }
    log.Fatal(err)
}
log.Printf("issued %s (%s)", ident.ID, ident.Status)

// Cursor pagination: the iterator follows next_cursor across pages.
it := client.Certificates(trstctl.CertificateListOptions{ListOptions: trstctl.ListOptions{Limit: 50}})
for it.Next(ctx) {
    log.Printf("%s %s", it.Value().ID, it.Value().Subject)
}
if err := it.Err(); err != nil {
    log.Fatal(err)
}
```

Build and test the Go SDK on its own:

```bash
cd clients/sdk/go
go build ./... && go vet ./... && go test ./...
```

### Idempotency-Key control

Mutations auto-generate an `Idempotency-Key`. Supply a stable one when you want a
retry across process restarts to remain exactly-once:

```go
owner, err := client.CreateOwnerKeyed(ctx,
    trstctl.OwnerRequest{Kind: "workload", Name: "payments"}, "my-stable-key")
```

### Errors

Every non-2xx response is a `*trstctl.Problem` (also an `error`):

```go
_, err := client.GetIdentity(ctx, "missing")
if prob, ok := trstctl.AsProblem(err); ok {
    // prob.HTTPStatus, prob.Type, prob.Title, prob.Detail, prob.Instance,
    // prob.Extensions, prob.IsRateLimited(), prob.RetryAfter
}
```

---

## TypeScript SDK (`typescript/`)

Package: `@trstctl/sdk`. Resource **types are generated** by `openapi-typescript`
from the pinned spec; a small dependency-free runtime (`src/index.ts`) adds the
auth, idempotency, retry, problem+json, and pagination behavior. Requires a
global `fetch` (Node 18+, Deno, browser).

Generate the types (pinned to `clients/sdk/openapi.json`):

```bash
cd clients/sdk/typescript
npx openapi-typescript ../openapi.json -o ./src/types.gen.ts
# or: npm run gen
```

```ts
import { TrstctlClient, isProblem } from "@trstctl/sdk";

const client = new TrstctlClient({ baseUrl: "https://localhost:8443", token: "trst_..." });

const ident = await client.issueFirstCertificate("payments"); // owner -> identity -> issued

for await (const cert of client.certificates({ limit: 50 })) { // follows next_cursor
  console.log(cert.id, cert.subject);
}

try {
  await client.getIdentity("missing");
} catch (err) {
  if (isProblem(err)) console.error(err.httpStatus, err.title, err.detail);
}
```

See `typescript/README.md` for the full reference and a copy-paste helper snippet
you can paste into a project that prefers raw `fetch`.

---

## Python SDK (`python/`)

Package: `trstctl-sdk`. The runtime is dependency-free and the Python TypedDict
resource aliases in `trstctl_sdk.types` are generated from the pinned OpenAPI schemas. It supports
the same bearer auth, optional tenant hint, mutation idempotency, retries,
`ProblemError`, and served secrets/PKI helpers as the other SDKs. The default
User-Agent is `trstctl-python-sdk/1`.

```python
from trstctl_sdk import ProblemError, TrstctlClient

client = TrstctlClient.from_env()

try:
    issued = client.issue_pki_secret(
        "payments.service",
        ttl_seconds=900,
        idempotency_key="payments-pki-2026-06-25",
    )
    client.create_secret(
        "apps/payments/api-token",
        "initial-fixture-value",
        idempotency_key="payments-secret-create",
    )
    current = client.get_secret("apps/payments/api-token")
except ProblemError as exc:
    print(exc.http_status, exc.title, exc.detail)
    raise

print(issued["serial"], current["version"])
```

Generate the Python type aliases:

```bash
python3 clients/sdk/python/scripts/gen_types.py \
  clients/sdk/openapi.json \
  clients/sdk/python/src/trstctl_sdk/types.py
```

The served-path acceptance test shells out to Python with `PYTHONPATH` pointed at
`clients/sdk/python/src` and performs a real auth + PKI issue + secret
create/read/rotate/delete round-trip against the assembled control-plane handler.

---

## Licensing

These SDKs are part of the trstctl source-available distribution; see the
repository `LICENSE`.
