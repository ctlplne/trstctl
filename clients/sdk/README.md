# trstctl client SDKs

Supported client SDKs for the trstctl control-plane REST API, plus the blessed
generator configs that produce them. They are pinned to the served OpenAPI 3.1
contract so they cannot silently drift from the API.

```
clients/sdk/
  openapi.json          # the served OpenAPI spec the SDKs are generated from
                        # (pinned == internal/api/testdata/openapi.golden.json
                        #  by the Go test internal/api.TestSDKSpecPinnedToGolden)
  go/                   # Go SDK — its own module, standard library only
  typescript/           # TypeScript SDK — generated types + dependency-free runtime
  python/               # Python SDK — generated TypedDicts + stdlib runtime
  java/                 # Java SDK — generated schema index + JDK-only runtime
```

Each SDK provides, out of the box (so every integrator does not re-implement
them):

- **Auth** — `Authorization: Bearer <token>` on every call; optional
  `X-Tenant-ID` hint for header/dev auth.
- **Idempotency (AN-5)** — an `Idempotency-Key` on every mutation, auto-generated
  if you do not supply one, and held stable across automatic retries so a
  retried create is exactly-once on the server.
- **problem+json (RFC 7807)** — non-2xx responses parse into a typed error.
- **Retries with backoff** — `429`/`502`/`503`/`504` retried with exponential
  backoff that honors `Retry-After`.
- **Cursor pagination** — list endpoints return `{ items, next_cursor }`; the
  SDK iterators follow `next_cursor`.

## Pinned to the served contract (no silent drift)

```
live ServeMux
  ==(internal/api.TestOpenAPIGolden)==>   internal/api/testdata/openapi.golden.json
  ==(internal/api.TestSDKSpecPinnedToGolden)==> clients/sdk/openapi.json
  --(scripts/gen-sdk.sh / make sdk)-->    Go SDK + TypeScript SDK + Python SDK + Java SDK
```

If the backend changes a field, the golden changes and `TestSDKSpecPinnedToGolden`
goes red until you re-run `make sdk`. TypeScript generates field-level types and
Python generates TypedDicts. Java generates a schema-name index, not field-level
models; its generic `request` returns decoded response maps. Go's supported types
and resource helpers are curated by hand, and its full generated model reference
is build-ignored. Regeneration alone does not add new callable Go or Java helpers.

For broker, attested and ephemeral workload issuance, CLI output and the generic
TypeScript/Python/Java request methods preserve the optional `spiffe_id` field.
It is the full certificate-derived identity, not the friendly subject. Older
saved responses can omit it. See [the workload handoff contract](../../docs/features/workload-identity.md#hand-the-signed-identity-to-the-receiving-service).
The supported Go SDK does not yet expose these workload routes or a public
generic request method; that remains a client-parity gap.

## Regenerate

```bash
make sdk         # re-pin clients/sdk/openapi.json + regenerate every SDK
make sdk-check   # CI: fail if the SDKs are out of sync with the served contract
make sdk-test    # build + test the Go, TypeScript, Python, and Java SDKs
```

---

## Go SDK (`go/`)

Module: `trstctl.com/sdk/go`. Imports nothing outside the standard library,
so it never pulls the control plane's dependency graph into your build. It is a
separate module from the server, so the server's `go.mod`/`go.sum` are untouched.

### Install — `trstctl.com/sdk/go` is a vanity path, not a code host

```bash
go get trstctl.com/sdk/go
```

That command resolves only if `trstctl.com` serves a `go-import` meta tag for the
path. **Nothing in this repository serves one today** — no tracked service or
config emits that tag, and the code is hosted at
`https://github.com/ctlplne/trstctl`, a host that does not match the module path.
Until the endpoint exists, use the fallback below.

**What the endpoint has to serve.** A GET of `https://trstctl.com/sdk/go?go-get=1`
must return HTML whose `<head>` contains:

```html
<meta name="go-import" content="trstctl.com/sdk/go git https://REPO-ROOT-URL">
```

- The import prefix in the tag equals the **full module path**, so `go` clones
  `REPO-ROOT-URL` and looks for that module's `go.mod`
  at the root of that repository — not in a subdirectory.
- `https://github.com/ctlplne/trstctl` therefore cannot be `REPO-ROOT-URL`: its
  root `go.mod` declares `trstctl.com/trstctl`, while the SDK's `go.mod` lives in
  `clients/sdk/go/`. Serving this path needs a repository (or a published
  split-out mirror) whose root *is* the SDK module, carrying `vX.Y.Z` tags.
- The same constraint applies to the server module `trstctl.com/trstctl`.
- `proxy.golang.org` must be able to reach the endpoint too, or integrators need
  `GOPRIVATE=trstctl.com/*` to bypass the proxy and the checksum database.

**Fallback that works today** — clone the repository and point your own module at
the SDK directory on disk:

```bash
git clone https://github.com/ctlplne/trstctl
go mod edit -replace trstctl.com/sdk/go=./trstctl/clients/sdk/go
go mod tidy   # adds the require line that the replace directive satisfies
```

Renumbering the module to `github.com/ctlplne/trstctl/clients/sdk/go` would make
`go get` work with no hosting at all; that is a launch decision, not a doc fix,
and it is recorded here so the trade-off is visible rather than implicit.

The supported surface is the hand-written, dependency-free client
(`client.go`, `resources.go`, `workloads.go`, `iterator.go`). `oapi-codegen.yaml` is a blessed
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

### Workload and agentic identity

The supported Go client covers the full REST journey for broker-issued agent
identities, direct attested X.509-SVIDs, and approval-gated ephemeral
credentials. Pass decoded proof bytes—not a base64 string. The SDK creates the
exact `payload_base64` wire field, wipes its own encoded request buffers after
every attempt, and never changes the caller-owned slice.

```go
proof, err := os.ReadFile("/run/secrets/workload-proof")
if err != nil {
    log.Fatal(err)
}

request := trstctl.BrokerAgentIdentityRequest{
    AgentID:      "inventory-agent",
    Method:       "k8s_sat",
    Payload:      proof,
    PublicKeyPEM: workloadPublicKeyPEM, // the private key stays with the workload
    Scopes:       []string{"inventory:read"},
    TTLSeconds:   600,
}

preview, err := client.PreviewBrokerAgentIdentity(ctx, request)
if err != nil {
    log.Fatal(err)
}
if !preview.Ready {
    log.Fatalf("broker request is blocked: %v", preview.Blockers)
}

identity, err := client.IssueBrokerAgentIdentityKeyed(ctx, request, "agent-7-issue-1")
if err != nil {
    if contractErr, ok := trstctl.AsResponseContractError(err); ok {
        // A nominal success did not match the pinned contract. Do not guess
        // whether issuance ran, and do not retry under a different key.
        log.Fatal(contractErr)
    }
    log.Fatal(err)
}
if identity.SPIFFEID == nil {
    log.Fatal("the server could not safely disclose the exact signed SPIFFE ID")
}
log.Printf("issued %s", *identity.SPIFFEID)
```

Equivalent typed pairs are `PreviewAttestedSVID` / `IssueAttestedSVIDKeyed`
and `PreviewEphemeralCredential` / `IssueEphemeralCredentialKeyed`. Ephemeral
issuance keeps the two outcomes distinct: `IsPending()` means the server
returned `202 awaiting_approval`; `IsIssued()` means it returned `201 issued`.
Approve only the genuine `ApprovalRequestID` with its matching `IntentDigest`
through `ApproveEphemeralCredentialKeyed`, then retry the unchanged request
with a fresh logical-operation key. Preview POSTs are effect-free and send no
`Idempotency-Key`; proof-bearing requests refuse redirects rather than replaying
evidence at another location.

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

Package: `@trstctl/sdk`. Resource types are generated by `openapi-typescript`
from the pinned spec; a small dependency-free runtime (`src/index.ts`) adds the
auth, idempotency, retry, problem+json, and pagination behavior. Requires a
global `fetch` (Node 18+, Deno, browser). The package includes publish metadata
for registry release and defaults to `trstctl-ts-sdk/1` as its User-Agent.

Generate the types (pinned to `clients/sdk/openapi.json`):

```bash
cd clients/sdk/typescript
npx openapi-typescript ../openapi.json -o ./src/types.gen.ts
# or: npm run gen
```

Build and test the TypeScript SDK on its own:

```bash
cd clients/sdk/typescript
npm run typecheck
npm test
```

The test suite compiles the real SDK source, injects a deterministic `fetch`,
and covers bearer auth, optional tenant headers, core owner/identity/certificate
resources, cursor pagination, stable mutation `Idempotency-Key` retry behavior,
and `problem+json` parsing.

See [`typescript/README.md`](typescript/README.md) for the full reference,
a quickstart example, and a copy-paste-without-installing option.

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

## Java SDK (`java/`)

Package: `com.trstctl:trstctl-sdk`. The runtime is JDK-only: it uses
`java.net.http` for transport, parses `problem+json` into `ProblemException`, sends
`Authorization`, optional `X-Tenant-ID`, and stable `Idempotency-Key` headers, and
retries `429`/`502`/`503`/`504` while honoring `Retry-After`. `OpenApiSchemas.java`
is generated from the pinned OpenAPI schema names so Java builds get the same drift
signal as the other SDKs without pulling in a codegen runtime. The default
User-Agent is `trstctl-java-sdk/1`.

```java
import com.trstctl.sdk.PkiSecret;
import com.trstctl.sdk.Secret;
import com.trstctl.sdk.TrstctlClient;

TrstctlClient client = TrstctlClient.fromEnv();

PkiSecret issued = client.issuePkiSecret(
    "payments.service",
    900,
    "payments-pki-2026-06-25"
);
Secret current = client.createSecret(
    "apps/payments/api-token",
    "initial-fixture-value",
    "payments-secret-create"
);

System.out.println(issued.serial() + " " + current.version());
```

Generate the Java schema index:

```bash
python3 clients/sdk/java/scripts/gen_schemas.py \
  clients/sdk/openapi.json \
  clients/sdk/java/src/main/java/com/trstctl/sdk/OpenApiSchemas.java
```

`make sdk-test` compiles the Java SDK and its JDK-only unit test when `javac` is
available. CI sets `TRSTCTL_REQUIRE_JAVA_SDK=1`, so the Java gate fails instead of
skipping if the JDK disappears from the runner. The served acceptance test compiles
and runs a Java program against the assembled control-plane handler and proves auth + PKI issue + secret create/read/rotate/delete end-to-end.

---

## Licensing

These SDKs are part of the trstctl MPL-2.0 open core; see the repository
`LICENSE`.
