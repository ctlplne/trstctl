# Client SDKs

## What it is

trstctl ships supported client SDKs for Go, TypeScript, Python, and Java, plus
blessed generator configs, so integrators do not have to hand-roll a client,
retry logic, idempotency, pagination, or error mapping. The SDKs are
generated/blessed against the served OpenAPI 3.1 contract and are pinned to it
so they cannot silently drift from the API.

“Ships” currently means the source, generated contract, tests, and local build
metadata are committed in this repository. It does **not** mean every library is
published to a public package registry. The exact distribution boundary is:

| SDK | Verified way to use it today | Public package claim |
| --- | --- | --- |
| Go | clone the repository and use a local `replace` to `clients/sdk/go` | none; the vanity `go-import` endpoint is not served |
| TypeScript | `npm install` the checked-out `clients/sdk/typescript` directory | none |
| Python | `python -m pip install` the checked-out `clients/sdk/python` directory | none |
| Java | build/install the checked-out `clients/sdk/java/pom.xml` into the local Maven repository | none |

The console uses only these verified local-source commands. A registry command can
replace one of them only after CI installs that exact published artifact from a
clean environment.

*Code:* `clients/sdk/` (`go/`, `typescript/`, `python/`, `java/`, and the pinned `openapi.json`).
*Regenerate:* `make sdk`. **Served contract + library.**

## Why it exists

The control plane already publishes its full OpenAPI 3.1 document (at
`/api/v1/openapi.json`) and a CLI at parity with the API. The SDKs add the next
layer every language team would otherwise re-implement:

- **Auth** — an `Authorization: Bearer <token>` header on every call (and an
  optional `X-Tenant-ID` hint for header/dev auth).
- **Idempotency** — an `Idempotency-Key` on every mutation, auto-generated
  when you do not supply one and held **stable across automatic retries**, so a
  retried create is exactly-once on the server (a retry never applies the change twice).
- **problem+json (RFC 7807)** — non-2xx responses parse into a typed error
  (`*trstctl.Problem` in Go, `TrstctlProblem` in TypeScript, `ProblemError` in Python,
  `ProblemException` in Java) carrying
  `status`/`title`/`detail`/`type`/`instance` and any extension members.
- **Retries with backoff** — `429`/`502`/`503`/`504` are retried with exponential
  backoff that **honors a `Retry-After` header** when the server sends one.
- **Cursor pagination** — list endpoints return `{ items, next_cursor }`; the SDK
  exposes iterators that follow `next_cursor` so you never juggle cursors by hand.

## How it works

### Pinned to the served contract

The published spec lives at `clients/sdk/openapi.json`. A CI check fails the build
if that file drifts from the spec the running server actually serves, and a second
check pins that served spec to the live route table. So a backend field
add/rename/remove turns the build red until the SDKs are regenerated with
`make sdk` — the SDKs cannot desync from the API undetected.

### Generation

```bash
# Re-pin clients/sdk/openapi.json to the served spec and regenerate every SDK.
make sdk

# CI guard: fail if the SDKs are out of sync with the served contract.
make sdk-check

# Build + test the Go, TypeScript, Python, and Java SDKs.
make sdk-test
```

Under the hood `scripts/gen-sdk.sh` copies the served golden to
`clients/sdk/openapi.json`, runs `openapi-typescript` for the TypeScript types,
runs the Python TypedDict generator, generates the Java OpenAPI schema index, and
(opt-in) `oapi-codegen` for the full Go model set.

## Use it

### Go

The Go SDK is its own module (`trstctl.com/sdk/go`) that imports nothing
outside the standard library, so adding it never drags the control plane's
dependency graph into your build.

`trstctl.com/sdk/go` is a vanity import path and no `go-import` endpoint is
served for it yet, so `go get trstctl.com/sdk/go` does not resolve on its own.
Read the Install section of `clients/sdk/README.md` first: it gives the exact
meta tag the path needs and the `replace` fallback that works today.

```go
import (
    "context"
    "log"

    trstctl "trstctl.com/sdk/go/trstctl"
)

func main() {
    // Auth: the token is sent as Authorization: Bearer on every call.
    client := trstctl.New("https://localhost:8443", "trst_...")
    ctx := context.Background()

    // Getting-started flow in one call: create owner -> create identity ->
    // transition to "issued". Each step carries its own Idempotency-Key, so a
    // retry never applies the change twice.
    ident, err := client.IssueFirstCertificate(ctx, "payments")
    if err != nil {
        // problem+json errors surface as a typed *trstctl.Problem.
        if prob, ok := trstctl.AsProblem(err); ok {
            log.Fatalf("issuance failed: %d %s — %s", prob.HTTPStatus, prob.Title, prob.Detail)
        }
        log.Fatal(err)
    }
    log.Printf("issued identity %s (status %s)", ident.ID, ident.Status)

    // Cursor pagination: the iterator follows next_cursor across pages.
    it := client.Certificates(trstctl.CertificateListOptions{ListOptions: trstctl.ListOptions{Limit: 50}})
    for it.Next(ctx) {
        cert := it.Value()
        log.Printf("certificate %s: %s", cert.ID, cert.Subject)
    }
    if err := it.Err(); err != nil {
        log.Fatal(err)
    }
}
```

Idempotency, retries (`429`/`5xx` with `Retry-After`), and the `X-Tenant-ID`
hint are configured on the client:

```go
client := trstctl.New("https://localhost:8443", "trst_...",
    trstctl.WithTenant("11111111-1111-1111-1111-111111111111"),
    trstctl.WithRetry(trstctl.RetryPolicy{MaxAttempts: 4, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second}),
)

// Supply your own stable Idempotency-Key when you want a retry across process
// restarts to remain exactly-once:
owner, err := client.CreateOwnerKeyed(ctx, trstctl.OwnerRequest{Kind: "workload", Name: "payments"}, "my-stable-key")
```

The same dependency-free client has typed agentic/workload journeys rather than
forcing an automation author to hand-roll HTTP:

- `PreviewBrokerAgentIdentity`, `IssueBrokerAgentIdentityKeyed`,
  `ListBrokerAgentIdentities`, and `GetBrokerAgentIdentity` cover effect-free
  review, exact issuance retry, and durable broker history.
- `PreviewAttestedSVID` and `IssueAttestedSVIDKeyed` cover direct attested
  X.509-SVID issuance.
- `PreviewEphemeralCredential`, `IssueEphemeralCredentialKeyed`, and
  `ApproveEphemeralCredentialKeyed` preserve the difference between a pending
  `202` approval and a completed `201` credential.

Proof and optional task-envelope inputs are caller-owned `[]byte`. The SDK
base64-encodes them for the OpenAPI wire contract, wipes its own encoded buffers
after each attempt, keeps a supplied idempotency key stable across retries, and
refuses redirects for proof-bearing requests. Optional `SPIFFEID` fields remain
nil when the exact signed URI is unavailable; the SDK never promotes a friendly
subject into a signed identity. See the Go section of `clients/sdk/README.md` for
the copyable review-and-issue example and ambiguous-success error handling.

### TypeScript

The TypeScript SDK's resource types are generated by `openapi-typescript` from
the pinned spec; a small dependency-free runtime adds the same auth, idempotency,
retry, problem+json, and pagination behavior. It requires a global `fetch`
(Node 18+, Deno, or a browser). The package is ready to publish as
`@trstctl/sdk`, includes public registry publish metadata, and carries a Node
test suite for bearer auth, optional tenant hints, core owner/identity/certificate
resources, cursor pagination, stable mutation `Idempotency-Key` retry behavior,
and typed `problem+json` errors.

```ts
import { TrstctlClient, isProblem } from "@trstctl/sdk";

const client = new TrstctlClient({
  baseUrl: "https://localhost:8443",
  token: "trst_...",
  // tenant: "11111111-1111-1111-1111-111111111111", // optional X-Tenant-ID hint
});

try {
  // create owner -> create identity -> transition to "issued", each with an
  // auto-generated Idempotency-Key.
  const ident = await client.issueFirstCertificate("payments");
  console.log(`issued identity ${ident.id} (status ${ident.status})`);
} catch (err) {
  if (isProblem(err)) {
    console.error(`issuance failed: ${err.httpStatus} ${err.title} — ${err.detail}`);
  } else {
    throw err;
  }
}

// Cursor pagination via an async generator that follows next_cursor.
for await (const cert of client.certificates({ limit: 50 })) {
  console.log(`certificate ${cert.id}: ${cert.subject}`);
}
```

See `clients/sdk/README.md` and `clients/sdk/typescript/README.md` for the full
reference, including the exact `npx openapi-typescript` command and the
copy-paste helper snippet. `make sdk-test` runs both `npm run typecheck` and
`npm test` for the TypeScript package.

### Python

The Python SDK package is `trstctl-sdk`. Its runtime is standard-library only,
and `trstctl_sdk.types` is generated from the pinned OpenAPI schemas. It is
covered by two gates: unit tests for auth/idempotency/problem handling, and a
served acceptance test that shells out to Python and performs bearer auth,
dynamic PKI issuance, and secret create/read/rotate/delete against the assembled
control-plane handler.

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

Use `TRSTCTL_SERVER`, `TRSTCTL_TOKEN`, and `TRSTCTL_TENANT` with
`TrstctlClient.from_env()`.

### Java

The Java SDK package is `com.trstctl:trstctl-sdk`. Its runtime is JDK-only:
`java.net.http` for transport, a small in-package JSON codec, and generated
`OpenApiSchemas` drift metadata from the pinned OpenAPI schema names. It has the
same operational behavior as the other SDKs: bearer auth, optional `X-Tenant-ID`,
stable `Idempotency-Key`, `ProblemException`, `Retry-After`, and helpers for dynamic
PKI issuance plus secret create/read/rotate/delete.

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

`clients/sdk/java/scripts/run_tests.sh` compiles the SDK and a JDK-only unit test.
CI runs the Java SDK gate in required mode, so the check fails instead of silently
skipping if the JDK disappears from the runner. The served-path acceptance test
compiles and runs a Java round-trip program against the assembled control plane when
a JDK is present.

## Pitfalls & limits

- A backend contract change requires `make sdk` regeneration — CI fails red
  until the pinned spec and SDKs are back in sync; do not hand-edit
  `clients/sdk/openapi.json`.
- The TypeScript runtime needs a global `fetch` (Node 18+, Deno, or a
  browser); the Java SDK needs a JDK (`java.net.http`); the Go and Python
  runtimes are standard-library only.
- The SDKs cover the served core contract; licensed EE-only routes are not in
  the pinned spec.

## Reference

- **Packages:** Go `trstctl.com/sdk/go` · TypeScript `@trstctl/sdk` ·
  Python `trstctl-sdk` · Java `com.trstctl:trstctl-sdk`.
- **Make targets:** `make sdk` (re-pin + regenerate), `make sdk-check`
  (CI drift guard), `make sdk-test` (build + test all four).
- **Env for `from_env()`/`fromEnv()`:** `TRSTCTL_SERVER`, `TRSTCTL_TOKEN`,
  `TRSTCTL_TENANT`.
- **Shared behavior:** bearer auth, optional `X-Tenant-ID`, stable
  `Idempotency-Key` on mutations, RFC 7807 typed errors, `Retry-After`-aware
  backoff on `429`/`502`/`503`/`504`, cursor iterators over
  `{ items, next_cursor }`.

## See also

[Platform & API](platform-and-api.md) (the contract these pin to) ·
[Build on the API journey](../journeys/build-on-the-api.md) ·
`clients/sdk/README.md` and the per-language READMEs
