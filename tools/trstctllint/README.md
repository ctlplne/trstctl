# trstctllint — the architecture linter

`trstctllint` is a custom [`go/analysis`](https://pkg.go.dev/golang.org/x/tools/go/analysis)
multichecker that enforces trstctl's architectural non-negotiables in CI. A pull
request cannot merge while any rule is violated.

## Rules

| Analyzer | Enforces | Summary |
|----------|----------|---------|
| `cryptoboundary` | **AN-3** | `crypto` / `crypto/*` may be imported only inside `internal/crypto` (and its subpackages). Every other package routes crypto through that boundary. |
| `tenantfilter` | **AN-1** | SQL data-manipulation queries (`SELECT`/`INSERT`/`UPDATE`/`DELETE`) in repository packages must **filter** on `tenant_id` — it must sit in a `WHERE` / `JOIN..ON` / `INSERT`-column / `ON CONFLICT` predicate, not merely appear in the text (comments and the `SELECT` list are stripped/ignored). |
| `keymaterial` | **AN-8** | In packages handling key material, fields/params/results must not be **string-backed** — bare `string`, named string types, `[]string`, `map[K]string`, arrays, and pointers to any of those are all flagged (use `[]byte`). |
| `idempotency` | **AN-5** | Served mutation handlers (either `//trstctl:mutation` or HTTP `route{mutation: true, handler: ...}`) must thread an idempotency key into a **real dedupe sink** (`orchestrator.Idempotency.Do` or a key-accepting forwarder such as `API.mutate`) — not merely name it, log it, or accept an unused parameter. |
| `eventsource` | **AN-2** | A served mutation handler (either `//trstctl:mutation` or HTTP `route{mutation: true, handler: ...}`) must not write the relational read model directly — neither via a `store.Store` `Create`/`Update`/`Delete`/`Upsert`/`Set` method or projected responder mutator (`RecordIssuedCert`, `RevokeIssuedCert`, `InsertCRL`) NOR via raw `INSERT`/`UPDATE`/`DELETE` SQL targeting a read-model table (`owners`, `issuers`, `identities`, `certificates`, `agents`, `tenants`, `identity_transitions`, `certificate_profiles`, `ca_issued_certs`, `ca_crls`); it must emit a domain event and let a projection build the read model (SPINE-010 closed the raw-SQL evasion). `SELECT` reads are allowed. |

All five rules resolve types and SQL clauses (not substrings/source spelling), so
a future violation cannot slip past CI by aliasing a receiver, hiding a secret
behind a named type, mentioning `tenant_id` in a comment, or passing an
idempotency key to a logger. `cryptoboundary`, `tenantfilter`, and `eventsource`
run over their whole scope; `keymaterial` applies to a fail-closed default set of
packages plus any marker opt-in; and served mutation coverage comes from both the
route registry and marker directives, so a missing comment cannot make an HTTP
mutation invisible.

## Marker directives (opt-in extension, fail-closed defaults)

Some rules apply to a fail-closed **default set** of packages (so a forgotten
marker cannot silently disable enforcement) and, in addition, wherever a package
or function opts in with a marker. Markers make a rule apply or, in one case,
sanction a single deliberate exemption; outside the one system-query hatch, they
never silence a finding.

- `//trstctl:repository` — marks a repository package outside `internal/store` so
  `tenantfilter` applies to it. (The orchestrator is already covered by default.)
- `//trstctl:keymaterial` — marks a package as key-handling so `keymaterial`
  applies to it. (`internal/crypto/secret` and `internal/crypto/seal` are covered
  by default, marker or not.)
- `//trstctl:mutation` — marks a handler function as a served mutation, so both
  `idempotency` (AN-5) and `eventsource` (AN-2) apply to it. HTTP routes with
  `mutation: true` are also covered automatically; the marker is the human-local
  declaration, not the only enforcement source.
- `//trstctl:system-query` — the **only** way to exempt a real DML statement from
  `tenantfilter`: it marks a single, deliberate cross-tenant **system** query (an
  auth-by-secret lookup whose tenant is not yet known, a cross-tenant
  dispatcher/sweep). It must lead the comment (`//trstctl:system-query <reason>`)
  and sit on, or just above, the statement. This keeps every cross-tenant query
  greppable and reviewed, rather than hidden by a missing predicate.

## Running it

```bash
go run ./tools/trstctllint ./...          # whole module (what `make lint` runs)
go run ./tools/trstctllint -tenantfilter=false ./...   # disable one rule for a run
go vet -vettool=$BIN ./...                # also usable as a vet tool
```

Each analyzer is independently testable with `go test ./tools/trstctllint/...`,
which uses `analysistest` fixtures under each analyzer's `testdata/`.

## Code hotspot guard

`go test ./tools/trstctllint/...` also runs a CODE-001 startup-shape guard. It
parses non-generated, non-test Go functions under `cmd/trstctl`,
`internal/config`, and `internal/server`, and fails if any function spans more
than 140 lines. Those paths are where control-plane boot, config validation,
server assembly, API/protocol mounting, and worker startup live; they must stay
split into named stages that can be audited independently.

The guard is intentionally scoped to the startup/assembly surface. Current
longer runtime functions outside that surface, such as OpenAPI schema table
construction, graph assembly, and projection event dispatch, remain visible in
ordinary complexity scans but are not CODE-001 exceptions for startup code. If
one of the guarded paths genuinely needs an exception, document the reason here
and encode it in the test with the narrowest function-level allowance.

## Escape hatch

There is **deliberately no blanket-ignore mechanism** — no `//nolint`, no
per-line suppression, no allowlist file. If a rule produces a false positive,
the only sanctioned fix is to **correct the rule itself in this package, with a
test fixture that captures the case** (add a clean fixture that must pass, or a
violating one that must fail). This keeps the non-negotiables un-violable and
keeps the rules honest: every refinement is encoded as a test.
