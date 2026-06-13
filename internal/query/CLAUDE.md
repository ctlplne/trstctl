# internal/query — the semantic query layer (scoping boundary)

This package is the tenant-then-RBAC scoping boundary that every later read consumer
(the AI reasoning layer, the MCP server, the developer portal, compliance reporting)
routes through. Its correctness is a cross-platform security property — treat changes
here with the same scrutiny as the signer. The design is
`docs/design/semantic-query-layer.md` (SF.6); this package is its build (SF.7).

## For callers (the internal SDK)

```go
e := query.New(store, log, queryPool, query.DefaultConfig())
res, err := e.Query(ctx, principal, query.Spec{
    Select: []query.Surface{query.SurfaceOwners, query.SurfaceCertificates, query.SurfaceLog},
    Where:  []query.Predicate{{Field: query.FieldOwnerName, Op: query.OpEq, Value: "payments"}},
    Limit:  100,
})
```

- The **tenant is the principal's**, always. There is no API to query another tenant;
  the `Spec` has no tenant or scope field. Don't add one.
- The principal must hold the read permission for **every** selected surface, or the
  whole query is `ErrForbidden` (denied before any read).
- Callers submit a **typed `Spec`** — allow-listed `Surface`/`Field`/`Op`, values bound
  as parameters. Never accept raw SQL/Cypher/text from a caller and never build a Spec
  field name from untrusted input.
- Errors are intentionally coarse (`ErrForbidden`/`ErrMalformed`/...) so a caller can't
  distinguish "out of scope" from "not found". Keep them that way.

## Invariants any change must preserve (and the tests that hold them)

- **AN-1 floor:** every surface read runs under `store.WithTenant(principal.TenantID)`
  (Postgres RLS) or, for the non-RLS event log, drops foreign-tenant events in-process.
  A cross-tenant row must be unreachable regardless of this layer's own correctness.
  Held by `TestCrossTenantReturnsNothingByConstruction` and the property test
  `TestPropertyNoQueryPathLeaksOutOfScope`.
- **No new untyped input.** New surfaces/fields/operators are added as allow-listed
  enums with a `requiredPermission` / `fieldSurface` entry; anything unknown fails
  closed. Held by the `*FailsClosed` tests.
- **AN-7 guards.** Queries run on the bounded pool with row/depth caps and a wall-clock
  deadline; over-budget or runaway queries fail closed. Held by
  `TestBackpressureRejectsWhenPoolSaturated`, `TestLimit/DepthOverBudgetFailsClosed`,
  and `TestDeadlineGuardTrips`.
- **AN-2 consistency.** `Result.Offset` reports the log offset the result reflects.

When you add a surface: add the `Surface`, its `requiredPermission`, a reader that is
tenant-scoped by construction, and extend the adversarial suite (especially the
property test) to cover it. The suite runs against real Postgres + embedded NATS in
`make test`, so it is part of the CI gate.

## Out of scope here

Write paths of any kind (this layer is read-only), the AI/MCP consumers (Epoch 19b),
and mounting the engine onto a serving surface (that is the S15.0 integration sprint).
