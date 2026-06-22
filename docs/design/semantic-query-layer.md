# Design: the semantic query layer (scoping boundary)

**Status:** reviewed design spike (SF.6). Specifies the mechanism SF.7 builds; this
document contains **no production behavior**, only the design, the threat model, and
the adversarial test plan SF.7 must pass.

**Risk tier:** catastrophic. The semantic query layer is *the* tenant-then-RBAC
scoping boundary that the AI reasoning layer (Epoch 19b), the externally reachable
MCP server, the developer self-service portal, and compliance reporting all route
through. A single scoping defect here is a cross-tenant disclosure across **every**
consumer at once — the same blast radius as the signer. It is therefore designed
before it is built, like the signer (S1.3/S1.4) and the SSH trust rewrite (S13.2).

## 1. Purpose and position

trstctl's queryable state lives on four surfaces:

1. the **event / audit log** (NATS JetStream; the event-sourced source of truth);
2. the **credential graph** (F21; relationships between owners, identities,
   certificates, issuers, hosts);
3. the **cert / secret inventory** (the Postgres read model projected from the log);
4. the **CBOM** (F52; the cryptographic bill of materials from discovery).

The semantic query layer is **one internal, read-only API** that joins across these
surfaces with **tenant-then-RBAC scoping enforced by construction**, so a query
*physically cannot* return data the caller is not entitled to. Downstream consumers
inherit the boundary for free and are **never trusted to self-censor**.

It sits **on top of** the existing guarantees, never beside them:

- **Per-tenant isolation is the floor.** Every read executes inside a tenant-scoped
  transaction (`WithTenant`), so PostgreSQL row-level security confines it to
  one tenant *in the database itself*. The query layer composes RBAC scope **on top**
  of that floor; it never replaces or bypasses it.
- **Reads are projections.** The layer reads the projected read model and the
  log; it returns results consistent with a known projection offset and never
  fabricates state outside the event-sourced model.
- **Bulkheaded.** Queries run on a dedicated bounded pool with cost and
  timeout guards, so a heavy or adversarial query can never starve issuance,
  readiness, or the signer.

## 2. Enforcement by construction (not post-filtering)

The defining property: **out-of-scope data is unreachable, not filtered out after
the fact.** Three mechanisms compose to guarantee it.

### 2.1 Tenant floor — mandatory RLS transaction

There is exactly one execution path, and it always opens a tenant-scoped
transaction. A query cannot be issued without a resolved `tenant_id`; the layer has
**no API that runs a query outside `WithTenant`**. Because the RLS policy is enforced
by PostgreSQL under the non-superuser app role, even a query builder bug that omitted
a tenant predicate would still return zero out-of-tenant rows — the floor holds
independently of the layer's own correctness. This mirrors, and reuses, the
platform's row-level-security isolation proof.

### 2.2 RBAC scope — a mandatory, layer-injected predicate

Within the tenant, RBAC scope (subject → permitted resource scopes) is applied as a
predicate the **layer** injects into every query plan from the authenticated
principal, **not** a parameter the caller supplies. Callers describe *what* they want
(a typed query spec, §2.3); the layer decides *what they may see*. The scope predicate
is:

- derived solely from the request's authenticated `Principal` (the same RBAC the API
  uses, S3.5), resolved server-side;
- attached to every per-surface sub-read before execution; a plan with an unresolved
  or empty scope **fails closed** (returns nothing, with an error), never "all rows";
- not expressible as "no scope" by a caller — the type system has no such value.

### 2.3 No raw queries — a typed, parameterized query spec

Callers never submit SQL, Cypher, or free text. They submit a **typed query spec**:
an allow-listed set of selectable surfaces, fields, filters, and join keys, each a
Go value. The layer compiles the spec to parameterized statements ($1, $2 …) per
surface; user-supplied values are **only ever bound parameters**, never concatenated
into a statement. Field/relationship names are validated against a fixed allow-list,
so neither a field name nor an operator can be attacker-controlled. Cross-surface
joins are performed **in-process** over the per-surface, already-scoped result sets —
there is no raw cross-tenant SQL join for a builder bug to widen.

## 3. Threat model — leak/abuse vectors and mitigations

| # | Vector | How it could leak / abuse | Mitigation (by construction) |
|---|---|---|---|
| V1 | **Cross-tenant join leakage** | An in-process join over two surfaces accidentally pairs rows from different tenants. | Every sub-read runs in the *same* `WithTenant(tenant)` transaction; results carry no other tenant's rows to begin with, so a join cannot reintroduce them. RLS is the floor; the join operates only on already-confined sets. A property test asserts no join output row has a foreign `tenant_id`. |
| V2 | **RBAC-scope bypass** | A caller widens its own scope (e.g. by passing a scope/tenant parameter) or a plan runs with empty scope = all rows. | Scope is injected by the layer from the authenticated principal, never accepted from the caller; the spec has no tenant/scope field. An unresolved/empty scope fails closed. Denial is at this layer, before execution. |
| V3 | **Query / parameter injection** | Attacker-controlled field names, operators, or values alter the statement. | No raw query input. Field/operator names are allow-listed enums; values are bound parameters only. A malformed or unknown field fails closed at compile time. |
| V4 | **Projection-staleness disclosure** | A read served from a lagging projection reveals state that policy already revoked, or hides a revocation. | Reads are pinned to a projection offset and report it; revocation-sensitive queries read at or after a required offset or fail closed. Results are consistent with a known point in the event log, never a torn mix. |
| V5 | **Cost-exhaustion DoS** | A deliberately expensive or looping query (deep graph walk, huge fan-out, cartesian blow-up) starves other subsystems. | §4 cost/timeout guard: bounded pool, per-query row/Depth caps, `statement_timeout`, and a wall-clock deadline; over-budget queries are killed and fail closed. |
| V6 | **Result-shape inference** | Error messages or row counts leak the existence of out-of-scope data. | Out-of-scope and not-found are indistinguishable to the caller (same empty/forbidden result); errors never echo out-of-scope identifiers. |
| V7 | **Graph traversal escaping tenant** | A relationship walk follows an edge into another tenant's subgraph. | The graph is built per tenant inside the same RLS transaction; edges cannot reference rows RLS hides, so a walk cannot cross the boundary. |

## 4. Cost and timeout guard model

- **Bulkhead.** Queries run on a dedicated, bounded worker pool with a bounded
  queue; a full queue rejects fast with a structured error. The query pool is
  isolated from the API, issuance, and signer pools.
- **Row and depth caps.** Each plan carries a maximum result-row cap and, for graph
  traversal, a maximum depth/fan-out; exceeding either aborts the query (fail closed),
  it does not truncate-and-return.
- **Database statement timeout.** The scoped transaction sets a `statement_timeout`
  so a runaway SQL read is killed by PostgreSQL itself.
- **Wall-clock deadline.** Every query takes a context deadline; the in-process join
  and graph walk check it between steps and abort promptly.
- **Determinism.** Guards are configured per deployment, surfaced as metrics
  (`trstctl_query_*`), and a tripped guard is an explicit, audited error — never a
  silent partial result.

## 5. Interface stubs (no behavior)

Indicative shape only; SF.7 implements it. No method below has behavior in this spike.

```go
// Package query is the tenant-then-RBAC scoping boundary over trstctl's four data
// surfaces. Every method executes inside a tenant-scoped transaction (the per-tenant
// isolation floor) on the bounded query pool; callers submit a typed Spec, never raw
// SQL/Cypher.
package query

// Principal is the authenticated caller; the layer derives RBAC scope from it.
type Principal interface {
    TenantID() string
    Scopes() []Scope // resource scopes the subject may read; empty => fail closed
}

// Surface enumerates the joinable data surfaces (allow-listed).
type Surface int
const (
    SurfaceLog Surface = iota
    SurfaceGraph
    SurfaceInventory
    SurfaceCBOM
)

// Spec is a typed, parameterized query plan. Field/filter/join names are
// allow-listed enums; values are bound parameters. There is no tenant or scope
// field — scope is injected by the engine from the Principal.
type Spec struct {
    Select  []Field
    From    []Surface
    Where   []Predicate // operator is an enum; Value is a bound parameter
    Join    []JoinKey
    Limit   int         // <= the engine's hard row cap
    MaxDepth int        // graph traversal bound
}

// Engine runs scoped queries. Query opens a WithTenant(principal.TenantID())
// transaction, injects the RBAC scope predicate, compiles Spec to parameterized
// per-surface reads, joins in-process, and enforces the cost/timeout guards.
type Engine interface {
    Query(ctx context.Context, p Principal, s Spec) (*Result, error)
}

// Result carries rows plus the projection offset they are consistent with.
type Result struct {
    Rows   []Row
    Offset uint64
}
```

## 6. Adversarial test plan (SF.7 must pass, wired into CI)

This plan is a **first-class deliverable** of SF.7. The build is not done until each
of these passes and the suite is part of CI.

1. **Cross-tenant returns nothing — by construction.** Seed two tenants; every query
   shape a caller in tenant A can express returns zero of tenant B's rows. The
   defining test, mirroring the row-level-security isolation proof. Includes the
   variant where the query builder is deliberately fed a B-tenant id — RLS still
   returns nothing.
2. **Property-based no-leak.** Generate random valid specs, random principals, and
   random two-tenant/RBAC fixtures; assert **no** generated query path yields a row
   whose `tenant_id` ≠ the caller's or whose resource scope ∉ the caller's scopes.
   This is the core security property and runs many iterations.
3. **RBAC out-of-scope denied at this layer.** A principal scoped to subset X cannot
   read resources in scope Y, even within its own tenant; denial happens before
   execution.
4. **Injection fails closed.** Specs carrying crafted field/operator names, or values
   intended to break out of parameter binding, are rejected at compile time; no
   statement is executed.
5. **Cost/timeout guard kills.** A deliberately expensive (deep/fan-out/looping) query
   is aborted by the row/depth cap, the `statement_timeout`, or the deadline; the pool
   is never exhausted (a concurrent cheap query still succeeds, because the query pool
   is its own isolated lane).
6. **Malformed query fails closed.** A spec referencing unknown surfaces/fields, or an
   internally inconsistent plan, returns a structured error and no rows.
7. **Projection-staleness bound.** A revocation-sensitive query reads at/after the
   required projection offset or fails closed; results report their offset.
8. **Join correctness.** A single query joining at least the log, the graph, and the
   inventory returns a correct, fully-scoped result (the positive acceptance).

## 7. Architectural guarantees honored

- **Per-tenant isolation** — RLS is the floor; scoping composes on top; a cross-tenant
  query is impossible at the database, independent of the layer's own correctness.
- **Event-sourced reads** — reads are consistent with a known projection offset; no
  state outside the event-sourced model.
- **Bulkheading** — a dedicated bounded pool with cost/timeout guards; a heavy query
  cannot starve other subsystems.

## 8. Review & sign-off

This spike is reviewed against the acceptance: every enumerated leak/abuse vector
(V1–V7) has a by-construction mitigation; the enforcement mechanism (mandatory RLS
transaction + layer-injected RBAC predicate + typed parameterized spec + in-process
scoped joins) is specified precisely enough to implement; the cost/timeout guard
model is defined; and the adversarial test plan (§6) is enumerated for SF.7 to
implement as a first-class deliverable. SF.7 must not begin until this design is the
committed reference.
