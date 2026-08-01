# Patent-sensitive work

This is the running list of work flagged `patent_sensitive: true`. Entries here
are plausibly novel mechanisms that must be surfaced to counsel BEFORE any
public disclosure — the repository going public, a release tag, public docs, or
a launch post. Nothing on this list blocks building, gating, or committing;
the repository is private and single-author, so nothing is disclosed today.

This list records sensitivity only. It makes no assessment of patentability —
that determination belongs to counsel.

| Flagged | Mechanism | Where it lives |
|---|---|---|
| 2026-08-01 | Computed cryptographic discovery coverage with explicit structural-unobservability classification: every served discovery source declares an observability envelope; the estate is classified into OBSERVED / OBSERVABLE-UNOBSERVED (with the specific reason and closing action) / STRUCTURALLY UNOBSERVABLE (classes enumerated in code with stated reasons); a catalog-derived test welds the served source set to the envelope registry in both directions. | `internal/cbom/coverage`, the executor registry in `internal/server/discovery.go`, the `discovery_coverage` read model, `GET /api/v1/discovery/coverage` |

Before any public disclosure: review this list with patent counsel and either
file, deliberately publish, or clear each entry.
