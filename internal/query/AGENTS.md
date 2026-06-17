# AGENTS.md - internal/query

This package is the semantic-query scoping boundary. It reads across store and
event-log surfaces only after tenant and RBAC checks decide what the caller may
see. A query bug can become a cross-tenant data leak.

Read `CLAUDE.md` in this directory for the detailed package-local rules until the
legacy filename is retired. Keep these invariants in your head while editing:

- The tenant is always the principal's tenant; do not add a caller-supplied tenant
  selector.
- Specs are typed and allow-listed; never accept raw SQL, Cypher, or field names
  from untrusted input.
- Missing permission denies the whole query before any read.
- Event-log reads must drop foreign-tenant events and report only tenant-local
  offsets.
- Keep bounded worker/backpressure and depth/row limits fail-closed.
