// Package store holds the PostgreSQL repositories, migrations, and row-level
// security policies (AN-1).
//
// Every table carries a tenant_id and every query filters on it; isolation is
// enforced by PostgreSQL row-level security rather than by application code.
// PostgreSQL is the datastore in every deployment mode (there is no SQLite
// path), and no other datastore is introduced. The architecture linter
// (tools/trstctllint) fails any repository query missing a tenant_id filter.
//
// Store exposes the connection pool, the migration runner, the Tenant entity
// and its repository, and WithTenant, which runs tenant-scoped queries under
// row-level security.
package store
