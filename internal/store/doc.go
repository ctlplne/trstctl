// Package store holds the PostgreSQL repositories, migrations, and row-level
// security policies (AN-1).
//
// Every table carries a tenant_id and every query filters on it; isolation is
// enforced by PostgreSQL row-level security rather than by application code.
// PostgreSQL is the datastore in every deployment mode (there is no SQLite
// path), and no other datastore is introduced. The architecture linter
// (tools/certctllint) fails any repository query missing a tenant_id filter.
//
// Implementation begins in sprint S2.2; this file reserves the package.
package store
