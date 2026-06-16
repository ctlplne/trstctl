package store

// Every data-manipulation query in a repository package must FILTER on tenant_id
// (AN-1) — tenant_id must appear in a row-restricting predicate, not merely
// somewhere in the text. The "Good" constants are clean; the "Bad" ones are
// flagged. The evasion cases (comment-only, SELECT-list-only, cast-only) are the
// substring-check false-negatives that ARCH-003 / SEC-004 / TENANT-001 closed.

const (
	listGood = "SELECT id, name FROM certificates WHERE tenant_id = $1 ORDER BY name"
	listBad  = "SELECT id, name FROM certificates WHERE owner = $1" // want "does not filter on tenant_id"

	updateGood = "UPDATE certificates SET revoked = true WHERE tenant_id = $1 AND id = $2"
	updateBad  = "UPDATE certificates SET revoked = true WHERE id = $1" // want "does not filter on tenant_id"

	deleteBad = "DELETE FROM certificates WHERE id = $1" // want "does not filter on tenant_id"

	insertGood = "INSERT INTO certificates (tenant_id, id, name) VALUES ($1, $2, $3)"
	insertBad  = "INSERT INTO certificates (id, name) VALUES ($1, $2)" // want "does not filter on tenant_id"

	// Not a DML statement, so it is not subject to the rule.
	ddl = "CREATE TABLE certificates (id uuid primary key)"

	// System (non-tenant) tables are exempt: no tenant_id is expected.
	migCheck  = "SELECT version FROM schema_migrations"
	migRecord = "INSERT INTO schema_migrations (version) VALUES ($1)"

	// Session/lock control functions read no table, so they are exempt: the
	// migration advisory lock (AN-1 R2.5) carries no tenant_id, and set_config
	// drives the RLS session variable rather than a tenant table.
	migLock   = "SELECT pg_advisory_lock($1)"
	migUnlock = "SELECT pg_advisory_unlock($1)"
	setTenant = "SELECT set_config('trstctl.tenant_id', $1, true)"
	regclass  = "SELECT to_regclass('public.schema_migrations') IS NOT NULL"

	// ── Substring-evasion regressions (ARCH-003 / SEC-004 / TENANT-001) ──
	// tenant_id is present in the TEXT but NOT in a predicate. The old rule
	// (strings.Contains(sql, "tenant_id")) passed all of these; the clause-aware
	// rule flags them.

	// tenant_id only in a trailing comment.
	commentOnly = "SELECT secret FROM secrets WHERE name = $1 -- and tenant_id" // want "does not filter on tenant_id"

	// tenant_id only in the SELECT list, never in WHERE.
	selectListOnly = "SELECT tenant_id, name, sealed FROM credentials WHERE name = $1" // want "does not filter on tenant_id"

	// tenant_id only as a returned, type-cast column; the filter is on name.
	castOnly = "SELECT id::text, tenant_id::text, name FROM identities WHERE name = $1" // want "does not filter on tenant_id"

	// tenant_id only in a block comment.
	blockCommentOnly = "DELETE FROM secrets /* keyed within tenant_id scope */ WHERE name = $1" // want "does not filter on tenant_id"

	// tenant_id only in ORDER BY (not a row restriction).
	orderByOnly = "SELECT name FROM certificates WHERE owner = $1 ORDER BY tenant_id" // want "does not filter on tenant_id"

	// ── Predicate-position positives (these correctly filter) ──

	// tenant_id in a WHERE, with a comment also present — clean.
	whereWithComment = "SELECT secret FROM secrets WHERE tenant_id = $1 -- by tenant"

	// tenant_id in the INSERT column list — clean (the written row is tenant-bound).
	insertCols = "INSERT INTO credentials (tenant_id, name, sealed) VALUES ($1, $2, $3)"

	// tenant_id in the ON CONFLICT conflict target of an upsert — clean.
	upsert = "INSERT INTO certs (tenant_id, fingerprint, pem) VALUES ($1,$2,$3) ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET pem = EXCLUDED.pem"

	// tenant_id in a JOIN ... ON condition — clean.
	joinOn = "SELECT c.id FROM certs c JOIN owners o ON o.tenant_id = c.tenant_id WHERE c.id = $1"

	// tenant_id carried only by a subquery's WHERE — clean (the subquery scopes it).
	subqueryWhere = "SELECT id::text, (SELECT count(*) FROM approvals a WHERE a.tenant_id = c.tenant_id) FROM ceremonies c WHERE c.tenant_id = $1"

	// A bare HTTP-method-looking string is NOT a DML statement (strict isDML),
	// so it must not be flagged even though the package is in scope.
	notSQL     = "DELETE"
	alsoNotSQL = "SELECT"
)

// Concatenated queries are judged as a whole: a predicate in a later fragment
// counts, and a missing predicate across all fragments is flagged. The table
// identifier is interpolated from a vetted constant.
func built(table string) (string, string) {
	clean := "DELETE FROM " + table + " WHERE tenant_id = $1"
	bad := "DELETE FROM " + table + " WHERE id = $1" // want "does not filter on tenant_id"
	return clean, bad
}

// systemException is a deliberate cross-tenant system query, exempted by the
// marker on its own line. It is the sanctioned escape hatch (greppable), not a
// per-line ignore.
func systemException() string {
	//trstctl:system-query — enumerates all tenants for a system maintenance pass; no tenant predicate by design.
	return "SELECT tenant_id::text, name FROM tenants ORDER BY tenant_id"
}

// incidentalMarkerMention proves the marker only exempts when it LEADS the
// comment: a mid-sentence mention does not exempt the following query.
func incidentalMarkerMention() string {
	// we deliberately avoid the trstctl:system-query hatch here
	return "SELECT secret FROM secrets WHERE name = $1" // want "does not filter on tenant_id"
}
