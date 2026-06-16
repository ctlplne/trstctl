// Package orchestrator stands in for the real orchestrator, one of the packages
// OUTSIDE internal/store that runs raw DML against tenant tables on the pool (the
// ARCH-003 blind spot). It carries NO //trstctl:repository marker — yet the rule
// still applies, because the package path is default-on (fail-closed, ARCH-004):
// a forgotten marker cannot silently disable AN-1 on the outbox SQL here.
package orchestrator

// enqueueGood writes a tenant-bound row (tenant_id in the INSERT columns).
const enqueueGood = "INSERT INTO outbox (tenant_id, destination, payload) VALUES ($1, $2, $3)"

// updateGood marks a row WHERE tenant_id — clean.
const updateGood = "UPDATE outbox SET status = 'delivered' WHERE id = $1 AND tenant_id = $2"

// leakBad omits any tenant predicate — flagged even with no marker (fail-closed).
const leakBad = "UPDATE outbox SET status = 'delivered' WHERE id = $1" // want "does not filter on tenant_id"

// selectListLeak returns tenant_id but does not filter on it — flagged.
const selectListLeak = "SELECT id, tenant_id::text, payload FROM outbox WHERE status = 'pending'" // want "does not filter on tenant_id"

// dispatcher is the genuine cross-tenant claim: exempted by the marker.
func dispatcher() string {
	//trstctl:system-query — the dispatcher drains every tenant's due rows in one pass; no tenant predicate by design.
	return "SELECT id, tenant_id::text, payload FROM outbox WHERE status = 'pending' FOR UPDATE SKIP LOCKED LIMIT 1"
}
