// Package api fixtures exercise AN-2: a //trstctl:mutation handler must not
// write the read model directly through the store; it must emit an event.
package api

import "trstctl.com/trstctl/internal/store"

// emit stands in for appending a domain event to the log.
func emit(eventType string) error { _ = eventType; return nil }

type API struct{}

type route struct {
	handler  any
	mutation bool
}

func (a *API) routes() []route {
	return []route{
		{handler: a.RouteMutationWritesStore, mutation: true},
		{handler: a.RouteMutationEmitsEvent, mutation: true},
		{handler: a.RouteReadWritesStore, mutation: false},
	}
}

// CreateOwnerBad writes the owners read table directly — the violation the
// audit found in the served handlers.
//
//trstctl:mutation
func CreateOwnerBad(st *store.Store) error {
	_, err := st.CreateOwner("billing") // want "must not write the read model directly"
	return err
}

// UpsertCertBad writes the certificate read table directly.
//
//trstctl:mutation
func UpsertCertBad(st *store.Store) error {
	return st.UpsertCertificate("fp-aaa") // want "must not write the read model directly"
}

// RevokeIssuedCertBad writes the OCSP/CRL responder read model directly.
//
//trstctl:mutation
func RevokeIssuedCertBad(st *store.Store) error {
	return st.RevokeIssuedCert("tenant-1", "ca-1", "01", 0) // want "must not write the read model directly"
}

// UpdateAndDeleteBad is two violations in one handler.
//
//trstctl:mutation
func UpdateAndDeleteBad(st *store.Store) error {
	if err := st.UpdateOwner("id", "n"); err != nil { // want "must not write the read model directly"
		return err
	}
	return st.DeleteOwner("id") // want "must not write the read model directly"
}

// CreateOwnerGood emits an event instead, and may freely read the store to
// validate inputs. No direct read-model write, so it is compliant.
//
//trstctl:mutation
func CreateOwnerGood(st *store.Store) error {
	if _, err := st.GetOwner("owner-1"); err != nil { // a read — allowed
		return err
	}
	return emit("owner.created")
}

// Unmarked is not a served mutation handler, so it is not constrained (it is the
// projector/command layer's job to write the read model) — neither its store
// mutator call nor a raw read-model write is flagged here.
func Unmarked(st *store.Store) error {
	if _, err := st.CreateOwner("x"); err != nil {
		return err
	}
	return exec("INSERT INTO owners (id, name) VALUES ($1, $2)")
}

// exec stands in for a tx.Exec(rawSQL, ...) raw-SQL execution path.
func exec(query string) error { _ = query; return nil }

// RawInsertBad is the SPINE-010 evasion: a marked mutation handler that reaches
// past the store mutators and writes the owners read table with raw SQL. The
// call-name check would miss this; the raw-SQL check must catch it.
//
//trstctl:mutation
func RawInsertBad(st *store.Store) error {
	return exec("INSERT INTO owners (id, name) VALUES ($1, $2)") // want "must not write the read model table .owners. with raw SQL"
}

// RawUpdateBad writes a read-model table via a raw UPDATE.
//
//trstctl:mutation
func RawUpdateBad(st *store.Store) error {
	return exec("UPDATE certificates SET status = 'revoked' WHERE id = $1") // want "must not write the read model table .certificates. with raw SQL"
}

// RawDeleteBad writes a read-model table via a raw DELETE.
//
//trstctl:mutation
func RawDeleteBad(st *store.Store) error {
	return exec("DELETE FROM identity_transitions WHERE identity_id = $1") // want "must not write the read model table .identity_transitions. with raw SQL"
}

// RawCRLInsertBad writes the CRL read model via raw SQL.
//
//trstctl:mutation
func RawCRLInsertBad(st *store.Store) error {
	return exec("INSERT INTO ca_crls (tenant_id, ca_id, crl_number) VALUES ($1, $2, $3)") // want "must not write the read model table .ca_crls. with raw SQL"
}

// RawSelectOK reads a read-model table — a SELECT is not a write, so it is allowed
// even in a mutation handler (the handler may validate inputs by reading).
//
//trstctl:mutation
func RawSelectOK(st *store.Store) error {
	if err := exec("SELECT id FROM owners WHERE id = $1"); err != nil {
		return err
	}
	return emit("owner.updated")
}

// RawWriteNonReadModelOK writes a NON-read-model table (an operational table that
// is not a projection of the log) — out of scope, not flagged.
//
//trstctl:mutation
func RawWriteNonReadModelOK(st *store.Store) error {
	return exec("INSERT INTO ca_authorities (tenant_id, name) VALUES ($1, $2)")
}

// NotSQLLooking proves the shape check: a struct-literal-ish string that merely
// starts with a SQL-ish word but is not a real statement is not flagged.
//
//trstctl:mutation
func NotSQLLooking(st *store.Store) error {
	return exec("update your profile in settings") // prose, no SET clause — not SQL
}

// RouteMutationWritesStore is not annotated, but the route registry declares it
// as a mutation. Route-derived coverage must catch the direct read-model write.
func (a *API) RouteMutationWritesStore(st *store.Store) error {
	_, err := st.CreateOwner("billing") // want "must not write the read model directly"
	return err
}

// RouteMutationEmitsEvent proves route-derived coverage accepts event emission.
func (a *API) RouteMutationEmitsEvent(st *store.Store) error {
	if _, err := st.GetOwner("owner-1"); err != nil {
		return err
	}
	return emit("owner.created")
}

// RouteReadWritesStore is registered as read-only, so it is ignored by this
// served-mutation rule.
func (a *API) RouteReadWritesStore(st *store.Store) error {
	_, err := st.CreateOwner("ignored")
	return err
}
