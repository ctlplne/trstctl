package api

import (
	"context"
	"net/http"
)

// AN-5: a handler marked //certctl:mutation must accept and honor an idempotency
// key. The S2.4 tightening: it is no longer enough to *mention* the key — it
// must be named and threaded through, either as a parameter or as an argument to
// a call (into the orchestrator's dedupe store).

// CreateBad never touches an idempotency key at all.
//
//certctl:mutation
func CreateBad(w http.ResponseWriter, r *http.Request) { // want "must accept and honor an idempotency key"
	_ = w
	_ = r
}

// ReadsButDiscards extracts the header into a plain variable and drops it; the
// key flows nowhere, so it does not honor AN-5. Under the pre-S2.4 rule the bare
// mention passed — that loophole is now closed.
//
//certctl:mutation
func ReadsButDiscards(w http.ResponseWriter, r *http.Request) { // want "must accept and honor an idempotency key"
	key := r.Header.Get("Idempotency-Key")
	_ = key
	_ = w
}

// CreateGood threads the extracted key into the store call, so the key is
// actually used to dedupe.
//
//certctl:mutation
func CreateGood(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	_ = save(r.Context(), idempotencyKey)
	_ = w
}

// RegisterTenant is the orchestrator-path style: it accepts the key as a
// parameter (and passes it to the dedupe store).
//
//certctl:mutation
func RegisterTenant(ctx context.Context, tenantID, name, idempotencyKey string) error {
	return save(ctx, idempotencyKey)
}

// Unmarked is not annotated as a mutation, so it is ignored even though it never
// touches an idempotency key.
func Unmarked(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r
}

func save(ctx context.Context, idempotencyKey string) error {
	_ = ctx
	_ = idempotencyKey
	return nil
}
