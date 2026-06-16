package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/orchestrator"
)

// AN-5: a handler marked //trstctl:mutation must thread an idempotency key into
// a real dedupe sink. The ARCH-002 tightening: it is no longer enough to pass
// the key to ANY call (a logger does not dedupe), nor to declare an
// idempotency-named parameter and never use it. The key must reach either
// orchestrator.Idempotency.Do (the canonical sink) or a forwarding call whose
// callee itself takes an idempotency-named parameter (the served API.mutate
// pattern, which threads the key onward to Do).

// logf stands in for a structured logger: an arbitrary call that happens to
// receive the key but does NOT dedupe.
func logf(format string, args ...any) {}

// save forwards to the dedupe store; its parameter is the idempotency key, so a
// call to it is a recognized forwarding sink (the API.mutate pattern).
func save(ctx context.Context, idempotencyKey string) error {
	_ = ctx
	_ = idempotencyKey
	return nil
}

// dedupe is the orchestrator dedupe store used by the canonical-sink cases.
var dedupe *orchestrator.Idempotency

// CreateBad never touches an idempotency key at all.
//
//trstctl:mutation
func CreateBad(w http.ResponseWriter, r *http.Request) { // want "must thread an idempotency key into a dedupe sink"
	_ = w
	_ = r
}

// ReadsButDiscards extracts the header into a plain variable and drops it; the
// key flows nowhere, so it does not honor AN-5.
//
//trstctl:mutation
func ReadsButDiscards(w http.ResponseWriter, r *http.Request) { // want "must thread an idempotency key into a dedupe sink"
	key := r.Header.Get("Idempotency-Key")
	_ = key
	_ = w
}

// PassesToLogger reads the key and hands it to a logger — a call, but not a
// dedupe sink. ARCH-002: this previously passed because the old rule accepted the
// key flowing into ANY call. It must now be flagged.
//
//trstctl:mutation
func PassesToLogger(w http.ResponseWriter, r *http.Request) { // want "must thread an idempotency key into a dedupe sink"
	idempotencyKey := r.Header.Get("Idempotency-Key")
	logf("creating resource idempotency_key=%s", idempotencyKey)
	_ = w
}

// ParamButUnused declares an idempotency-named parameter but never threads it
// anywhere. ARCH-002: a parameter by itself is not honoring; this must be
// flagged (the old rule passed it on the parameter name alone).
//
//trstctl:mutation
func ParamButUnused(ctx context.Context, tenantID, name, idempotencyKey string) error { // want "must thread an idempotency key into a dedupe sink"
	_ = ctx
	_ = tenantID
	_ = name
	_ = idempotencyKey // discarded, never reaches a sink
	return nil
}

// CreateGoodViaMutate threads the extracted key into a forwarding sink (save
// takes an idempotency-named parameter), the served-handler pattern.
//
//trstctl:mutation
func CreateGoodViaMutate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	_ = save(r.Context(), idempotencyKey)
	_ = w
}

// CreateGoodViaDo threads the key straight into the canonical sink,
// orchestrator.Idempotency.Do.
//
//trstctl:mutation
func CreateGoodViaDo(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	_, _ = dedupe.Do(r.Context(), "tenant", idempotencyKey, func(ctx context.Context) ([]byte, error) {
		return nil, nil
	})
	_ = w
}

// RegisterTenantForwards accepts the key as a parameter and forwards it to the
// dedupe store (orchestrator-path style).
//
//trstctl:mutation
func RegisterTenantForwards(ctx context.Context, tenantID, name, idempotencyKey string) error {
	return save(ctx, idempotencyKey)
}

// Unmarked is not annotated as a mutation, so it is ignored even though it never
// touches an idempotency key.
func Unmarked(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r
}
