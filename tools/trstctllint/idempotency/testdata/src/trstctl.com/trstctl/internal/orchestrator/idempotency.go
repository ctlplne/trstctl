// Package orchestrator stands in for the real orchestrator so the analyzer can
// resolve the canonical dedupe sink, (*Idempotency).Do, by its true type and
// import path (not by the spelling of the receiver at a call site).
package orchestrator

import "context"

// Idempotency is the dedupe store. Do runs fn at most once per (tenant, key).
type Idempotency struct{}

// Do is the canonical AN-5 dedupe sink: a call resolving to this method honors
// the rule when the idempotency key flows into it.
func (i *Idempotency) Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	return fn(ctx)
}
