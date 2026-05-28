// Package orchestrator implements the credential lifecycle state machine and
// the cross-cutting mutation guarantees that hang off it.
//
// It owns idempotency (AN-5): every state-changing operation records an
// Idempotency-Key so replays return the original result instead of executing
// again. It also owns the outbox dispatch (AN-6): every external call is
// written to the outbox in the same transaction as the state change and is
// performed by a separate worker, giving at-least-once delivery with an
// exactly-once effect.
//
// Implementation begins in sprint S3.2; this file reserves the package.
package orchestrator
