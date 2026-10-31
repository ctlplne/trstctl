// SPDX-License-Identifier: BUSL-1.1

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
// DestinationScope keeps claim selection, expired-lease recovery, in-flight
// budgets and circuit probes in the same destination family. Exact and prefix
// includes form a union; either exclusion removes a destination. Empty includes
// retain the ordinary all-destinations behavior. All comparisons are literal.
// Routing a row grants no tenant service or receiver authority: a post-delete
// effect needs its own dedicated worker and independently verified invocation.
//
// The package persists idempotency keys in tenant-scoped tables, so it carries
// the //trstctl:repository marker below and its SQL is subject to the AN-1
// tenant-filter rule. The lifecycle state machine itself lands in S3.2.
//
//trstctl:repository
package orchestrator
