// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"sync"
	"sync/atomic"

	"trstctl.com/trstctl/internal/events"
)

// headMemo is THE per-tenant, head-keyed memo for event-log projections that
// sit on request paths (AUD-201 follow-up F4/V27b). vault_compat_state and
// policy_versions each hand-rolled this exact flow — LastSequence, lock/lookup,
// hit on atSeq == head, rebuild, store, fall back to an uncached rebuild when
// the head read fails — and F5/V21's third replay endpoint had no memo at all.
// One implementation means F3's incremental catch-up and every future
// projection cache land in a single place.
type headMemo[T any] struct {
	mu       sync.Mutex
	byTenant map[string]headMemoEntry[T]

	// scannedEvents counts every event a rebuild or catch-up observes; test
	// instrumentation for the F3/V27a bounded-catch-up property.
	scannedEvents atomic.Int64
}

type headMemoEntry[T any] struct {
	value T
	atSeq uint64
}

// headMemoHooks enables incremental catch-up (F3/V27a): Copy must deep-copy
// the projection's shared structure — cached values are aliased by snapshots
// already returned to callers — and Fold applies one event. Projections whose
// fold mutates shared records may pass nil hooks and keep from-zero rebuilds.
type headMemoHooks[T any] struct {
	Copy func(T) T
	Fold func(*T, events.Event) error
}

// get returns the tenant's projection at the current log head. rebuild replays
// from zero (the caller wraps its own scanned-event counting via count). On a
// head mismatch with hooks present, only the events after the cached sequence
// are folded — via ReplayThrough bounded to the captured head, so a racing
// append cannot smuggle events past the recorded sequence — onto a Copy of the
// cached value. Catch-up failures (generation switch, gap) and head
// regressions fall back to the from-zero rebuild. A failed head read falls
// back to an uncached rebuild rather than failing the request.
func (m *headMemo[T]) get(
	ctx context.Context,
	log *events.Log,
	tenantID string,
	rebuild func(context.Context) (T, error),
	hooks *headMemoHooks[T],
) (T, error) {
	if log == nil {
		return rebuild(ctx)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		return rebuild(ctx)
	}
	m.mu.Lock()
	cached, ok := m.byTenant[tenantID]
	m.mu.Unlock()
	if ok && cached.atSeq == head {
		return cached.value, nil
	}
	if ok && cached.atSeq < head && hooks != nil && hooks.Copy != nil && hooks.Fold != nil {
		built := hooks.Copy(cached.value)
		if err := log.ReplayThrough(ctx, cached.atSeq+1, head, func(ev events.Event) error {
			m.scannedEvents.Add(1)
			return hooks.Fold(&built, ev)
		}); err == nil {
			m.store(tenantID, built, head)
			return built, nil
		}
	}
	built, err := rebuild(ctx)
	if err != nil {
		return built, err
	}
	m.store(tenantID, built, head)
	return built, nil
}

func (m *headMemo[T]) store(tenantID string, value T, head uint64) {
	m.mu.Lock()
	if m.byTenant == nil {
		m.byTenant = map[string]headMemoEntry[T]{}
	}
	m.byTenant[tenantID] = headMemoEntry[T]{value: value, atSeq: head}
	m.mu.Unlock()
}

// prime stores a value directly; tests use it to seed cache states.
func (m *headMemo[T]) prime(tenantID string, value T, head uint64) {
	m.store(tenantID, value, head)
}
