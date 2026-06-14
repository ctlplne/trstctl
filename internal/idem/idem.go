// Package idem is the shared idempotency seam (AN-5) used by the incident-response
// and approval subsystems (Epoch 12). The PostgreSQL-backed
// orchestrator.Idempotency satisfies Idempotencer in production; Memory is the
// in-process implementation for single-node deployments and tests.
package idem

import (
	"context"
	"errors"
	"sync"
)

// Idempotencer records an idempotency key with its result; a replay returns the
// original result rather than executing again (AN-5).
type Idempotencer interface {
	Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error)
}

// ErrInProgress is returned when a concurrent caller holds the same key.
var ErrInProgress = errors.New("idem: operation already in progress")

// Memory is a thread-safe in-memory Idempotencer.
type Memory struct {
	mu       sync.Mutex
	done     map[string][]byte
	inflight map[string]bool
}

// NewMemory constructs a Memory idempotencer.
func NewMemory() *Memory {
	return &Memory{done: map[string][]byte{}, inflight: map[string]bool{}}
}

// Do runs fn once per (tenantID,key): a successful result is recorded and
// replayed; an error releases the claim so a later retry can succeed.
func (m *Memory) Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	full := tenantID + "|" + key
	m.mu.Lock()
	if r, ok := m.done[full]; ok {
		m.mu.Unlock()
		return r, nil
	}
	if m.inflight[full] {
		m.mu.Unlock()
		return nil, ErrInProgress
	}
	m.inflight[full] = true
	m.mu.Unlock()

	res, err := fn(ctx)

	m.mu.Lock()
	delete(m.inflight, full)
	if err == nil {
		m.done[full] = res
	}
	m.mu.Unlock()
	return res, err
}
