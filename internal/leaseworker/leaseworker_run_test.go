// SPDX-License-Identifier: MPL-2.0

package leaseworker

import (
	"context"
	"sync"
	"testing"
	"time"
)

type countEngine struct {
	mu             sync.Mutex
	expire, revoke int
}

func (e *countEngine) ExpireDue(context.Context, time.Time) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expire++
	return 0, nil
}
func (e *countEngine) RunRevocations(context.Context) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revoke++
	return 0, nil
}

func TestWorkerRunTicksThenDrainsOnCancel(t *testing.T) {
	e := &countEngine{}
	w := New(e, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(35 * time.Millisecond) // allow several ticks
	cancel()
	if err := <-done; err == nil {
		t.Error("Run should return the context cancellation error")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.expire < 1 {
		t.Error("worker never ticked (no ExpireDue calls)")
	}
	if e.revoke < 1 {
		t.Error("worker never drained the revocation queue")
	}
}
