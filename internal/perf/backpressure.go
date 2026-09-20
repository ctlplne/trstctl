// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
)

const (
	soakBackpressureSubsystem = "perf-soak-backpressure"
	soakBackpressureRejects   = 3
)

// SoakBackpressureObserver receives the real bounded-queue stats captured while
// the soak runner keeps neighboring hot paths active.
type SoakBackpressureObserver interface {
	ObserveSoakBackpressure([]bulkhead.Stats)
}

// BoundedRejectionPhase holds one saturated product bulkhead long enough for a
// neighboring hot path to be measured under pressure.
type BoundedRejectionPhase struct {
	pool    *bulkhead.Pool
	release chan struct{}
	closed  bool
}

// StartBoundedRejectionPhase saturates a tiny real bulkhead and induces a bounded
// number of fast rejections. Call Close after the neighboring measurement is done.
func StartBoundedRejectionPhase() (*BoundedRejectionPhase, error) {
	pool := bulkhead.New(bulkhead.Config{Name: soakBackpressureSubsystem, Workers: 1, Queue: 1})
	phase := &BoundedRejectionPhase{pool: pool, release: make(chan struct{})}
	started := make(chan struct{}, 1)
	if err := pool.Submit(func() {
		started <- struct{}{}
		<-phase.release
	}); err != nil {
		phase.Close()
		return nil, fmt.Errorf("start bounded backpressure worker: %w", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		phase.Close()
		return nil, fmt.Errorf("start bounded backpressure worker: timed out")
	}
	if err := pool.Submit(func() { <-phase.release }); err != nil {
		phase.Close()
		return nil, fmt.Errorf("fill bounded backpressure queue: %w", err)
	}
	for i := 0; i < soakBackpressureRejects; i++ {
		if err := pool.Submit(func() {}); !errors.Is(err, bulkhead.ErrRejected) {
			phase.Close()
			return nil, fmt.Errorf("induce bounded backpressure rejection %d: %w", i+1, err)
		}
	}
	return phase, nil
}

// QueueRejects returns the real rejection counter from the saturated pool.
func (p *BoundedRejectionPhase) QueueRejects() float64 {
	if p == nil || p.pool == nil {
		return 0
	}
	return float64(p.pool.Stats().Rejected)
}

// Stats returns the real bulkhead stats for metrics publication.
func (p *BoundedRejectionPhase) Stats() []bulkhead.Stats {
	if p == nil || p.pool == nil {
		return nil
	}
	return []bulkhead.Stats{p.pool.Stats()}
}

// Close releases queued work and drains the saturated pool.
func (p *BoundedRejectionPhase) Close() {
	if p == nil || p.pool == nil || p.closed {
		return
	}
	p.closed = true
	close(p.release)
	p.pool.Close()
}
