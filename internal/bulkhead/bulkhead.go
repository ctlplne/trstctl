// SPDX-License-Identifier: MPL-2.0

// Package bulkhead implements AN-7: each subsystem runs on its own bounded worker
// pool with a bounded queue. When a pool is saturated it rejects new work fast,
// with a structured error, instead of blocking the caller — so one slow or
// flooded subsystem can never exhaust the capacity another depends on.
//
// Pool is the reusable primitive; Set groups one isolated Pool per subsystem. A
// rejected submission returns *Rejected (matchable with errors.Is(err,
// ErrRejected)), which the API layer maps to a 429/503 problem+json response.
package bulkhead

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// Reason classifies why a submission was rejected.
type Reason string

const (
	// ReasonFull means the worker pool's queue is at capacity. The caller may
	// retry later.
	ReasonFull Reason = "queue full"
	// ReasonClosed means the pool has been shut down. Permanent.
	ReasonClosed Reason = "pool closed"
	// ReasonUnknown means no pool is registered for the named subsystem. Permanent.
	ReasonUnknown Reason = "unknown subsystem"
)

// ErrRejected matches any backpressure rejection via errors.Is.
var ErrRejected = errors.New("bulkhead: work rejected")

// Rejected is the structured error returned when work cannot be accepted.
type Rejected struct {
	Pool     string // the subsystem/pool name
	Reason   Reason
	Capacity int // the pool's queue capacity, for context
}

// Error implements error.
func (e *Rejected) Error() string {
	return fmt.Sprintf("bulkhead %q rejected work: %s (queue capacity %d)", e.Pool, e.Reason, e.Capacity)
}

// Is reports whether the target is the ErrRejected sentinel, so callers can
// detect backpressure with errors.Is.
func (e *Rejected) Is(target error) bool { return target == ErrRejected }

// Retryable reports whether retrying later might succeed (a transient full
// queue), as opposed to a permanent rejection (closed pool, unknown subsystem).
func (e *Rejected) Retryable() bool { return e.Reason == ReasonFull }

// Config describes a pool.
type Config struct {
	Name    string // subsystem name, used in errors and stats
	Workers int    // concurrent workers (>=1; defaults to 1)
	Queue   int    // queue capacity (>=0; work beyond this is rejected)
}

// Stats is a snapshot of a pool's state and lifetime counters.
type Stats struct {
	Name      string
	Workers   int
	Capacity  int
	Queued    int // tasks currently waiting in the queue
	Submitted int64
	Completed int64
	Rejected  int64
	Panicked  int64
}

// Pool is a bounded worker pool: Workers goroutines draining a queue of at most
// Queue tasks. Submitting to a full pool fails fast rather than blocking.
type Pool struct {
	name    string
	workers int
	queue   chan func()

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	submitted atomic.Int64
	completed atomic.Int64
	rejected  atomic.Int64
	panicked  atomic.Int64
}

// New starts a Pool per the config. Workers defaults to 1 and a negative Queue is
// treated as 0.
func New(cfg Config) *Pool {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.Queue < 0 {
		cfg.Queue = 0
	}
	p := &Pool{
		name:    cfg.Name,
		workers: cfg.Workers,
		queue:   make(chan func(), cfg.Queue),
	}
	p.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for task := range p.queue {
		p.run(task)
	}
}

// run executes one task, isolating a panic so a single bad task cannot tear down
// the worker or the process.
func (p *Pool) run(task func()) {
	defer func() {
		if r := recover(); r != nil {
			p.panicked.Add(1)
			return
		}
		p.completed.Add(1)
	}()
	task()
}

// Submit enqueues task for execution. It returns nil if the task was accepted,
// or *Rejected (never blocking) if the queue is full or the pool is closed.
func (p *Pool) Submit(task func()) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		p.rejected.Add(1)
		return &Rejected{Pool: p.name, Reason: ReasonClosed, Capacity: cap(p.queue)}
	}
	select {
	case p.queue <- task:
		p.submitted.Add(1)
		return nil
	default:
		p.rejected.Add(1)
		return &Rejected{Pool: p.name, Reason: ReasonFull, Capacity: cap(p.queue)}
	}
}

// Close stops accepting work, lets the workers drain everything already queued,
// and waits for them to finish. It is safe to call more than once.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.queue)
	p.mu.Unlock()
	p.wg.Wait()
}

// Stats returns a snapshot of the pool's counters.
func (p *Pool) Stats() Stats {
	return Stats{
		Name:      p.name,
		Workers:   p.workers,
		Capacity:  cap(p.queue),
		Queued:    len(p.queue),
		Submitted: p.submitted.Load(),
		Completed: p.completed.Load(),
		Rejected:  p.rejected.Load(),
		Panicked:  p.panicked.Load(),
	}
}
