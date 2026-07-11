// SPDX-License-Identifier: MPL-2.0

package bulkhead_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
)

// PERF-005 (27-PERF) PROTECT regression guard.
//
// Confirmed strength: subsystems run on BOUNDED, FAST-REJECTING worker pools
// (internal/bulkhead/bulkhead.go), and the Set groups one ISOLATED pool per subsystem
// so a saturated subsystem cannot consume another's capacity
// (internal/bulkhead/set.go) — AN-7 bulkheads + backpressure. Route-level metrics ride
// on top via Stats().
//
// This is a fully BEHAVIORAL, in-memory test — no Postgres, no NATS, no network, well
// under the time budget. It (1) fills a real Pool to capacity and asserts the next
// Submit fast-rejects with a *Rejected/ErrRejected error rather than blocking, with the
// correct ReasonFull and Retryable semantics; (2) asserts a closed pool rejects
// permanently (not retryable); and (3) asserts pool ISOLATION — saturating one
// subsystem in a Set does not stop another subsystem from accepting work, and an
// unknown subsystem rejects. If a future change makes a pool block instead of shed, or
// lets one subsystem's saturation leak into another, this guard goes RED.
func TestProtectPERF005_PoolFastRejectsWhenFull(t *testing.T) {
	// One worker, queue of one: capacity is exactly 1 running + 1 queued = 2 in-flight.
	p := bulkhead.New(bulkhead.Config{Name: "perf005", Workers: 1, Queue: 1})
	defer p.Close()

	release := make(chan struct{})
	started := make(chan struct{}, 1)

	// Occupy the single worker with a task that blocks until we release it.
	if err := p.Submit(func() {
		started <- struct{}{}
		<-release
	}); err != nil {
		t.Fatalf("PERF-005: first Submit (occupy worker) unexpectedly rejected: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("PERF-005: the worker never picked up the first task; the pool is not draining its queue")
	}

	// Fill the single queue slot (this one is parked behind the busy worker).
	if err := p.Submit(func() { <-release }); err != nil {
		t.Fatalf("PERF-005: second Submit (fill queue) unexpectedly rejected: %v", err)
	}

	// The pool is now full (worker busy + queue full). The next Submit MUST fast-reject
	// rather than block.
	done := make(chan error, 1)
	go func() { done <- p.Submit(func() {}) }()
	var rejErr error
	select {
	case rejErr = <-done:
	case <-time.After(2 * time.Second):
		close(release) // unblock the parked tasks before failing
		t.Fatal("PERF-005: Submit to a full pool BLOCKED instead of fast-rejecting; the bulkhead no longer sheds load")
	}
	if rejErr == nil {
		close(release)
		t.Fatal("PERF-005: Submit to a full pool returned nil; over-capacity work must be rejected, not silently accepted")
	}
	if !errors.Is(rejErr, bulkhead.ErrRejected) {
		close(release)
		t.Fatalf("PERF-005: full-pool rejection %v does not match ErrRejected; callers can no longer detect backpressure via errors.Is", rejErr)
	}
	var rej *bulkhead.Rejected
	if !errors.As(rejErr, &rej) {
		close(release)
		t.Fatalf("PERF-005: full-pool rejection is not a *Rejected: %v", rejErr)
	}
	if rej.Reason != bulkhead.ReasonFull {
		close(release)
		t.Errorf("PERF-005: full-pool rejection reason = %q, want %q (queue full)", rej.Reason, bulkhead.ReasonFull)
	}
	if !rej.Retryable() {
		close(release)
		t.Error("PERF-005: a queue-full rejection must be Retryable (a transient full queue)")
	}

	// Let the parked tasks drain so Close() returns promptly.
	close(release)

	// A closed pool rejects permanently (not retryable).
	p2 := bulkhead.New(bulkhead.Config{Name: "perf005-closed", Workers: 1, Queue: 1})
	p2.Close()
	err := p2.Submit(func() {})
	var rej2 *bulkhead.Rejected
	if !errors.As(err, &rej2) || rej2.Reason != bulkhead.ReasonClosed {
		t.Fatalf("PERF-005: Submit to a closed pool = %v, want a *Rejected with ReasonClosed", err)
	}
	if rej2.Retryable() {
		t.Error("PERF-005: a closed-pool rejection must NOT be retryable (permanent)")
	}
}

// TestProtectPERF005_SubsystemPoolsAreIsolated proves a saturated subsystem does not
// consume another subsystem's capacity (the core bulkhead isolation guarantee).
func TestProtectPERF005_SubsystemPoolsAreIsolated(t *testing.T) {
	const busy, idle = "busy-subsystem", "idle-subsystem"
	set := bulkhead.NewSet(
		bulkhead.Config{Name: busy, Workers: 1, Queue: 1},
		bulkhead.Config{Name: idle, Workers: 1, Queue: 1},
	)
	defer set.Close()

	release := make(chan struct{})
	defer close(release)
	var wg sync.WaitGroup

	// Saturate the busy subsystem: occupy its worker and fill its queue.
	wg.Add(1)
	if err := set.Submit(busy, func() { wg.Done(); <-release }); err != nil {
		t.Fatalf("PERF-005: occupying %s rejected: %v", busy, err)
	}
	wg.Wait() // ensure the worker is actually running before filling the queue
	if err := set.Submit(busy, func() { <-release }); err != nil {
		t.Fatalf("PERF-005: filling %s queue rejected: %v", busy, err)
	}
	// The busy subsystem is now saturated and must shed.
	if err := set.Submit(busy, func() {}); !errors.Is(err, bulkhead.ErrRejected) {
		t.Fatalf("PERF-005: a saturated subsystem did not shed; got %v", err)
	}

	// ISOLATION: the idle subsystem must still accept work despite the busy one being
	// saturated. If this rejects, one subsystem's load has leaked into another.
	ran := make(chan struct{}, 1)
	if err := set.Submit(idle, func() { ran <- struct{}{} }); err != nil {
		t.Fatalf("PERF-005: the idle subsystem rejected work while a DIFFERENT subsystem was saturated; pool isolation is broken: %v", err)
	}
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("PERF-005: the idle subsystem accepted but never ran the task; isolation/draining is broken")
	}

	// An unknown subsystem rejects permanently (no pool to consume).
	err := set.Submit("no-such-subsystem", func() {})
	var rej *bulkhead.Rejected
	if !errors.As(err, &rej) || rej.Reason != bulkhead.ReasonUnknown {
		t.Fatalf("PERF-005: Submit to an unknown subsystem = %v, want a *Rejected with ReasonUnknown", err)
	}
}

// TestProtectPERF005_DefaultSetRegistersIsolatedSubsystemPools locks that the canonical
// subsystem set exists and that each registered subsystem has its own (non-nil,
// distinct) pool — the route-level isolation the strength depends on.
func TestProtectPERF005_DefaultSetRegistersIsolatedSubsystemPools(t *testing.T) {
	set := bulkhead.Default()
	defer set.Close()

	subsystems := []string{
		bulkhead.SubsystemAPI,
		bulkhead.SubsystemProjections,
		bulkhead.SubsystemOutbox,
		bulkhead.SubsystemOutboxExternalCA,
		bulkhead.SubsystemOutboxConnectors,
		bulkhead.SubsystemOutboxSecrets,
		bulkhead.SubsystemOutboxSecretSync,
		bulkhead.SubsystemOutboxManagedKeys,
		bulkhead.SubsystemOutboxTransparency,
		bulkhead.SubsystemOutboxCodeSigning,
		bulkhead.SubsystemOutboxNotifications,
		bulkhead.SubsystemSigning,
		bulkhead.SubsystemQuery,
		bulkhead.SubsystemPolicy,
		bulkhead.SubsystemProtocols,
		bulkhead.SubsystemAgent,
		bulkhead.SubsystemCBOM,
	}
	seen := map[*bulkhead.Pool]string{}
	for _, name := range subsystems {
		p := set.Pool(name)
		if p == nil {
			t.Errorf("PERF-005: default Set has no isolated pool for subsystem %q", name)
			continue
		}
		if other, dup := seen[p]; dup {
			t.Errorf("PERF-005: subsystems %q and %q share the same pool pointer; they are not isolated", name, other)
		}
		seen[p] = name
	}

	// Stats() must report one entry per registered pool (the route-level metrics seam),
	// ordered and non-empty.
	stats := set.Stats()
	if len(stats) < len(subsystems) {
		t.Errorf("PERF-005: Stats() reported %d pools, want at least %d (the per-subsystem metrics seam regressed)", len(stats), len(subsystems))
	}
	for _, s := range stats {
		if s.Name == "" {
			t.Error("PERF-005: a pool Stats entry has a blank subsystem name")
		}
		if s.Capacity < 0 {
			t.Errorf("PERF-005: pool %q reports negative capacity %d", s.Name, s.Capacity)
		}
	}
}
