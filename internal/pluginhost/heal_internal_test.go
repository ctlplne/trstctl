// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
)

// spinOKWASM exports spin() i32 — an infinite loop, the shape of a guest that
// exceeds its deadline — and ok() i32 which returns 7 immediately.
var spinOKWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type: () -> i32
	0x03, 0x03, 0x02, 0x00, 0x00, // two funcs of type 0
	0x07, 0x0d, 0x02, // exports: 2 entries
	0x04, 0x73, 0x70, 0x69, 0x6e, 0x00, 0x00, // "spin" -> func 0
	0x02, 0x6f, 0x6b, 0x00, 0x01, // "ok" -> func 1
	0x0a, 0x10, 0x02, // code: 2 bodies
	0x09, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x41, 0x00, 0x0b, // spin: loop { br 0 }; i32.const 0
	0x04, 0x00, 0x41, 0x07, 0x0b, // ok: i32.const 7
}

// TestInterruptedCallDoesNotBrickTheConnector is the regression guard for
// AUD-201 follow-up J2/V8. WithCloseOnContextDone makes guests interruptible —
// and closes the api.Module when a call's context ends. Nothing reset it and
// no cache reloads, so ONE deploy exceeding its deadline bricked that
// connector until process restart: every later Invoke returned sys.ExitError,
// and certificate deployments and renewals through it silently stopped. The
// plugin now heals by re-instantiating from its retained bytes, so the next
// invocation succeeds.
func TestInterruptedCallDoesNotBrickTheConnector(t *testing.T) {
	ctx := context.Background()
	h := New()
	t.Cleanup(func() { _ = h.Close(ctx) })
	plugin, err := h.Load(ctx, spinOKWASM, NewGrant())
	if err != nil {
		t.Skipf("fixture guest did not load in this environment: %v", err)
	}
	t.Cleanup(func() { _ = plugin.Close(context.Background()) })

	// A call that exceeds its deadline: the interrupt closes the module.
	timeoutCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if _, err := h.Invoke(timeoutCtx, plugin, "spin"); err == nil {
		cancel()
		t.Fatal("a looping guest returned without error; the interrupt did not fire")
	}
	cancel()

	// The NEXT invocation must succeed — this is the whole finding.
	v, err := h.Invoke(ctx, plugin, "ok")
	if err != nil {
		t.Fatalf("the connector is bricked after one interrupted call: %v", err)
	}
	if v != 7 {
		t.Fatalf("healed invoke returned %d, want 7", v)
	}
}

// TestAbandonedQueueEntryDoesNotKillAHealthyModule pins the bulkhead half of
// J2/V8: Invoke returns on ctx.Done while its closure still sits in the
// bounded queue; when that closure eventually ran it called into wazero with
// the DEAD context — under the old shared-instance design that closed a
// healthy module without the guest ever executing. The closure must fast-drop
// dead work, and later invocations must be untouched by the abandonment.
func TestAbandonedQueueEntryDoesNotKillAHealthyModule(t *testing.T) {
	ctx := context.Background()
	pool := bulkhead.New(bulkhead.Config{Name: "plugin-heal-test", Workers: 1, Queue: 4})
	t.Cleanup(pool.Close)
	h := New(WithPool(pool))
	plugin, err := h.Load(ctx, spinOKWASM, NewGrant())
	if err != nil {
		t.Skipf("fixture guest did not load in this environment: %v", err)
	}
	t.Cleanup(func() { _ = plugin.Close(context.Background()) })

	// Occupy the single worker so the next Invoke queues.
	release := make(chan struct{})
	blocked := make(chan struct{})
	if err := pool.Submit(func() { close(blocked); <-release }); err != nil {
		t.Fatalf("occupy worker: %v", err)
	}
	<-blocked

	// Enqueue an invoke, then abandon it while it is still queued.
	abandonCtx, abandonCancel := context.WithCancel(ctx)
	invokeDone := make(chan error, 1)
	go func() {
		_, err := h.Invoke(abandonCtx, plugin, "ok")
		invokeDone <- err
	}()
	// Give the goroutine a moment to enqueue behind the blocker, then abandon.
	time.Sleep(50 * time.Millisecond)
	abandonCancel()
	if err := <-invokeDone; err == nil {
		t.Fatal("the abandoned invoke reported success")
	}
	// Let the abandoned closure drain through the worker; it must fast-drop
	// without instantiating or executing anything.
	close(release)
	seqBefore := plugin.nameSeq.Load()
	deadline := time.Now().Add(5 * time.Second)
	for plugin.nameSeq.Load() != seqBefore {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := plugin.nameSeq.Load(); got != seqBefore {
		t.Fatalf("the abandoned queue entry instantiated a call module (seq %d -> %d); dead work must be dropped before it touches wazero", seqBefore, got)
	}
	if v, err := h.Invoke(ctx, plugin, "ok"); err != nil || v != 7 {
		t.Fatalf("invoke after the abandoned entry drained = (%d, %v), want (7, nil)", v, err)
	}
}
