package signing

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestLimiterRejectsBeyondCapacity is the deterministic core of the SIGNER-001
// AN-7 bound: a fixed-capacity limiter accepts exactly cap slots and rejects the
// next acquisition immediately (never blocking), then accepts again after a
// release.
func TestLimiterRejectsBeyondCapacity(t *testing.T) {
	lim := newLimiter(3)
	if lim.capacity() != 3 {
		t.Fatalf("capacity = %d, want 3", lim.capacity())
	}
	for i := 0; i < 3; i++ {
		if !lim.tryAcquire() {
			t.Fatalf("acquire %d should succeed within capacity", i)
		}
	}
	if lim.inflight() != 3 {
		t.Fatalf("inflight = %d, want 3", lim.inflight())
	}
	// Saturated: the next acquire must reject fast (returns false, does not block).
	done := make(chan bool, 1)
	go func() { done <- lim.tryAcquire() }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("acquire beyond capacity should fail fast, got success")
		}
	case <-time.After(time.Second):
		t.Fatal("tryAcquire blocked instead of rejecting fast")
	}
	// Releasing one frees a slot.
	lim.release()
	if !lim.tryAcquire() {
		t.Fatal("acquire after release should succeed")
	}
}

// TestBulkheadInterceptorShedsExpensiveLoad proves the interceptor's AN-7
// contract deterministically: with capacity N, N expensive RPCs can be in flight
// at once, the (N+1)th is rejected immediately with RESOURCE_EXHAUSTED, and a
// cheap RPC (Health) is NEVER gated even while the expensive pool is saturated —
// so a Sign/GenerateKey flood cannot starve liveness.
func TestBulkheadInterceptorShedsExpensiveLoad(t *testing.T) {
	const cap = 4
	lim := newLimiter(cap)
	interceptor := bulkheadInterceptor(lim)

	release := make(chan struct{})
	var inHandler atomic.Int32
	blockingHandler := func(ctx context.Context, req any) (any, error) {
		inHandler.Add(1)
		<-release // hold the slot until the test releases it
		return "ok", nil
	}

	signInfo := &grpc.UnaryServerInfo{FullMethod: signerpb.SignerService_Sign_FullMethodName}

	// Fill capacity with blocked expensive RPCs.
	var wg sync.WaitGroup
	for i := 0; i < cap; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = interceptor(context.Background(), nil, signInfo, blockingHandler)
		}()
	}
	// Wait until all cap handlers are actually in flight (holding slots).
	deadline := time.Now().Add(2 * time.Second)
	for inHandler.Load() < cap {
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d handlers entered", inHandler.Load(), cap)
		}
		time.Sleep(time.Millisecond)
	}

	// The next expensive RPC is shed fast with RESOURCE_EXHAUSTED.
	rejectHandlerCalled := false
	start := time.Now()
	_, err := interceptor(context.Background(), nil, signInfo,
		func(ctx context.Context, req any) (any, error) { rejectHandlerCalled = true; return nil, nil })
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("saturated expensive RPC: got %v, want ResourceExhausted", status.Code(err))
	}
	if rejectHandlerCalled {
		t.Error("a shed RPC must not reach the handler (no key op performed)")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("rejection took %v; AN-7 requires rejecting fast, not blocking", d)
	}

	// A cheap RPC (Health) is unaffected even while the expensive pool is full.
	healthInfo := &grpc.UnaryServerInfo{FullMethod: "/trstctl.signing.v1.SignerService/Health"}
	healthRan := false
	if _, err := interceptor(context.Background(), nil, healthInfo,
		func(ctx context.Context, req any) (any, error) { healthRan = true; return "serving", nil }); err != nil {
		t.Errorf("Health should not be gated by the expensive bulkhead, got %v", err)
	}
	if !healthRan {
		t.Error("Health handler should have run despite a saturated expensive pool")
	}

	close(release)
	wg.Wait()
}

// TestBulkheadInterceptorAddsDeadline confirms an RPC with no caller deadline is
// given one, so a wedged operation cannot pin an in-flight slot forever.
func TestBulkheadInterceptorAddsDeadline(t *testing.T) {
	lim := newLimiter(1)
	interceptor := bulkheadInterceptor(lim)
	info := &grpc.UnaryServerInfo{FullMethod: "/trstctl.signing.v1.SignerService/Sign"}
	var hadDeadline bool
	_, err := interceptor(context.Background(), nil, info,
		func(ctx context.Context, req any) (any, error) {
			_, hadDeadline = ctx.Deadline()
			return "ok", nil
		})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if !hadDeadline {
		t.Error("interceptor should add a deadline when the caller set none")
	}
}
