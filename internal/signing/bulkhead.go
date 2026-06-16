package signing

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// AN-7 backpressure for the signing service.
//
// The signer is the single most sensitive process (AN-4: "if it is compromised,
// the company is over"), and issuance fails closed when it is unhealthy — so a
// flood of expensive Sign/GenerateKey calls from the (assumed-compromisable)
// control plane must shed load fast rather than drive the signer to CPU/memory
// exhaustion and take issuance platform-wide offline. The design promises a
// bounded in-flight cap and RESOURCE_EXHAUSTED (docs/design/signing-service.md
// §5.4/§5.5); this implements it with a fixed-size semaphore over the expensive
// RPCs, plus a per-RPC deadline. Cheap, non-key-bound RPCs (Health,
// GetPublicKey, DestroyKey) are deliberately NOT gated, so a saturating flood of
// Sign/GenerateKey can never starve a liveness probe.

const (
	// defaultMaxInflight bounds concurrent expensive (key-using) RPCs. Sized for
	// a single signer process: signing and especially RSA-4096 keygen are
	// CPU-bound, so a small bound protects the host while leaving ample headroom
	// for a healthy control plane (which issues serially per request).
	defaultMaxInflight = 32

	// defaultRPCTimeout caps how long any single RPC may run if the caller did
	// not set a shorter deadline. Work past the deadline is abandoned (design
	// §5.4), so a wedged operation cannot hold an in-flight slot forever.
	defaultRPCTimeout = 30 * time.Second
)

// expensiveMethods are the key-using RPCs subject to the in-flight bound. They
// are the only ones that consume real CPU (a signature, or a keygen) and the
// only DoS lever worth gating. Liveness/metadata RPCs stay unbounded. The keys
// come from the generated gRPC stub's FullMethodName constants, which are the
// authoritative dispatch paths the server matches at runtime (so this can never
// silently drift from the registered service name).
var expensiveMethods = map[string]bool{
	signerpb.SignerService_Sign_FullMethodName:        true,
	signerpb.SignerService_GenerateKey_FullMethodName: true,
}

// limiter is a fixed-capacity, non-blocking concurrency gate. A failed Acquire
// means the signer is at capacity and the caller must back off; it never blocks.
type limiter struct {
	slots chan struct{}
}

func newLimiter(capacity int) *limiter {
	if capacity < 1 {
		capacity = 1
	}
	return &limiter{slots: make(chan struct{}, capacity)}
}

// tryAcquire takes a slot without blocking. It returns false (reject fast) when
// the pool is saturated — this is the AN-7 "full pool rejects fast" contract.
func (l *limiter) tryAcquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *limiter) release() { <-l.slots }

func (l *limiter) capacity() int { return cap(l.slots) }

// inflight reports how many slots are currently held (for tests/metrics).
func (l *limiter) inflight() int { return len(l.slots) }

// bulkheadInterceptor returns a unary server interceptor that bounds concurrent
// expensive RPCs to lim.capacity(); excess calls are rejected immediately with
// codes.ResourceExhausted (never blocking, never queuing unboundedly), and every
// RPC is given a deadline if the caller did not set one.
func bulkheadInterceptor(lim *limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Bound the RPC's lifetime so an abandoned/wedged call cannot pin a slot.
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, defaultRPCTimeout)
			defer cancel()
		}

		if !expensiveMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		if !lim.tryAcquire() {
			method := info.FullMethod
			if i := strings.LastIndex(method, "/"); i >= 0 {
				method = method[i+1:]
			}
			return nil, status.Errorf(codes.ResourceExhausted,
				"signer at capacity (%d concurrent %s in flight); retry later", lim.capacity(), method)
		}
		defer lim.release()
		return handler(ctx, req)
	}
}
