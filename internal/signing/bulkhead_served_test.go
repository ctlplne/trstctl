package signing_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestSignerShedsFloodOverUDS is the SIGNER-001 / RED-003 served-path acceptance
// test: a real signer running over a Unix domain socket, flooded with far more
// concurrent Sign RPCs than its in-flight bound, sheds the excess fast with
// RESOURCE_EXHAUSTED rather than admitting unbounded concurrency (the pre-fix
// behavior that drives the signer to CPU/memory exhaustion and takes issuance
// platform-wide offline). It also proves a cheap liveness probe (Health) keeps
// answering while the expensive pool is saturated.
//
// Determinism: a test-only gate holds each in-flight Sign on the server side, so
// exactly `bound` slots fill and stay full while the rest of the burst arrives.
// That removes any dependence on wall-clock timing — the excess MUST be shed.
//
// Pre-fix (no bulkhead) this test fails: every Sign is admitted, zero are shed.
func TestSignerShedsFloodOverUDS(t *testing.T) {
	const bound = 4
	dir := t.TempDir()
	socket := filepath.Join(dir, "s.sock")

	svc := signing.NewServer()

	// Create the key BEFORE installing the gate, so GenerateKey is unaffected and
	// we have a handle to sign with.
	gen, err := svc.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Gate: every Sign blocks here (holding its in-flight slot) until released.
	release := make(chan struct{})
	var gated atomic.Int32
	svc.SetSignGateForTest(func() {
		gated.Add(1)
		<-release
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, svc, signing.ServeOptions{MaxInflight: bound})
	}()

	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()

	signReq := func(timeout time.Duration) error {
		sctx, c := context.WithTimeout(ctx, timeout)
		defer c()
		_, err := client.RawSignForTest(sctx, &signerpb.SignRequest{
			Handle: gen.GetHandle(),
			Digest: make([]byte, 32),
			Hash:   signerpb.Hash_HASH_SHA256,
		})
		return err
	}

	// Phase 1: fill the pool. Fire `bound` Signs; each enters the gate and holds
	// its slot. They will not return until we close(release).
	var fillWG sync.WaitGroup
	fillErrs := make(chan error, bound)
	for i := 0; i < bound; i++ {
		fillWG.Add(1)
		go func() {
			defer fillWG.Done()
			fillErrs <- signReq(30 * time.Second) // held in the gate until release
		}()
	}
	// Wait until all `bound` slots are genuinely occupied in the gate.
	deadline := time.Now().Add(5 * time.Second)
	for gated.Load() < bound {
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("only %d/%d Signs reached the gate", gated.Load(), bound)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Phase 2: the pool is now saturated. Further Signs must be shed immediately
	// with RESOURCE_EXHAUSTED (they never reach the gate).
	// A short per-call timeout means that even if a regression let an extra Sign
	// into the (blocked) gate, the test fails fast rather than deadlocking.
	const extra = 16
	var shed, leaked int32
	var exWG sync.WaitGroup
	for i := 0; i < extra; i++ {
		exWG.Add(1)
		go func() {
			defer exWG.Done()
			err := signReq(3 * time.Second)
			switch status.Code(err) {
			case codes.ResourceExhausted:
				atomic.AddInt32(&shed, 1)
			case codes.OK:
				atomic.AddInt32(&leaked, 1) // would mean the bound did not hold
			}
		}()
	}
	exWG.Wait()

	if shed == 0 {
		close(release)
		t.Fatalf("saturated signer admitted all %d extra Signs; expected RESOURCE_EXHAUSTED shedding (pool is unbounded)", extra)
	}
	if leaked != 0 {
		close(release)
		t.Fatalf("%d extra Signs were admitted past the in-flight bound of %d", leaked, bound)
	}

	// Phase 3: Health must answer fast even with the pool fully saturated (cheap
	// RPC is not gated by the expensive bulkhead).
	hctx, hc := context.WithTimeout(ctx, 2*time.Second)
	if !client.Healthy(hctx) {
		hc()
		close(release)
		t.Fatal("Health did not answer while the expensive pool was saturated")
	}
	hc()

	// Release the held Signs; they should now complete cleanly.
	close(release)
	fillWG.Wait()
	close(fillErrs)
	for err := range fillErrs {
		if err != nil {
			t.Errorf("a held Sign failed after release: %v", err)
		}
	}

	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

// TestSignerHealthUnaffectedBySlowKeygen is the focused form of the audit's
// second verification ("a single slow GenerateKey cannot block Health"): a
// long-running keygen is in flight, yet Health answers promptly.
func TestSignerHealthUnaffectedBySlowKeygen(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// RSA-4096 keygen is the slowest signer op; it must not hold any lock
		// that Health needs.
		_, _ = s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_RSA_4096})
	}()

	// Health must answer well before the keygen finishes.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h, err := s.Health(ctx, &signerpb.HealthRequest{})
		if err != nil || h.GetStatus() != signerpb.HealthResponse_STATUS_SERVING {
			t.Fatalf("Health during keygen = %v, err %v; want SERVING", h.GetStatus(), err)
		}
		select {
		case <-done:
			return // keygen finished; we already proved Health answered during it
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	<-done
}
