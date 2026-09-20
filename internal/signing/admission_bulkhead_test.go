// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	signerpb "trstctl.com/trstctl/internal/signing/proto"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/signing"
)

// TestSignerAdmission_BulkheadBoundsConcurrentRPCs is the AUD-6 regression: the
// operator's bulkheads.signing pool must actually BOUND concurrent signer
// round-trips from the control-plane side. It installs the same submit-and-wait
// hook the server assembly installs, over a real bulkhead pool with workers=1,
// queue=0, against a REAL signer over a UDS whose Sign is held open — and
// asserts the second concurrent RPC is rejected fast with bulkhead.ErrRejected,
// client-side, without ever reaching the signer. A test that merely asserts the
// pool exists in the Set passes on the pre-fix tree; this one cannot: before the
// admission hook existed, nothing routed signer work through the pool at all.
func TestSignerAdmission_BulkheadBoundsConcurrentRPCs(t *testing.T) {
	dir, err := os.MkdirTemp("", "sg-admission")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")

	svc := signing.NewServer()
	gen, err := svc.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Hold every Sign open server-side so the single admitted RPC occupies the
	// pool's one worker deterministically.
	release := make(chan struct{})
	var gated atomic.Int32
	svc.SetSignGateForTest(func() {
		gated.Add(1)
		<-release
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- signing.ServeServerWithOptions(ctx, socket, svc, devServeOptions()) }()

	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()

	// The exact hook shape internal/server installs: submit-and-wait on the
	// operator's signing pool. workers=1, queue=0 ⇒ one in-flight RPC, zero
	// queued, everything else rejected fast.
	pool := bulkhead.New(bulkhead.Config{Name: bulkhead.SubsystemSigning, Workers: 1, Queue: 0})
	t.Cleanup(pool.Close)
	client.SetAdmission(func(call func() error) error {
		done := make(chan error, 1)
		if err := pool.Submit(func() { done <- call() }); err != nil {
			return err
		}
		return <-done
	})
	if !client.AdmissionInstalled() {
		t.Fatal("admission hook not installed")
	}

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

	// First RPC: admitted, reaches the signer, held in the gate.
	first := make(chan error, 1)
	go func() { first <- signReq(30 * time.Second) }()
	deadline := time.Now().Add(5 * time.Second)
	for gated.Load() < 1 {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("first Sign never reached the signer gate")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Second RPC while the worker is held: rejected fast with the structured
	// bulkhead error, and it must never reach the signer.
	err = signReq(5 * time.Second)
	if !errors.Is(err, bulkhead.ErrRejected) {
		close(release)
		t.Fatalf("second concurrent signer RPC = %v, want bulkhead.ErrRejected (the operator's bound must bind)", err)
	}
	if got := gated.Load(); got != 1 {
		close(release)
		t.Fatalf("signer gate saw %d RPCs, want 1 — the rejected call must be shed client-side", got)
	}

	// Release: the admitted RPC completes successfully through the pool.
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("admitted Sign failed: %v", err)
	}

	select {
	case err := <-served:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("serve: %v", err)
		}
	default:
	}
}

// TestSignerAdmission_IsScopedPerClient reproduces the broad-suite failure that
// a process-global admission hook caused: one assembled server closed its pool,
// then an unrelated client's Health calls were rejected by that closed pool.
// Each connection must own its hook so shutdown and parallel assemblies cannot
// poison one another.
func TestSignerAdmission_IsScopedPerClient(t *testing.T) {
	dir, err := os.MkdirTemp("", "sg-isolation")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(), devServeOptions())
	}()

	clientA := waitReady(t, socket)
	t.Cleanup(func() { _ = clientA.Close() })
	clientB := waitReady(t, socket)
	t.Cleanup(func() { _ = clientB.Close() })
	pool := bulkhead.New(bulkhead.Config{Name: "closed-client-a", Workers: 1, Queue: 0})
	pool.Close()
	clientA.SetAdmission(func(call func() error) error {
		return pool.Submit(func() { _ = call() })
	})

	if clientA.Healthy(context.Background()) {
		t.Fatal("client A unexpectedly bypassed its closed admission pool")
	}
	if !clientB.Healthy(context.Background()) {
		t.Fatal("client B was poisoned by client A's closed admission pool")
	}

	cancel()
	if err := <-served; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serve: %v", err)
	}
}
