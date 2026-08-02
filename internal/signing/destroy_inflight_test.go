// SPDX-License-Identifier: MPL-2.0

package signing_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestDestroyKeyDuringInFlightSignFailsClosed pins the AN-4 fail-closed contract on
// the RPC surface: the signer serves Sign and DestroyKey concurrently and holds no
// per-key lock between the handle lookup and the private-key operation, so a
// DestroyKey can complete after a Sign has already resolved its handle. That Sign
// must then fail closed with the destroyed-key error — never crash, never sign with
// released material.
//
// Scope, stated precisely: s.signGate fires at server.go:293-294, which is AFTER the
// handle lookup but BEFORE held.signer.SignDigest at :297 — i.e. OUTSIDE the
// private-key operation. So this test is NOT the regression tripwire for the
// use-after-free; it passes with or without the secret.Buffer borrow fix, because
// pre-fix the resumed Sign simply sees a nil buffer and returns the same error. The
// tripwire for the borrow itself is TestSignDigestInFlightSurvivesConcurrentDestroy
// (internal/crypto — only an in-package seam can park INSIDE the private-key
// operation) plus TestConcurrentSignAndDestroyKeyStaysWithinTheContract below, run
// under -race. This test's job is the narrower one of pinning the error contract so
// a future refactor cannot turn a lost destroy race into a success or a panic.
//
// Determinism: the gate parks the Sign, the destroy is completed while it is parked,
// and only then is the gate released. No timing assumption is involved.
func TestDestroyKeyDuringInFlightSignFailsClosed(t *testing.T) {
	svc := signing.NewServer()
	ctx := context.Background()

	gen, err := svc.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	svc.SetSignGateForTest(func() {
		once.Do(func() { close(entered) })
		<-release
	})

	type result struct {
		resp *signerpb.SignResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := svc.Sign(ctx, &signerpb.SignRequest{
			Handle: gen.GetHandle(),
			Digest: make([]byte, 32),
			Hash:   signerpb.Hash_HASH_SHA256,
		})
		done <- result{resp, err}
	}()

	<-entered
	if _, err := svc.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: gen.GetHandle()}); err != nil {
		t.Fatalf("DestroyKey while a Sign was in flight: %v", err)
	}
	close(release)

	got := <-done
	if got.err == nil {
		t.Fatal("Sign succeeded against a key destroyed before the private-key operation ran; it must fail closed")
	}
	if code := status.Code(got.err); code != codes.Internal {
		t.Errorf("Sign after concurrent DestroyKey: code = %v, want %v (err = %v)", code, codes.Internal, got.err)
	}
	if !strings.Contains(got.err.Error(), "locked key has been destroyed") {
		t.Errorf("Sign after concurrent DestroyKey = %v, want the destroyed-key error", got.err)
	}
}

// TestConcurrentSignAndDestroyKeyStaysWithinTheContract runs the same interleaving
// unsynchronized and at volume. It is deliberately outcome-tolerant — every
// individual Sign may legitimately succeed, be refused as destroyed, or find the
// handle already gone — so it can never flake; what it catches is anything OUTSIDE
// that set: a fault, a race report under -race, or a signature produced from
// released key material. Run it with -race.
func TestConcurrentSignAndDestroyKeyStaysWithinTheContract(t *testing.T) {
	const keys = 24
	svc := signing.NewServer()
	ctx := context.Background()

	handles := make([]*signerpb.KeyHandle, 0, keys)
	for i := 0; i < keys; i++ {
		gen, err := svc.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
			Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		})
		if err != nil {
			t.Fatalf("GenerateKey %d: %v", i, err)
		}
		handles = append(handles, gen.GetHandle())
	}

	var wg sync.WaitGroup
	for _, h := range handles {
		wg.Add(3)
		go func(h *signerpb.KeyHandle) {
			defer wg.Done()
			if _, err := svc.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: h}); err != nil {
				t.Errorf("DestroyKey(%s): %v", h.GetId(), err)
			}
		}(h)
		for j := 0; j < 2; j++ {
			go func(h *signerpb.KeyHandle) {
				defer wg.Done()
				_, err := svc.Sign(ctx, &signerpb.SignRequest{
					Handle: h,
					Digest: make([]byte, 32),
					Hash:   signerpb.Hash_HASH_SHA256,
				})
				if err == nil {
					return // signed before the destroy landed: allowed
				}
				switch status.Code(err) {
				case codes.NotFound:
					return // handle already forgotten: allowed
				case codes.Internal:
					if strings.Contains(err.Error(), "locked key has been destroyed") {
						return // key released before the operation ran: allowed
					}
				}
				t.Errorf("Sign(%s) raced by DestroyKey returned an out-of-contract error: %v", h.GetId(), err)
			}(h)
		}
	}
	wg.Wait()
}
