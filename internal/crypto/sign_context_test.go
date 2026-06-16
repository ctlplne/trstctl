package crypto_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestSignContextFallsBackForSoftwareSigner verifies the CODE-002 helper:
// SignContext / GenerateKeyContext work uniformly across backends. The CPU-bound
// software signer does NOT implement crypto.ContextSigner (it has no I/O to
// cancel), so the helper must fall back to the context-less Sign/GenerateKey and
// still produce a valid signature. A caller can therefore thread a context
// everywhere without special-casing the backend.
func TestSignContextFallsBackForSoftwareSigner(t *testing.T) {
	b := crypto.NewSoftwareBackend()

	signer, err := crypto.GenerateKeyContext(context.Background(), b, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyContext (software): %v", err)
	}
	// The software signer is deliberately NOT a ContextSigner.
	if _, ok := signer.(crypto.ContextSigner); ok {
		t.Error("the software signer should NOT implement crypto.ContextSigner (it has no cancelable I/O)")
	}

	msg := []byte("context helper probe")
	opts := crypto.SignOptions{Hash: crypto.SHA256}
	sig, err := crypto.SignContext(context.Background(), signer, msg, opts)
	if err != nil {
		t.Fatalf("SignContext (software fallback): %v", err)
	}
	if err := crypto.Verify(signer.Public(), msg, sig, opts); err != nil {
		t.Fatalf("software signature via SignContext did not verify: %v", err)
	}
}

// TestSignContextRespectsAlreadyCancelledContext verifies the helpers fail fast on
// an already-cancelled context rather than performing the operation — the cheap
// safety property that makes threading a context meaningful even for the fallback
// (software) path, which would otherwise ignore the context entirely.
func TestSignContextRespectsAlreadyCancelledContext(t *testing.T) {
	b := crypto.NewSoftwareBackend()
	signer, err := b.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before use

	if _, err := crypto.SignContext(ctx, signer, []byte("x"), crypto.SignOptions{Hash: crypto.SHA256}); !errors.Is(err, context.Canceled) {
		t.Errorf("SignContext with a cancelled context = %v; want context.Canceled", err)
	}
	if _, err := crypto.GenerateKeyContext(ctx, b, crypto.ECDSAP256); !errors.Is(err, context.Canceled) {
		t.Errorf("GenerateKeyContext with a cancelled context = %v; want context.Canceled", err)
	}
}
