package pluginhost_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
)

// trustedSigner generates an Ed25519 key pair through the crypto boundary (AN-3)
// and returns a one-key trust policy plus a closure that signs a module the way
// an operator's plugin-signing tool would.
func trustedSigner(t *testing.T, pins ...string) (*pluginhost.TrustPolicy, func([]byte) []byte) {
	t.Helper()
	pubDER, sign, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tp, err := pluginhost.NewTrustPolicy([][]byte{crypto.MarshalPublicKeyPEM(pubDER)}, pins)
	if err != nil {
		t.Fatalf("NewTrustPolicy: %v", err)
	}
	return tp, sign
}

// TestLoadVerifiedAdmitsSignedModule is the SUPPLY-004 happy path: a module
// signed by a trusted key loads through the verified path and runs.
func TestLoadVerifiedAdmitsSignedModule(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	tp, sign := trustedSigner(t)
	sig := sign(helloWASM)

	p, err := h.LoadVerified(ctx, helloWASM, sig, tp, pluginhost.NewGrant())
	if err != nil {
		t.Fatalf("LoadVerified of a correctly-signed module: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })

	got, err := h.Invoke(ctx, p, "run")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if got != 42 {
		t.Errorf("run() = %d, want 42", got)
	}
}

// TestLoadVerifiedRefusesUnsigned is the SUPPLY-004 core assertion: a module
// with no signature is refused — the runtime is never instantiated.
func TestLoadVerifiedRefusesUnsigned(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	tp, _ := trustedSigner(t)
	if _, err := h.LoadVerified(ctx, helloWASM, nil, tp, pluginhost.NewGrant()); err == nil {
		t.Fatal("LoadVerified admitted an UNSIGNED module; it must be refused (SUPPLY-004)")
	}
}

// TestLoadVerifiedRefusesTampered is the SUPPLY-004 tamper assertion: a module
// mutated after signing no longer verifies and is refused.
func TestLoadVerifiedRefusesTampered(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	tp, sign := trustedSigner(t)
	sig := sign(helloWASM)

	// Flip a guaranteed-different byte in the module body (the i32.const operand),
	// keeping it a valid module shape, so the failure is provenance, not parse.
	tampered := append([]byte(nil), helloWASM...)
	last := len(tampered) - 2 // the 0x2a (42) constant operand
	tampered[last] ^= 0xFF
	if _, err := h.LoadVerified(ctx, tampered, sig, tp, pluginhost.NewGrant()); err == nil {
		t.Fatal("LoadVerified admitted a BYTE-TAMPERED module; it must be refused (SUPPLY-004)")
	}
}

// TestLoadVerifiedRefusesWrongKey is the SUPPLY-004 untrusted-signer assertion: a
// valid signature from a key NOT in the trust policy is refused.
func TestLoadVerifiedRefusesWrongKey(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	// Trust policy holds key A; the module is signed by an entirely different key B.
	tp, _ := trustedSigner(t)
	_, signB, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.LoadVerified(ctx, helloWASM, signB(helloWASM), tp, pluginhost.NewGrant()); err == nil {
		t.Fatal("LoadVerified admitted a module signed by an UNTRUSTED key; it must be refused (SUPPLY-004)")
	}
}

// TestLoadVerifiedHonorsContentPin is the SUPPLY-004 pinning assertion: with a
// pinned digest set, only the exact pinned artifact is admitted even if signed.
func TestLoadVerifiedHonorsContentPin(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	// Pin the digest of capWASM, but try to load helloWASM signed by the trusted key.
	pin := crypto.SHA256Hex(capWASM)
	tp, sign := trustedSigner(t, pin)
	if _, err := h.LoadVerified(ctx, helloWASM, sign(helloWASM), tp, pluginhost.NewGrant()); err == nil {
		t.Fatal("LoadVerified admitted a module not in the pinned allowlist; it must be refused (SUPPLY-004)")
	}
	// The pinned module (also signed) is admitted.
	p, err := h.LoadVerified(ctx, capWASM, sign(capWASM), tp, pluginhost.NewGrant(pluginhost.CapFSWrite))
	if err != nil {
		t.Fatalf("LoadVerified of the pinned, signed module: %v", err)
	}
	_ = p.Close(ctx)
}

// TestTrustPolicyFailsClosed is the SUPPLY-004 fail-closed assertion: a policy
// with no trusted keys cannot be constructed, and a nil policy verifies nothing.
func TestTrustPolicyFailsClosed(t *testing.T) {
	if _, err := pluginhost.NewTrustPolicy(nil, nil); err == nil {
		t.Error("NewTrustPolicy with no trusted keys must fail (fail closed)")
	}
	var nilPolicy *pluginhost.TrustPolicy
	if err := nilPolicy.Verify(helloWASM, []byte("sig")); err == nil {
		t.Error("a nil trust policy must refuse every module (fail closed)")
	}
}
