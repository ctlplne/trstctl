// SPDX-License-Identifier: MPL-2.0

package codesign

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

type keyMap struct {
	m map[string]crypto.DigestSigner
}

func (k keyMap) Signer(_ string, id string) (crypto.DigestSigner, error) {
	s, ok := k.m[id]
	if !ok {
		return nil, fmt.Errorf("no key %s", id)
	}
	return s, nil
}

type gateFn func(ctx context.Context, t, p, k, d string) (bool, string)

func (g gateFn) MaySign(ctx context.Context, t, p, k, d string) (bool, string) {
	return g(ctx, t, p, k, d)
}

type recordingDigestSigner struct {
	inner crypto.DigestSigner
	seen  []byte
}

func (s *recordingDigestSigner) Public() crypto.PublicKey    { return s.inner.Public() }
func (s *recordingDigestSigner) Algorithm() crypto.Algorithm { return s.inner.Algorithm() }
func (s *recordingDigestSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	s.seen = append(s.seen[:0], digest...)
	return s.inner.SignDigest(digest, opts)
}

func TestCodesignSignsTheSuppliedSHA256DigestExactlyOnce(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	recorder := &recordingDigestSigner{inner: key}
	svc, err := New(Config{TenantID: "tenant-a", Keys: keyMap{m: map[string]crypto.DigestSigner{"release": recorder}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Sum([]byte("artifact bytes"))
	sig, err := svc.Sign(context.Background(), SignRequest{Principal: "builder", KeyID: "release", ArtifactType: "blob", Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recorder.seen, digest) {
		t.Fatalf("signer received %x, want caller's exact digest %x", recorder.seen, digest)
	}
	doubleHash := crypto.SHA256Sum(digest)
	if bytes.Equal(recorder.seen, doubleHash) {
		t.Fatal("code signing double-hashed the artifact digest")
	}
	if err := crypto.VerifyDigest(key.Public(), digest, sig.Value, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}); err != nil {
		t.Fatalf("stock digest verification failed: %v", err)
	}
}

func TestCodesignKeyBasedNoKeyToRequester(t *testing.T) {
	key, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer key.Destroy()
	rec := &auditsink.Recorder{}
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{"key1": key}}, Audit: rec})
	digest := crypto.SHA256Sum([]byte("the artifact"))
	for _, at := range []string{"blob", "oci-image", "sbom"} {
		sig, err := svc.Sign(context.Background(), SignRequest{Principal: "alice", KeyID: "key1", ArtifactType: at, Digest: digest})
		if err != nil {
			t.Fatalf("%s sign: %v", at, err)
		}
		if err := svc.Verify(sig, digest); err != nil {
			t.Fatalf("%s verify: %v", at, err)
		}
	}
	if rec.Count("codesign.signed") != 3 {
		t.Errorf("signed audit count = %d, want 3", rec.Count("codesign.signed"))
	}
}

func TestCodesignUnapprovedRefused(t *testing.T) {
	key, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer key.Destroy()
	rec := &auditsink.Recorder{}
	gate := gateFn(func(_ context.Context, _, p, _, _ string) (bool, string) {
		if p == "intruder" {
			return false, "not an authorized signer"
		}
		return true, ""
	})
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{"key1": key}}, Gate: gate, Audit: rec})
	if _, err := svc.Sign(context.Background(), SignRequest{Principal: "intruder", KeyID: "key1", Digest: crypto.SHA256Sum([]byte("x"))}); err == nil {
		t.Error("an unapproved signer was permitted by policy")
	}
	if rec.Count("codesign.refused") != 1 {
		t.Error("policy refusal not audited")
	}
}

func TestCodesignKeylessFulcioBound(t *testing.T) {
	eph, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer eph.Destroy()
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{}}})
	digest := crypto.SHA256Sum([]byte("image-manifest"))
	// The verified attestation is authoritative: Fulcio-specific verified claims
	// take precedence over the generic OIDC subject/issuer.
	san := "https://github.com/acme/x/.github/workflows/release.yml@refs/heads/main"
	sig, err := svc.SignKeyless(context.Background(), KeylessRequest{
		Principal: "ci",
		Identity: attest.Attestation{
			Method: "github_oidc", Subject: "repo:acme/x:ref:refs/heads/main",
			Claims: map[string]string{
				"fulcio_san": san, "fulcio_issuer": "https://token.actions.githubusercontent.com",
			},
			VerifiedAt: time.Now(),
		},
		FulcioSAN:    san,
		FulcioIssuer: "https://token.actions.githubusercontent.com",
		Ephemeral:    eph, ArtifactType: "oci-image", Digest: digest,
	})
	if err != nil {
		t.Fatalf("SignKeyless: %v", err)
	}
	if err := svc.VerifyKeyless(sig, digest); err != nil {
		t.Fatalf("keyless verify: %v", err)
	}
	// The signature is bound to the ATTESTATION's identity, not a caller-asserted one.
	if sig.FulcioSAN != san {
		t.Errorf("keyless SAN = %q, want the verified attestation subject %q", sig.FulcioSAN, san)
	}
	if sig.FulcioIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("keyless issuer = %q, want the verified attestation issuer", sig.FulcioIssuer)
	}
}

func TestCodesignKeylessRequiresConfiguredGateDecision(t *testing.T) {
	eph, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer eph.Destroy()
	rec := &auditsink.Recorder{}
	called := false
	gate := gateFn(func(_ context.Context, tenantID, principal, keyID, digestHex string) (bool, string) {
		called = true
		if tenantID != "t1" || principal != "ci" || keyID != "keyless:repo:acme/release" || digestHex == "" {
			t.Fatalf("keyless gate tuple = tenant %q principal %q key %q digest %q", tenantID, principal, keyID, digestHex)
		}
		return false, "approval required"
	})
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{}}, Gate: gate, Audit: rec})
	_, err := svc.SignKeyless(context.Background(), KeylessRequest{
		Principal: "ci",
		Identity: attest.Attestation{
			Method: "github_oidc", Subject: "repo:acme/release", VerifiedAt: time.Now(),
		},
		Ephemeral: eph, ArtifactType: "oci-image", Digest: crypto.SHA256Sum([]byte("artifact")),
	})
	if err == nil || !called {
		t.Fatalf("keyless gate refusal = called %v err %v", called, err)
	}
	if rec.Count("codesign.keyless.refused") != 1 {
		t.Fatalf("keyless gate refusal audit count = %d", rec.Count("codesign.keyless.refused"))
	}
}

// TestCodesignKeylessRejectsForgedSAN is the PKIGOV-011 acceptance: SignKeyless must
// reject a request whose caller-supplied FulcioSAN does NOT match the verified
// attestation subject — a caller cannot attach an arbitrary SAN to a keyless
// signature. Pre-fix SignKeyless ignored req.Identity entirely and trusted
// FulcioSAN, so an attacker-chosen SAN was honored. The refusal is audited.
func TestCodesignKeylessRejectsForgedSAN(t *testing.T) {
	eph, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer eph.Destroy()
	rec := &auditsink.Recorder{}
	svc, _ := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{}}, Audit: rec})
	digest := crypto.SHA256Sum([]byte("artifact"))

	// The attestation verifies identity "repo:acme/real", but the caller claims a
	// SAN for a DIFFERENT repo. The mismatch must be rejected.
	_, err := svc.SignKeyless(context.Background(), KeylessRequest{
		Principal: "ci",
		Identity: attest.Attestation{
			Method: "github_oidc", Subject: "repo:acme/real:ref:refs/heads/main",
			VerifiedAt: time.Now(),
		},
		FulcioSAN: "repo:attacker/forged:ref:refs/heads/main",
		Ephemeral: eph, ArtifactType: "blob", Digest: digest,
	})
	if err == nil {
		t.Fatal("SignKeyless accepted a FulcioSAN that does not match the verified attestation (PKIGOV-011)")
	}
	if rec.Count("codesign.keyless.refused") != 1 {
		t.Errorf("keyless SAN-mismatch refusal not audited (got %d)", rec.Count("codesign.keyless.refused"))
	}

	// With the SAN omitted (deriving it from the attestation) the SAME request
	// succeeds and binds to the VERIFIED subject — proving the attestation, not the
	// caller, is authoritative.
	sig, err := svc.SignKeyless(context.Background(), KeylessRequest{
		Principal: "ci",
		Identity: attest.Attestation{
			Method: "github_oidc", Subject: "repo:acme/real:ref:refs/heads/main",
			VerifiedAt: time.Now(),
		},
		Ephemeral: eph, ArtifactType: "blob", Digest: digest,
	})
	if err != nil {
		t.Fatalf("SignKeyless with attestation-derived SAN failed: %v", err)
	}
	if sig.FulcioSAN != "repo:acme/real:ref:refs/heads/main" {
		t.Errorf("keyless SAN = %q, want the verified subject", sig.FulcioSAN)
	}
}
