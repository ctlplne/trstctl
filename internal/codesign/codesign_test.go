package codesign

import (
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

func (k keyMap) Signer(id string) (crypto.DigestSigner, error) {
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
	// The verified attestation is authoritative: its Subject is the SAN and its
	// oidc_issuer claim is the issuer (PKIGOV-011). The caller may echo them, but
	// they must match the attestation.
	san := "https://github.com/acme/x/.github/workflows/release.yml@refs/heads/main"
	sig, err := svc.SignKeyless(context.Background(), KeylessRequest{
		Principal: "ci",
		Identity: attest.Attestation{
			Method: "github_oidc", Subject: san,
			Claims:     map[string]string{"oidc_issuer": "https://token.actions.githubusercontent.com"},
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
