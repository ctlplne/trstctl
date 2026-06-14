package codesign

import (
	"context"
	"fmt"
	"testing"

	"trustctl.io/trustctl/internal/attest"
	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
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
	sig, err := svc.SignKeyless(context.Background(), KeylessRequest{
		Principal:    "ci",
		Identity:     attest.Attestation{Method: "github_oidc", Subject: "repo:acme/x:ref:refs/heads/main"},
		FulcioSAN:    "https://github.com/acme/x/.github/workflows/release.yml@refs/heads/main",
		FulcioIssuer: "https://token.actions.githubusercontent.com",
		Ephemeral:    eph, ArtifactType: "oci-image", Digest: digest,
	})
	if err != nil {
		t.Fatalf("SignKeyless: %v", err)
	}
	if err := svc.VerifyKeyless(sig, digest); err != nil {
		t.Fatalf("keyless verify: %v", err)
	}
	if sig.FulcioSAN == "" || sig.FulcioIssuer == "" {
		t.Error("keyless signature not bound to a Fulcio identity")
	}
}
