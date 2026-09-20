// SPDX-License-Identifier: BUSL-1.1

package digest_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/digest"
	"trstctl.com/trstctl/internal/signing"
)

// Root, policy posture and watermark in one signed body (XREC-claims-9, 11).
func TestDigest_CommitsRootPostureWatermark(t *testing.T) {
	base := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), sampleRules(), "plane-a", "42")
	baseHash := mustHash(t, base.Body)
	assertContains(t, mustBodyBytes(t, base.Body), []byte(`"spec_version":"xrec.canon/v1"`))

	recordChanged := mustBuild(t, sampleSet(t, "revoked", canon.SpecVersionV1), sampleRules(), "plane-a", "42")
	assertDifferentHash(t, baseHash, mustHash(t, recordChanged.Body), "record change")

	postureChanged := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), []digest.Rule{{
		ID:         "all-active",
		Expression: "status == active AND algorithm == ed25519",
		Evaluate: func(r canon.CanonicalRecord) bool {
			return r.Status == canon.StatusActive && r.Algorithm == "ed25519"
		},
	}}, "plane-a", "42")
	assertDifferentHash(t, baseHash, mustHash(t, postureChanged.Body), "posture change")

	watermarkChanged := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), sampleRules(), "plane-a", "43")
	assertDifferentHash(t, baseHash, mustHash(t, watermarkChanged.Body), "watermark change")

	specChanged := mustBuild(t, sampleSet(t, "active", "xrec.canon/v2"), sampleRules(), "plane-a", "42")
	assertDifferentHash(t, baseHash, mustHash(t, specChanged.Body), "spec version change")
}

func TestDigest_SignedPerPlane(t *testing.T) {
	artifactSigner, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: "xrec-test-signer"})
	if err != nil {
		t.Fatal(err)
	}
	svc := signing.NewServer(signing.WithArtifactSigner(artifactSigner))
	client := serveSigner(t, svc)
	trusted := map[string]crypto.PublicKey{artifactSigner.KeyID(): artifactSigner.Public()}

	planeA := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), sampleRules(), "plane-a", "42")
	planeB := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), sampleRules(), "plane-b", "42")

	signedA, err := digest.Sign(context.Background(), client, planeA.Body, artifactSigner.KeyID())
	if err != nil {
		t.Fatalf("sign plane A: %v", err)
	}
	if err := signedA.Verify(trusted); err != nil {
		t.Fatalf("verify plane A: %v", err)
	}
	signedB, err := digest.Sign(context.Background(), client, planeB.Body, "")
	if err != nil {
		t.Fatalf("sign plane B: %v", err)
	}
	if err := signedB.Verify(trusted); err != nil {
		t.Fatalf("verify plane B: %v", err)
	}
	if bytes.Equal(signedA.DigestHash, signedB.DigestHash) {
		t.Fatal("authority_id did not bind per-plane digest hash")
	}
	if signedA.KeyID != artifactSigner.KeyID() || signedB.KeyID != artifactSigner.KeyID() {
		t.Fatalf("unexpected key ids: %q %q", signedA.KeyID, signedB.KeyID)
	}
}

func TestDigest_OrchestratorCannotSign(t *testing.T) {
	artifactSigner, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: "xrec-test-signer"})
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]crypto.PublicKey{artifactSigner.KeyID(): artifactSigner.Public()}
	body := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), sampleRules(), "plane-a", "42").Body

	bodyBytes := mustBodyBytes(t, body)
	bodyHash := crypto.SHA256Sum(bodyBytes)
	attacker, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(attacker.Destroy)
	sig, err := attacker.SignDigest(bodyHash, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	forged := digest.SignedDigest{
		Body:         body,
		DigestHash:   bodyHash,
		KeyID:        artifactSigner.KeyID(),
		Algorithm:    attacker.Algorithm(),
		PublicKeyDER: attacker.Public().DER,
		Signature:    sig,
	}
	if err := forged.Verify(trusted); !errors.Is(err, digest.ErrUntrustedKey) {
		t.Fatalf("forged digest verification error = %v, want ErrUntrustedKey", err)
	}

	if _, err := digest.Sign(context.Background(), nil, body, artifactSigner.KeyID()); !errors.Is(err, digest.ErrInvalidDigest) {
		t.Fatalf("nil signer error = %v, want ErrInvalidDigest", err)
	}
}

// Sorted, domain-separated Merkle leaves and nodes (XREC-claim-9).
func TestTree_DomainSeparationLeafNode(t *testing.T) {
	set := sampleSet(t, "active", canon.SpecVersionV1)
	tree, err := digest.BuildTreeFromSet(set)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest.LeafHash([]byte("k"), []byte("v")), digest.NodeHash(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))) {
		t.Fatal("leaf and node domains collided")
	}
	key, err := digest.RecordKeyBytes(set.Records[0].RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := tree.InclusionProof(key)
	if !ok {
		t.Fatal("missing inclusion proof")
	}
	if !proof.VerifyInclusion(tree.Root) {
		t.Fatal("inclusion proof did not verify")
	}
	absent, err := digest.RecordKeyBytes(canon.RecordKey{TenantID: "tenant-a", RecordType: canon.RecordTypeKey, StableID: "missing-key"})
	if err != nil {
		t.Fatal(err)
	}
	absence, ok := tree.AbsenceProof(absent)
	if !ok {
		t.Fatal("target unexpectedly present")
	}
	if !absence.VerifyAbsence(tree.Root) {
		t.Fatal("absence proof did not verify")
	}
	empty, err := digest.BuildTree(nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyAbsence, ok := empty.AbsenceProof([]byte("tenant-a\x00key\x00missing"))
	if !ok || !emptyAbsence.VerifyAbsence(empty.Root) {
		t.Fatal("empty-tree absence proof did not verify")
	}
}

// Per-rule policy-posture counts (XREC-claim-11).
func TestPosture_PerRuleCounts(t *testing.T) {
	set := sampleSet(t, "revoked", canon.SpecVersionV1)
	summary, err := digest.SummarizePosture(sampleRules(), set.Records)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.PolicySetHash) != 32 {
		t.Fatalf("policy_set_hash len = %d, want 32", len(summary.PolicySetHash))
	}
	if len(summary.PerRule) != 2 {
		t.Fatalf("per_rule len = %d, want 2", len(summary.PerRule))
	}
	got := map[string]digest.RuleCount{}
	for _, count := range summary.PerRule {
		got[count.RuleID] = count
	}
	if got["active-only"].SatisfyingCount != 1 || got["active-only"].ViolatingCount != 1 {
		t.Fatalf("active counts = %+v, want 1/1", got["active-only"])
	}
	if got["non-secret-ref"].SatisfyingCount != 2 || got["non-secret-ref"].ViolatingCount != 0 {
		t.Fatalf("non-secret counts = %+v, want 2/0", got["non-secret-ref"])
	}
}

func TestDigest_NoSecretEvidence(t *testing.T) {
	body := mustBuild(t, sampleSet(t, "active", canon.SpecVersionV1), sampleRules(), "plane-a", "42").Body
	if bytes.Contains(mustBodyBytes(t, body), []byte("super-secret-password")) {
		t.Fatal("secret marker leaked into digest body")
	}
	body.Watermark.Position = "token=super-secret-password"
	if _, err := body.CanonicalBytes(); !errors.Is(err, digest.ErrSecretEvidence) {
		t.Fatalf("secret watermark error = %v, want ErrSecretEvidence", err)
	}
}

func sampleSet(t *testing.T, keyStatus, spec string) canon.Set {
	t.Helper()
	now := time.Unix(1800000000, 0).UTC()
	later := now.Add(24 * time.Hour)
	records := []canon.ObservedRecord{
		{
			TenantID:   "tenant-a",
			RecordType: canon.RecordTypeKey,
			Key:        &canon.KeyIdentity{LogicalID: "kms/prod/signing"},
			Algorithm:  "EdDSA",
			Validity:   canon.ValidityInput{NotBefore: &now, NotAfter: &later},
			Status:     keyStatus,
			Provenance: canon.Provenance{AuthorityID: "kms-prod", NativeID: "key/1"},
			Attributes: map[string]canon.Value{"purpose": canon.String("signing")},
		},
		{
			TenantID:   "tenant-a",
			RecordType: canon.RecordTypeX509Certificate,
			X509:       &canon.X509Identity{IssuerNameDER: []byte{0x30, 0x03, 0x31, 0x01, 0x61}, SerialHex: "01"},
			Algorithm:  "RSA_2048",
			Validity:   canon.ValidityInput{NotBefore: &now, NotAfter: &later},
			Status:     "active",
			Provenance: canon.Provenance{AuthorityID: "vault-prod", NativeID: "pki/cert/1"},
			Attributes: map[string]canon.Value{"san_uri": canon.URI("spiffe://example.test/ns/prod/sa/api")},
		},
	}
	set, err := canon.ReduceTenant(spec, "tenant-a", records)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func sampleRules() []digest.Rule {
	return []digest.Rule{
		{
			ID:         "active-only",
			Expression: "status == active",
			Evaluate: func(r canon.CanonicalRecord) bool {
				return r.Status == canon.StatusActive
			},
		},
		{
			ID:         "non-secret-ref",
			Expression: "record_type != secret_ref",
			Evaluate: func(r canon.CanonicalRecord) bool {
				return r.RecordType != canon.RecordTypeSecretRef
			},
		},
	}
}

func mustBuild(t *testing.T, set canon.Set, rules []digest.Rule, authority, position string) digest.BuiltDigest {
	t.Helper()
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authority,
		Rules:       rules,
		Watermark:   digest.Watermark{Position: position, ObservedAt: 1799999900},
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func mustHash(t *testing.T, body digest.Body) []byte {
	t.Helper()
	h, err := body.DigestHash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustBodyBytes(t *testing.T, body digest.Body) []byte {
	t.Helper()
	b, err := body.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertDifferentHash(t *testing.T, a, b []byte, label string) {
	t.Helper()
	if bytes.Equal(a, b) {
		t.Fatalf("%s did not change digest hash", label)
	}
}

func assertContains(t *testing.T, haystack, needle []byte) {
	t.Helper()
	if !bytes.Contains(haystack, needle) {
		t.Fatalf("%q missing from %s", needle, haystack)
	}
}

func serveSigner(t *testing.T, svc *signing.Server) *signing.Client {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	}
	dir, err := os.MkdirTemp(base, "xrec-sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, svc, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	client := waitReady(t, socket, served)
	t.Cleanup(func() {
		_ = client.Close()
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("signer serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("signer serve did not stop")
		}
	})
	return client
}

func waitReady(t *testing.T, socket string, served <-chan error) *signing.Client {
	t.Helper()
	client, err := signing.Dial(socket)
	if err != nil {
		t.Fatalf("dial signer: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		ok := client.Healthy(ctx)
		cancel()
		if ok {
			return client
		}
		select {
		case err := <-served:
			_ = client.Close()
			t.Fatalf("signer serve failed: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			_ = client.Close()
			t.Fatal("signer not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
