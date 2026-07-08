// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func TestWitness_MinimalDisclosure(t *testing.T) {
	left := mustPlane(t, "tenant-a", "vault", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "b", label: "left-only"},
		{id: "c", label: "shared-c"},
	})
	right := mustPlane(t, "tenant-a", "kms", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "c", label: "shared-c"},
	})
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     "round-1",
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		Left:        left.State,
		Right:       right.State,
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !body.VerifyWitnessID() {
		t.Fatalf("witness_id %q does not match content hash", body.WitnessID)
	}
	if len(body.Entries) != 1 || body.Entries[0].Class != witness.ClassPresence {
		t.Fatalf("entries = %+v, want one presence divergence", body.Entries)
	}
	entry := body.Entries[0]
	if len(entry.DisclosedRecords) != 1 || !bytes.Equal(entry.DisclosedRecords[0].CanonicalRecordBytes, left.CanonicalByID["b"]) {
		t.Fatalf("disclosed records = %+v, want only left-only record", entry.DisclosedRecords)
	}
	raw := mustWitnessBytes(t, body)
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(left.CanonicalByID["b"]))) {
		t.Fatal("witness omitted the only diverging canonical record")
	}
	for _, nonDivergingID := range []string{"a", "c"} {
		leftRaw := left.CanonicalByID[nonDivergingID]
		rightRaw := right.CanonicalByID[nonDivergingID]
		leftEncoded := []byte(base64.StdEncoding.EncodeToString(leftRaw))
		rightEncoded := []byte(base64.StdEncoding.EncodeToString(rightRaw))
		if bytes.Contains(raw, leftRaw) || bytes.Contains(raw, rightRaw) || bytes.Contains(raw, leftEncoded) || bytes.Contains(raw, rightEncoded) {
			t.Fatalf("witness leaked non-diverging record %q", nonDivergingID)
		}
	}
	if entry.Absence == nil || entry.Absence.Lower == nil || entry.Absence.Upper == nil {
		t.Fatalf("presence absence proof did not carry both bracketing record keys: %+v", entry.Absence)
	}

	artifactSigner, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: "xrec-test-signer"})
	if err != nil {
		t.Fatal(err)
	}
	svc := signing.NewServer(signing.WithArtifactSigner(artifactSigner))
	client := serveSigner(t, svc)
	signed, err := witness.Sign(context.Background(), client, body, "")
	if err != nil {
		t.Fatalf("Sign witness: %v", err)
	}
	if signed.KeyID != artifactSigner.WitnessKeyID() || len(signed.Signature) == 0 {
		t.Fatalf("witness signature = %+v, want signer-side witness key", signed)
	}
	if bytes.Equal(signed.Signature, body.WitnessHash()) {
		t.Fatal("witness signature is just a control-plane hash, not a signer-side signature")
	}
}

func TestWitness_AbsenceProofBracketing(t *testing.T) {
	left := mustPlane(t, "tenant-a", "vault", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "b", label: "left-only"},
		{id: "c", label: "shared-c"},
	})
	right := mustPlane(t, "tenant-a", "kms", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "c", label: "shared-c"},
	})
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     "round-1",
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		Left:        left.State,
		Right:       right.State,
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	entry := body.Entries[0]
	inc := mustInclusion(t, entry, "vault")
	if !inc.Verify(left.State.Digest.Body.MerkleRoot) {
		t.Fatal("containing-tree inclusion proof did not verify")
	}
	if entry.Absence == nil || !entry.Absence.Verify(right.State.Digest.Body.MerkleRoot) {
		t.Fatal("bracketing absence proof did not verify")
	}
	lowerKey, err := digest.RecordKeyBytes(right.RecordByID["a"].RecordKey)
	if err != nil {
		t.Fatalf("lower key: %v", err)
	}
	upperKey, err := digest.RecordKeyBytes(right.RecordByID["c"].RecordKey)
	if err != nil {
		t.Fatalf("upper key: %v", err)
	}
	if !bytes.Equal(entry.Absence.Lower.RecordKeyBytes, lowerKey) || !bytes.Equal(entry.Absence.Upper.RecordKeyBytes, upperKey) {
		t.Fatalf("absence proof brackets = %q/%q, want adjacent a/c", entry.Absence.Lower.RecordKeyBytes, entry.Absence.Upper.RecordKeyBytes)
	}
	target := entry.Absence.TargetKeyBytes
	if bytes.Compare(entry.Absence.Lower.RecordKeyBytes, target) >= 0 {
		t.Fatalf("lower bracket %q is not below target %q", entry.Absence.Lower.RecordKeyBytes, target)
	}
	if bytes.Compare(target, entry.Absence.Upper.RecordKeyBytes) >= 0 {
		t.Fatalf("upper bracket %q is not above target %q", entry.Absence.Upper.RecordKeyBytes, target)
	}
	if len(entry.Absence.Lower.LeafHash) != 32 || len(entry.Absence.Upper.LeafHash) != 32 {
		t.Fatal("absence proof must carry bracketing leaf hashes, not bracketing record bodies")
	}
}

func TestWitness_ClassifiesAllFourClasses(t *testing.T) {
	left := mustPlane(t, "tenant-a", "vault", []observedKey{
		{id: "a", label: "policy-target"},
		{id: "b", label: "left-only"},
		{id: "c", label: "left-value"},
	})
	right := mustPlane(t, "tenant-a", "kms", []observedKey{
		{id: "a", label: "policy-target"},
		{id: "c", label: "right-value"},
	})
	policyKey := left.RecordByID["a"].RecordKey
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     "round-1",
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		Left:        left.State,
		Right:       right.State,
		PolicyViolations: []witness.PolicyViolation{{
			AuthorityID:   "vault",
			RecordKey:     policyKey,
			RuleID:        "active-only",
			PolicySetHash: left.State.Digest.Body.PostureSummary.PolicySetHash,
		}},
		Staleness: []witness.Staleness{{
			AuthorityID: "kms",
			Reason:      "watermark_stalled",
			Watermark:   left.State.Digest.Body.Watermark,
			LivenessSec: 3600,
		}},
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	classes := map[string]int{}
	for _, entry := range body.Entries {
		classes[entry.Class]++
	}
	for _, class := range []string{witness.ClassPresence, witness.ClassAttributeConflict, witness.ClassPolicyViolation, witness.ClassStaleness} {
		if classes[class] == 0 {
			t.Fatalf("class %s absent from entries %+v", class, body.Entries)
		}
	}
}

type observedKey struct {
	id    string
	label string
}

type planeFixture struct {
	State         witness.PlaneState
	RecordByID    map[string]canon.CanonicalRecord
	CanonicalByID map[string][]byte
}

func mustPlane(t *testing.T, tenantID, authorityID string, keys []observedKey) planeFixture {
	t.Helper()
	observed := make([]canon.ObservedRecord, 0, len(keys))
	for _, key := range keys {
		observed = append(observed, canon.ObservedRecord{
			TenantID:   tenantID,
			RecordType: canon.RecordTypeKey,
			StableID:   key.id,
			Key:        &canon.KeyIdentity{LogicalID: key.id},
			Algorithm:  "ed25519",
			Status:     canon.StatusActive,
			Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: key.id},
			Attributes: map[string]canon.Value{"label": canon.String(key.label)},
		})
	}
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, observed)
	if err != nil {
		t.Fatalf("ReduceTenant: %v", err)
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authorityID,
		Rules: []digest.Rule{{
			ID:         "active-only",
			Expression: "status == active",
			Evaluate: func(r canon.CanonicalRecord) bool {
				return r.Status == canon.StatusActive
			},
		}},
		Watermark:   digest.Watermark{Position: authorityID + "-42", ObservedAt: 1799999900},
		GeneratedAt: 1800000000,
	})
	if err != nil {
		t.Fatalf("Build digest: %v", err)
	}
	hash, err := built.Body.DigestHash()
	if err != nil {
		t.Fatalf("DigestHash: %v", err)
	}
	byID := map[string]canon.CanonicalRecord{}
	bytesByID := map[string][]byte{}
	for _, rec := range set.Records {
		byID[rec.RecordKey.StableID] = rec
		b, err := rec.CanonicalBytes()
		if err != nil {
			t.Fatalf("CanonicalBytes: %v", err)
		}
		bytesByID[rec.RecordKey.StableID] = b
	}
	return planeFixture{
		State: witness.PlaneState{
			AuthorityID: authorityID,
			Set:         set,
			Tree:        built.Tree,
			Digest: digest.SignedDigest{
				Body:         built.Body,
				DigestHash:   hash,
				KeyID:        "digest-key-" + authorityID,
				Algorithm:    crypto.ECDSAP256,
				PublicKeyDER: []byte("digest-public-" + authorityID),
				Signature:    []byte("digest-signature-" + authorityID),
			},
		},
		RecordByID:    byID,
		CanonicalByID: bytesByID,
	}
}

func mustWitnessBytes(t *testing.T, body witness.Body) []byte {
	t.Helper()
	b, err := body.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	return b
}

func mustInclusion(t *testing.T, entry witness.Entry, authorityID string) witness.InclusionProof {
	t.Helper()
	for _, proof := range entry.Inclusions {
		if proof.AuthorityID == authorityID {
			return proof.Proof
		}
	}
	t.Fatalf("missing inclusion proof for %s in %+v", authorityID, entry)
	return witness.InclusionProof{}
}

func serveSigner(t *testing.T, svc *signing.Server) *signing.Client {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	}
	dir, err := os.MkdirTemp(base, "xrec-witness-sgn")
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
