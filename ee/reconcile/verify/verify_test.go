// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify_test

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	xrecverify "trstctl.com/trstctl/ee/reconcile/verify"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
)

func TestWitness_OfflineVerifiableByEitherAuthority(t *testing.T) {
	fx := newOfflineFixture(t)
	for _, authorityID := range []string{"vault", "kms"} {
		result, err := xrecverify.Verify(context.Background(), xrecverify.Request{
			Evidence:           fx.Evidence,
			Digests:            fx.Digests,
			TrustedDigestKeys:  fx.DigestTrust,
			TrustedWitnessKeys: fx.WitnessTrust,
			Policy: xrecverify.Policy{
				VerifierAuthority: authorityID,
				Now:               fx.Now,
				FreshnessBound:    time.Hour,
			},
		})
		if err != nil {
			t.Fatalf("Verify for %s: %v", authorityID, err)
		}
		if result.WitnessID != fx.Evidence.Body.WitnessID || len(result.Determinations) != 1 {
			t.Fatalf("result for %s = %+v", authorityID, result)
		}
		d := result.Determinations[0]
		if d.Class != witness.ClassPresence || d.RecordKey.StableID != "b" {
			t.Fatalf("determination = %+v, want presence divergence for only b", d)
		}
		for _, disclosed := range d.DisclosedRecords {
			if disclosed.RecordKey.StableID != "b" {
				t.Fatalf("verifier disclosed non-diverging record %+v", disclosed.RecordKey)
			}
		}
	}
}

func TestVerify_MerkleProofsAgainstRoots(t *testing.T) {
	fx := newOfflineFixture(t)
	if _, err := xrecverify.Verify(context.Background(), fx.Request()); err != nil {
		t.Fatalf("Verify valid fixture: %v", err)
	}
	badInclusion := fx
	badInclusion.Evidence = cloneEvidence(fx.Evidence)
	badInclusion.Evidence.Body.Entries[0].Inclusions[0].Proof.CanonicalRecordBytes = []byte("tampered")
	if _, err := xrecverify.Verify(context.Background(), badInclusion.Request()); !errors.Is(err, xrecverify.ErrUnverified) {
		t.Fatalf("tampered inclusion err = %v, want ErrUnverified", err)
	}
	badAbsence := fx
	badAbsence.Evidence = cloneEvidence(fx.Evidence)
	badAbsence.Evidence.Body.Entries[0].Absence.TargetKeyBytes = []byte("wrong-target")
	if _, err := xrecverify.Verify(context.Background(), badAbsence.Request()); !errors.Is(err, xrecverify.ErrUnverified) {
		t.Fatalf("tampered absence err = %v, want ErrUnverified", err)
	}
}

func TestVerify_RejectsBadDigestSignature(t *testing.T) {
	fx := newOfflineFixture(t)
	bad := fx
	bad.Digests = cloneDigests(fx.Digests)
	bad.Digests[0].Signature[0] ^= 0xff
	if _, err := xrecverify.Verify(context.Background(), bad.Request()); !errors.Is(err, xrecverify.ErrUnverified) {
		t.Fatalf("bad digest signature err = %v, want ErrUnverified", err)
	}
}

func TestVerify_NoAuthorityCommunication(t *testing.T) {
	assertVerifierImportsNoEgress(t)
	fx := newOfflineFixture(t)
	result, err := xrecverify.Verify(context.Background(), fx.Request())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.AuthorityContacted {
		t.Fatalf("verifier reported authority contact: %+v", result)
	}
}

func TestVerify_PublishedConformanceVectorOffline(t *testing.T) {
	vector := readVerifyVector(t, "presence-divergence.fixture.json")
	fx := offlineFixtureFromVector(t, vector)
	req := fx.Request()
	req.Policy.VerifierAuthority = vector.Policy.VerifierAuthority
	req.Policy.RequireCountersignFrom = vector.Policy.RequireCountersignFrom
	req.Policy.Now = time.Unix(vector.Policy.Now, 0).UTC()
	req.Policy.FreshnessBound = time.Duration(vector.Policy.FreshnessBoundSeconds) * time.Second

	result, err := xrecverify.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify vector %s: %v", vector.ID, err)
	}
	if result.AuthorityContacted {
		t.Fatalf("vector %s contacted an authority: %+v", vector.ID, result)
	}
	if len(result.Determinations) != vector.Expected.DeterminationCount {
		t.Fatalf("vector %s determinations = %+v", vector.ID, result.Determinations)
	}
	got := result.Determinations[0]
	if got.Class != vector.Expected.Class || got.PresentAuthority != vector.Expected.PresentAuthority ||
		got.RecordKey.StableID != vector.Expected.StableID || got.RecordKey.RecordType != vector.Expected.RecordType {
		t.Fatalf("vector %s determination = %+v, want %+v", vector.ID, got, vector.Expected)
	}
	for _, disclosed := range got.DisclosedRecords {
		if disclosed.RecordKey.StableID != vector.Expected.StableID {
			t.Fatalf("vector %s disclosed non-diverging record %+v", vector.ID, disclosed.RecordKey)
		}
	}
}

func TestVerify_CountersignRequiredElseUnverified(t *testing.T) {
	fx := newOfflineFixture(t)
	missing := fx
	missing.Evidence = cloneEvidence(fx.Evidence)
	missing.Evidence.CounterSignatures = nil
	req := missing.Request()
	req.Policy.RequireCountersignFrom = "kms"
	if _, err := xrecverify.Verify(context.Background(), req); !errors.Is(err, xrecverify.ErrUnverified) {
		t.Fatalf("missing countersign err = %v, want ErrUnverified", err)
	}

	req = fx.Request()
	req.Policy.RequireCountersignFrom = "kms"
	if _, err := xrecverify.Verify(context.Background(), req); err != nil {
		t.Fatalf("required countersign present: %v", err)
	}
}

func TestVerify_FreshnessBoundEnforced(t *testing.T) {
	fx := newOfflineFixture(t)
	req := fx.Request()
	req.Policy.Now = time.Unix(1800000200, 0).UTC()
	req.Policy.FreshnessBound = time.Hour
	result, err := xrecverify.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("fresh digest rejected: %v", err)
	}
	if len(result.StaleDigests) != 0 {
		t.Fatalf("stale digests = %+v, want none", result.StaleDigests)
	}
}

func TestVerify_StaleWatermarkFlagged(t *testing.T) {
	fx := newOfflineFixture(t)
	req := fx.Request()
	req.Policy.Now = time.Unix(1800007201, 0).UTC()
	req.Policy.FreshnessBound = time.Hour
	result, err := xrecverify.Verify(context.Background(), req)
	if !errors.Is(err, xrecverify.ErrStaleWatermark) {
		t.Fatalf("stale err = %v, want ErrStaleWatermark", err)
	}
	if len(result.StaleDigests) != 2 || result.StaleDigests[0].AuthorityID == "" {
		t.Fatalf("stale result = %+v, want both digests flagged", result.StaleDigests)
	}
}

type offlineFixture struct {
	Evidence     witness.Evidence
	Digests      []digest.SignedDigest
	DigestTrust  map[string]crypto.PublicKey
	WitnessTrust map[string]crypto.PublicKey
	Now          time.Time
}

func (f offlineFixture) Request() xrecverify.Request {
	return xrecverify.Request{
		Evidence:           f.Evidence,
		Digests:            f.Digests,
		TrustedDigestKeys:  f.DigestTrust,
		TrustedWitnessKeys: f.WitnessTrust,
		Policy: xrecverify.Policy{
			Now:            f.Now,
			FreshnessBound: time.Hour,
		},
	}
}

type verifyVector struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	RoundID     string        `json:"round_id"`
	SpecVersion string        `json:"spec_version"`
	GeneratedAt int64         `json:"generated_at"`
	Planes      []vectorPlane `json:"planes"`
	Policy      vectorPolicy  `json:"policy"`
	Expected    vectorExpect  `json:"expected"`
}

type vectorPlane struct {
	AuthorityID         string         `json:"authority_id"`
	WatermarkPosition   string         `json:"watermark_position"`
	WatermarkObservedAt int64          `json:"watermark_observed_at"`
	Records             []vectorRecord `json:"records"`
}

type vectorRecord struct {
	StableID string `json:"stable_id"`
	Label    string `json:"label"`
}

type vectorPolicy struct {
	VerifierAuthority      string `json:"verifier_authority"`
	RequireCountersignFrom string `json:"require_countersign_from"`
	Now                    int64  `json:"now"`
	FreshnessBoundSeconds  int64  `json:"freshness_bound_seconds"`
}

type vectorExpect struct {
	DeterminationCount int    `json:"determination_count"`
	Class              string `json:"class"`
	PresentAuthority   string `json:"present_authority"`
	StableID           string `json:"stable_id"`
	RecordType         string `json:"record_type"`
}

func readVerifyVector(t *testing.T, name string) verifyVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatalf("read vector %s: %v", name, err)
	}
	var vector verifyVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("parse vector %s: %v", name, err)
	}
	if len(vector.Planes) != 2 {
		t.Fatalf("vector %s has %d planes, want 2", name, len(vector.Planes))
	}
	return vector
}

func offlineFixtureFromVector(t *testing.T, vector verifyVector) offlineFixture {
	t.Helper()
	signer, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: vector.ID})
	if err != nil {
		t.Fatalf("NewArtifactSigner: %v", err)
	}
	t.Cleanup(signer.Destroy)
	left := signedVectorPlane(t, signer, vector.TenantID, vector.Planes[0], vector.GeneratedAt)
	right := signedVectorPlane(t, signer, vector.TenantID, vector.Planes[1], vector.GeneratedAt)
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     vector.RoundID,
		TenantID:    vector.TenantID,
		SpecVersion: vector.SpecVersion,
		Left:        left.State,
		Right:       right.State,
		GeneratedAt: vector.GeneratedAt,
	})
	if err != nil {
		t.Fatalf("Build vector witness: %v", err)
	}
	original, err := witness.SignForAuthority(context.Background(), signer, body, vector.Planes[0].AuthorityID, signer.WitnessKeyID())
	if err != nil {
		t.Fatalf("Sign vector witness: %v", err)
	}
	evidence, err := witness.EvidenceFromSignedWitness(original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness vector: %v", err)
	}
	digestTrust := map[string]crypto.PublicKey{signer.KeyID(): signer.Public()}
	witnessTrust := map[string]crypto.PublicKey{signer.WitnessKeyID(): signer.WitnessPublic()}
	if vector.Policy.RequireCountersignFrom != "" {
		counter, err := witness.CounterSign(context.Background(), signer, witness.CounterSignRequest{
			Evidence:           evidence,
			Digests:            []digest.SignedDigest{left.State.Digest, right.State.Digest},
			AuthorityID:        vector.Policy.RequireCountersignFrom,
			KeyID:              signer.WitnessKeyID(),
			TrustedDigestKeys:  digestTrust,
			TrustedWitnessKeys: witnessTrust,
		})
		if err != nil {
			t.Fatalf("CounterSign vector: %v", err)
		}
		evidence.CounterSignatures = []witness.WitnessSignature{counter}
	}
	return offlineFixture{
		Evidence:     evidence,
		Digests:      []digest.SignedDigest{left.State.Digest, right.State.Digest},
		DigestTrust:  digestTrust,
		WitnessTrust: witnessTrust,
		Now:          time.Unix(vector.Policy.Now, 0).UTC(),
	}
}

func signedVectorPlane(t *testing.T, signer *digest.ArtifactSigner, tenantID string, plane vectorPlane, generatedAt int64) planeFixture {
	t.Helper()
	keys := make([]observedKey, 0, len(plane.Records))
	for _, record := range plane.Records {
		keys = append(keys, observedKey{id: record.StableID, label: record.Label})
	}
	return signedPlaneWithWatermark(t, signer, tenantID, plane.AuthorityID, keys, digest.Watermark{
		Position:   plane.WatermarkPosition,
		ObservedAt: plane.WatermarkObservedAt,
	}, generatedAt)
}

func newOfflineFixture(t *testing.T) offlineFixture {
	t.Helper()
	signer, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: "xrec-verify-test"})
	if err != nil {
		t.Fatalf("NewArtifactSigner: %v", err)
	}
	t.Cleanup(signer.Destroy)
	left := signedPlane(t, signer, "tenant-a", "vault", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "b", label: "left-only"},
		{id: "c", label: "shared-c"},
	})
	right := signedPlane(t, signer, "tenant-a", "kms", []observedKey{
		{id: "a", label: "shared-a"},
		{id: "c", label: "shared-c"},
	})
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     "round-verify-1",
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		Left:        left.State,
		Right:       right.State,
		GeneratedAt: 1800000100,
	})
	if err != nil {
		t.Fatalf("Build witness: %v", err)
	}
	original, err := witness.SignForAuthority(context.Background(), signer, body, "vault", signer.WitnessKeyID())
	if err != nil {
		t.Fatalf("Sign witness: %v", err)
	}
	evidence, err := witness.EvidenceFromSignedWitness(original)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	digestTrust := map[string]crypto.PublicKey{signer.KeyID(): signer.Public()}
	witnessTrust := map[string]crypto.PublicKey{signer.WitnessKeyID(): signer.WitnessPublic()}
	counter, err := witness.CounterSign(context.Background(), signer, witness.CounterSignRequest{
		Evidence:           evidence,
		Digests:            []digest.SignedDigest{left.State.Digest, right.State.Digest},
		AuthorityID:        "kms",
		KeyID:              signer.WitnessKeyID(),
		TrustedDigestKeys:  digestTrust,
		TrustedWitnessKeys: witnessTrust,
	})
	if err != nil {
		t.Fatalf("CounterSign: %v", err)
	}
	evidence.CounterSignatures = []witness.WitnessSignature{counter}
	return offlineFixture{
		Evidence:     evidence,
		Digests:      []digest.SignedDigest{left.State.Digest, right.State.Digest},
		DigestTrust:  digestTrust,
		WitnessTrust: witnessTrust,
		Now:          time.Unix(1800000200, 0).UTC(),
	}
}

type observedKey struct {
	id    string
	label string
}

type planeFixture struct {
	State witness.PlaneState
}

func signedPlane(t *testing.T, signer *digest.ArtifactSigner, tenantID, authorityID string, keys []observedKey) planeFixture {
	t.Helper()
	return signedPlaneWithWatermark(t, signer, tenantID, authorityID, keys, digest.Watermark{
		Position:   authorityID + "-100",
		ObservedAt: 1800000000,
	}, 1800000100)
}

func signedPlaneWithWatermark(t *testing.T, signer *digest.ArtifactSigner, tenantID, authorityID string, keys []observedKey, watermark digest.Watermark, generatedAt int64) planeFixture {
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
		Watermark:   watermark,
		GeneratedAt: generatedAt,
	})
	if err != nil {
		t.Fatalf("Build digest: %v", err)
	}
	signed, err := digest.Sign(context.Background(), signer, built.Body, signer.KeyID())
	if err != nil {
		t.Fatalf("Sign digest: %v", err)
	}
	return planeFixture{
		State: witness.PlaneState{
			AuthorityID: authorityID,
			Set:         set,
			Tree:        built.Tree,
			Digest:      signed,
		},
	}
}

func cloneEvidence(in witness.Evidence) witness.Evidence {
	out := in
	out.Body.DigestRefs = append([]witness.DigestRef(nil), in.Body.DigestRefs...)
	out.Body.Entries = append([]witness.Entry(nil), in.Body.Entries...)
	for i := range out.Body.Entries {
		entry := in.Body.Entries[i]
		out.Body.Entries[i].Inclusions = append([]witness.InclusionProofRef(nil), entry.Inclusions...)
		for j := range out.Body.Entries[i].Inclusions {
			out.Body.Entries[i].Inclusions[j].Proof.RecordKeyBytes = append([]byte(nil), entry.Inclusions[j].Proof.RecordKeyBytes...)
			out.Body.Entries[i].Inclusions[j].Proof.CanonicalRecordBytes = append([]byte(nil), entry.Inclusions[j].Proof.CanonicalRecordBytes...)
			out.Body.Entries[i].Inclusions[j].Proof.Siblings = append([]witness.ProofNode(nil), entry.Inclusions[j].Proof.Siblings...)
		}
		if entry.Absence != nil {
			abs := *entry.Absence
			abs.TargetKeyBytes = append([]byte(nil), entry.Absence.TargetKeyBytes...)
			out.Body.Entries[i].Absence = &abs
		}
		out.Body.Entries[i].DisclosedRecords = append([]witness.DisclosedRecord(nil), entry.DisclosedRecords...)
	}
	out.Signatures = append([]witness.WitnessSignature(nil), in.Signatures...)
	out.CounterSignatures = append([]witness.WitnessSignature(nil), in.CounterSignatures...)
	return out
}

func cloneDigests(in []digest.SignedDigest) []digest.SignedDigest {
	out := append([]digest.SignedDigest(nil), in...)
	for i := range out {
		out[i].DigestHash = append([]byte(nil), in[i].DigestHash...)
		out[i].PublicKeyDER = append([]byte(nil), in[i].PublicKeyDER...)
		out[i].Signature = append([]byte(nil), in[i].Signature...)
	}
	return out
}

func assertVerifierImportsNoEgress(t *testing.T) {
	t.Helper()
	banned := map[string]bool{
		"net":                                 true,
		"net/http":                            true,
		"net/rpc":                             true,
		"google.golang.org/grpc":              true,
		"trstctl.com/trstctl/internal/events": true,
		"trstctl.com/trstctl/internal/store":  true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read verifier package: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if banned[path] || bannedRoot(imp, path) {
				t.Fatalf("verifier imports egress/control-plane dependency %q in %s", path, name)
			}
		}
	}
}

func bannedRoot(_ *ast.ImportSpec, path string) bool {
	return strings.HasPrefix(path, "net/") || strings.HasPrefix(path, "google.golang.org/grpc/")
}
