// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	xrecverify "trstctl.com/trstctl/ee/reconcile/verify"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
)

func TestConformance_PublishedVectors(t *testing.T) {
	for _, vector := range readPublishedVectors(t) {
		t.Run(vector.ID, func(t *testing.T) {
			fx := fixtureFromVector(t, vector)
			result, err := xrecverify.Verify(context.Background(), fx.request(vector))
			if err != nil {
				t.Fatalf("Verify valid vector: %v", err)
			}
			assertVectorResult(t, vector, result)

			tampered := fx
			tampered.Digests = cloneSignedDigests(fx.Digests)
			tampered.Digests[0].Signature[0] ^= 0xff
			if _, err := xrecverify.Verify(context.Background(), tampered.request(vector)); !errors.Is(err, xrecverify.ErrUnverified) {
				t.Fatalf("tampered vector err = %v, want ErrUnverified", err)
			}
		})
	}
}

func TestDifferential_GeneratorVerifierAgree(t *testing.T) {
	for _, vector := range readPublishedVectors(t) {
		t.Run(vector.ID, func(t *testing.T) {
			fx := fixtureFromVector(t, vector)
			if err := witness.VerifyOffline(witness.OfflineVerifyRequest{
				Evidence:               fx.Evidence,
				Digests:                fx.Digests,
				TrustedDigestKeys:      fx.DigestTrust,
				TrustedWitnessKeys:     fx.WitnessTrust,
				VerifierAuthority:      vector.Policy.VerifierAuthority,
				RequireCountersignFrom: vector.Policy.RequireCountersignFrom,
			}); err != nil {
				t.Fatalf("generator verify valid vector: %v", err)
			}
			if _, err := xrecverify.Verify(context.Background(), fx.request(vector)); err != nil {
				t.Fatalf("independent verifier valid vector: %v", err)
			}

			tampered := fx
			tampered.Evidence = cloneEvidence(fx.Evidence)
			tampered.Evidence.Body.Entries[0].Inclusions[0].Proof.CanonicalRecordBytes = []byte("tampered")
			genErr := witness.VerifyOffline(witness.OfflineVerifyRequest{
				Evidence:           tampered.Evidence,
				Digests:            tampered.Digests,
				TrustedDigestKeys:  tampered.DigestTrust,
				TrustedWitnessKeys: tampered.WitnessTrust,
			})
			_, verifierErr := xrecverify.Verify(context.Background(), tampered.request(vector))
			if genErr == nil || !errors.Is(verifierErr, xrecverify.ErrUnverified) {
				t.Fatalf("tampered agreement genErr=%v verifierErr=%v, want both reject", genErr, verifierErr)
			}
		})
	}
}

func TestFuzz_DigestWitnessDecode(t *testing.T) {
	for _, vector := range readPublishedVectors(t) {
		fx := fixtureFromVector(t, vector)
		rawEvidence, err := json.Marshal(fx.Evidence)
		if err != nil {
			t.Fatalf("marshal evidence: %v", err)
		}
		rawDigests, err := json.Marshal(fx.Digests)
		if err != nil {
			t.Fatalf("marshal digests: %v", err)
		}
		var evidence witness.Evidence
		if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
			t.Fatalf("decode evidence: %v", err)
		}
		var digests []digest.SignedDigest
		if err := json.Unmarshal(rawDigests, &digests); err != nil {
			t.Fatalf("decode digests: %v", err)
		}
		req := fx.request(vector)
		req.Evidence = evidence
		req.Digests = digests
		if _, err := xrecverify.Verify(context.Background(), req); err != nil {
			t.Fatalf("verify decoded corpus: %v", err)
		}
	}
}

func FuzzDigestWitnessDecode(f *testing.F) {
	for _, path := range vectorPaths(f) {
		raw, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("read seed %s: %v", path, err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var vector publishedVector
		if err := json.Unmarshal(raw, &vector); err == nil && vector.ID != "" {
			_, _ = decodeVector(vector)
		}
		var evidence witness.Evidence
		if err := json.Unmarshal(raw, &evidence); err == nil {
			_, _ = evidence.CanonicalBytes()
		}
		var signed digest.SignedDigest
		if err := json.Unmarshal(raw, &signed); err == nil {
			_, _ = signed.Body.CanonicalBytes()
		}
	})
}

func TestEdition_CoreBuildLinksNoXREC(t *testing.T) {
	root := repoRoot(t)
	build := exec.Command("go", "build", "-tags", "trstctl_core", "./cmd/trstctl")
	build.Dir = root
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("core build: %v\n%s", err, out)
	}
	list := exec.Command("go", "list", "-tags", "trstctl_core", "-deps", "./cmd/trstctl")
	list.Dir = root
	list.Env = os.Environ()
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list core deps: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "trstctl.com/trstctl/ee/reconcile") {
			t.Fatalf("core build links XREC package %s", line)
		}
	}
}

func TestEdition_AllXRECPackagesAreEE(t *testing.T) {
	root := repoRoot(t)
	mplSPDX := []byte("SPDX-License-Identifier: " + "MPL-2.0")
	err := filepath.WalkDir(filepath.Join(root, "ee", "reconcile"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(raw, []byte("SPDX-License-Identifier: LicenseRef-trstctl-EE")) {
			return fmt.Errorf("%s missing LicenseRef-trstctl-EE SPDX", relPath(root, path))
		}
		if bytes.Contains(raw, mplSPDX) {
			return fmt.Errorf("%s carries MPL SPDX inside XREC", relPath(root, path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"cmd/trstctl/ee_attach.go":        true,
		"cmd/trstctl-signer/ee_attach.go": true,
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		rel := relPath(root, path)
		if strings.HasPrefix(rel, "ee/reconcile/") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte("trstctl.com/trstctl/ee/reconcile")) && !allowed[rel] {
			return fmt.Errorf("%s imports XREC outside the tagged attach seam", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestZeroRemoval_CoreVisibilityIntact(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range []string{
		"internal/discovery",
		"internal/connector",
		"internal/secretsync",
		"internal/spireupstream",
		"internal/agent/drift",
		"web/src/pages",
	} {
		if info, err := os.Stat(filepath.Join(root, dir)); err != nil || !info.IsDir() {
			t.Fatalf("zero-removal free surface %s missing or not a directory", dir)
		}
	}
	api := readText(t, filepath.Join(root, "internal", "api", "api.go"))
	for _, route := range []string{
		"/api/v1/discovery/sources",
		"/api/v1/discovery/runs",
		"/api/v1/discovery/findings",
		"/api/v1/discovery/monitoring",
		"/api/v1/discovery/drift-remediation",
		"/api/v1/connectors/catalog",
		"/api/v1/connectors/targets",
		"/api/v1/secrets/cloud-secret-managers",
	} {
		if !strings.Contains(api, route) {
			t.Fatalf("zero-removal free route %s missing from core API", route)
		}
	}
}

type conformanceFixture struct {
	Evidence     witness.Evidence
	Digests      []digest.SignedDigest
	DigestTrust  map[string]crypto.PublicKey
	WitnessTrust map[string]crypto.PublicKey
}

func (f conformanceFixture) request(vector publishedVector) xrecverify.Request {
	return xrecverify.Request{
		Evidence:           f.Evidence,
		Digests:            f.Digests,
		TrustedDigestKeys:  f.DigestTrust,
		TrustedWitnessKeys: f.WitnessTrust,
		Policy: xrecverify.Policy{
			VerifierAuthority:      vector.Policy.VerifierAuthority,
			RequireCountersignFrom: vector.Policy.RequireCountersignFrom,
			Now:                    time.Unix(vector.Policy.Now, 0).UTC(),
			FreshnessBound:         time.Duration(vector.Policy.FreshnessBoundSeconds) * time.Second,
		},
	}
}

type publishedVector struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	RoundID     string         `json:"round_id"`
	SpecVersion string         `json:"spec_version"`
	GeneratedAt int64          `json:"generated_at"`
	Planes      []vectorPlane  `json:"planes"`
	Policy      vectorPolicy   `json:"policy"`
	Expected    vectorExpected `json:"expected"`
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

type vectorExpected struct {
	DeterminationCount int    `json:"determination_count"`
	Class              string `json:"class"`
	PresentAuthority   string `json:"present_authority"`
	StableID           string `json:"stable_id"`
	RecordType         string `json:"record_type"`
}

type vectorPlaneState struct {
	AuthorityID string
	Set         canon.Set
	Tree        *digest.Tree
	Signed      digest.SignedDigest
	DigestKey   *crypto.LockedSigner
	WitnessKey  *crypto.LockedSigner
}

func readPublishedVectors(t testing.TB) []publishedVector {
	t.Helper()
	paths := vectorPaths(t)
	out := make([]publishedVector, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read vector %s: %v", path, err)
		}
		var vector publishedVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("decode vector %s: %v", path, err)
		}
		out = append(out, vector)
	}
	return out
}

func vectorPaths(t testing.TB) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(repoRoot(t), "ee", "reconcile", "conformance", "testdata", "vectors", "*.fixture.json"))
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no published XREC conformance vectors found")
	}
	return matches
}

func fixtureFromVector(t testing.TB, vector publishedVector) conformanceFixture {
	t.Helper()
	fx, err := decodeVector(vector)
	if err != nil {
		t.Fatalf("decode vector %s: %v", vector.ID, err)
	}
	return fx
}

func decodeVector(vector publishedVector) (conformanceFixture, error) {
	if len(vector.Planes) < 2 {
		return conformanceFixture{}, fmt.Errorf("vector %s has fewer than two planes", vector.ID)
	}
	planes := make([]vectorPlaneState, 0, len(vector.Planes))
	for _, plane := range vector.Planes {
		state, err := vectorPlaneFixture(vector, plane)
		if err != nil {
			return conformanceFixture{}, err
		}
		defer state.DigestKey.Destroy()
		defer state.WitnessKey.Destroy()
		planes = append(planes, state)
	}
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     vector.RoundID,
		TenantID:    vector.TenantID,
		SpecVersion: vector.SpecVersion,
		Left:        vectorWitnessPlane(planes[0]),
		Right:       vectorWitnessPlane(planes[1]),
		GeneratedAt: vector.GeneratedAt,
	})
	if err != nil {
		return conformanceFixture{}, err
	}
	primary, err := signWitness(body, planes[0].WitnessKey, planes[0].AuthorityID, planes[0].AuthorityID+"-witness-key", vector.GeneratedAt)
	if err != nil {
		return conformanceFixture{}, err
	}
	counter, err := signWitness(body, planes[1].WitnessKey, planes[1].AuthorityID, planes[1].AuthorityID+"-witness-key", vector.GeneratedAt)
	if err != nil {
		return conformanceFixture{}, err
	}
	digests := make([]digest.SignedDigest, 0, len(planes))
	digestTrust := map[string]crypto.PublicKey{}
	witnessTrust := map[string]crypto.PublicKey{}
	for _, plane := range planes {
		digests = append(digests, plane.Signed)
		digestTrust[plane.Signed.KeyID] = crypto.PublicKey{Algorithm: plane.Signed.Algorithm, DER: append([]byte(nil), plane.Signed.PublicKeyDER...)}
		witnessTrust[plane.AuthorityID+"-witness-key"] = plane.WitnessKey.Public()
	}
	return conformanceFixture{
		Evidence: witness.Evidence{
			Body:              body,
			Signatures:        []witness.WitnessSignature{primary},
			CounterSignatures: []witness.WitnessSignature{counter},
		},
		Digests:      digests,
		DigestTrust:  digestTrust,
		WitnessTrust: witnessTrust,
	}, nil
}

func vectorPlaneFixture(vector publishedVector, plane vectorPlane) (vectorPlaneState, error) {
	records := make([]canon.ObservedRecord, 0, len(plane.Records))
	for _, rec := range plane.Records {
		records = append(records, canon.ObservedRecord{
			TenantID:   vector.TenantID,
			RecordType: canon.RecordTypeKey,
			StableID:   rec.StableID,
			Key:        &canon.KeyIdentity{LogicalID: rec.StableID},
			Algorithm:  "ed25519",
			Status:     canon.StatusActive,
			Provenance: canon.Provenance{AuthorityID: plane.AuthorityID, NativeID: rec.StableID},
			Attributes: map[string]canon.Value{"label": canon.String(rec.Label)},
		})
	}
	set, err := canon.ReduceTenant(vector.SpecVersion, vector.TenantID, records)
	if err != nil {
		return vectorPlaneState{}, err
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: plane.AuthorityID,
		Watermark: digest.Watermark{
			Position:   plane.WatermarkPosition,
			ObservedAt: plane.WatermarkObservedAt,
		},
		GeneratedAt: vector.GeneratedAt,
	})
	if err != nil {
		return vectorPlaneState{}, err
	}
	digestKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return vectorPlaneState{}, err
	}
	witnessKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		digestKey.Destroy()
		return vectorPlaneState{}, err
	}
	signed, err := signDigest(built.Body, digestKey, plane.AuthorityID+"-digest-key")
	if err != nil {
		digestKey.Destroy()
		witnessKey.Destroy()
		return vectorPlaneState{}, err
	}
	return vectorPlaneState{AuthorityID: plane.AuthorityID, Set: set, Tree: built.Tree, Signed: signed, DigestKey: digestKey, WitnessKey: witnessKey}, nil
}

func signDigest(body digest.Body, key *crypto.LockedSigner, keyID string) (digest.SignedDigest, error) {
	payload, err := body.CanonicalBytes()
	if err != nil {
		return digest.SignedDigest{}, err
	}
	hash := crypto.SHA256Sum(payload)
	sig, err := key.SignDigest(hash, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return digest.SignedDigest{}, err
	}
	pub := key.Public()
	return digest.SignedDigest{
		Body:         body,
		DigestHash:   hash,
		KeyID:        keyID,
		Algorithm:    pub.Algorithm,
		PublicKeyDER: append([]byte(nil), pub.DER...),
		Signature:    append([]byte(nil), sig...),
	}, nil
}

func signWitness(body witness.Body, key *crypto.LockedSigner, authorityID, keyID string, signedAt int64) (witness.WitnessSignature, error) {
	payload, err := body.CanonicalBytes()
	if err != nil {
		return witness.WitnessSignature{}, err
	}
	hash := crypto.SHA256Sum(payload)
	sig, err := key.SignDigest(hash, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return witness.WitnessSignature{}, err
	}
	pub := key.Public()
	return witness.WitnessSignature{
		WitnessID:    body.WitnessID,
		AuthorityID:  authorityID,
		ContentHash:  hash,
		KeyID:        keyID,
		Algorithm:    pub.Algorithm,
		PublicKeyDER: append([]byte(nil), pub.DER...),
		Signature:    append([]byte(nil), sig...),
		SignedAt:     signedAt,
	}, nil
}

func vectorWitnessPlane(p vectorPlaneState) witness.PlaneState {
	return witness.PlaneState{AuthorityID: p.AuthorityID, Set: p.Set, Tree: p.Tree, Digest: p.Signed}
}

func assertVectorResult(t *testing.T, vector publishedVector, result xrecverify.Result) {
	t.Helper()
	if result.AuthorityContacted {
		t.Fatalf("vector %s contacted an authority", vector.ID)
	}
	if len(result.Determinations) != vector.Expected.DeterminationCount {
		t.Fatalf("vector %s determinations = %+v", vector.ID, result.Determinations)
	}
	got := result.Determinations[0]
	if got.Class != vector.Expected.Class || got.PresentAuthority != vector.Expected.PresentAuthority ||
		got.RecordKey.StableID != vector.Expected.StableID || got.RecordKey.RecordType != vector.Expected.RecordType {
		t.Fatalf("vector %s determination = %+v, want %+v", vector.ID, got, vector.Expected)
	}
}

func cloneSignedDigests(in []digest.SignedDigest) []digest.SignedDigest {
	out := make([]digest.SignedDigest, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].DigestHash = append([]byte(nil), in[i].DigestHash...)
		out[i].PublicKeyDER = append([]byte(nil), in[i].PublicKeyDER...)
		out[i].Signature = append([]byte(nil), in[i].Signature...)
		out[i].Body.MerkleRoot = append([]byte(nil), in[i].Body.MerkleRoot...)
		out[i].Body.PostureSummary.PolicySetHash = append([]byte(nil), in[i].Body.PostureSummary.PolicySetHash...)
	}
	return out
}

func cloneEvidence(in witness.Evidence) witness.Evidence {
	raw, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out witness.Evidence
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func repoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func readText(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
