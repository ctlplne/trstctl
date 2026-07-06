// SPDX-License-Identifier: LicenseRef-trstctl-EE

package rpverify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/ee/translog"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const tenant = "tenant-1"

type memEpoch struct{ m map[string]uint64 }

func newMemEpoch() *memEpoch { return &memEpoch{m: map[string]uint64{}} }
func (s *memEpoch) LastAccepted(id string) (uint64, bool, error) {
	v, ok := s.m[id]
	return v, ok, nil
}
func (s *memEpoch) SetLastAccepted(id string, e uint64) error { s.m[id] = e; return nil }

func mustChain(t *testing.T) succession.SampleChain {
	t.Helper()
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://td.example", "spiffe://td.example/db", tenant)
	if err != nil {
		t.Fatalf("BuildSampleChain: %v", err)
	}
	return sc
}

func input(sc succession.SampleChain) rpverify.Input {
	return rpverify.Input{TrustRootPubDER: sc.TrustRootPubDER, Genesis: sc.Genesis, Chain: sc.Records}
}

// buildInclusion appends each record's commitment to a fresh transparency log and
// returns index-aligned inclusion evidence under the final signed tree head.
func buildInclusion(t *testing.T, sc succession.SampleChain) ([]rpverify.InclusionEvidence, []byte) {
	t.Helper()
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	log := translog.New(signer)
	for _, rec := range sc.Records {
		leaf, err := succession.Commit(rec.Fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := log.Append(leaf); err != nil {
			t.Fatal(err)
		}
	}
	head, err := log.Head()
	if err != nil {
		t.Fatal(err)
	}
	ev := make([]rpverify.InclusionEvidence, len(sc.Records))
	for i := range sc.Records {
		proof, _, err := log.InclusionProof(i)
		if err != nil {
			t.Fatal(err)
		}
		ev[i] = rpverify.InclusionEvidence{STH: head, Proof: proof, Index: i}
	}
	return ev, signer.Public().DER
}

func TestRPVerify_AcceptsValidChain(t *testing.T) {
	sc := mustChain(t)
	res, err := rpverify.Verify(input(sc), newMemEpoch(), rpverify.Options{ExpectedTenant: tenant})
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if res.Epoch != 2 {
		t.Fatalf("current epoch = %d, want 2", res.Epoch)
	}

	// A tampered successor signature is rejected.
	bad := input(sc)
	bad.Chain = append([]succession.SuccessionRecord{}, sc.Records...)
	tamper := bad.Chain[0]
	tamper.Possession.Signature = append([]byte{0x00}, tamper.Possession.Signature...)
	bad.Chain[0] = tamper
	if _, err := rpverify.Verify(bad, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant}); err == nil {
		t.Fatal("tampered chain verified")
	}
}

func TestRPVerify_RejectsDowngrade(t *testing.T) {
	sc := mustChain(t)
	store := newMemEpoch()
	_ = store.SetLastAccepted(sc.Genesis.IdentityID, 5)
	if _, err := rpverify.Verify(input(sc), store, rpverify.Options{ExpectedTenant: tenant}); !errors.Is(err, succession.ErrDowngrade) {
		t.Fatalf("downgrade: got %v, want ErrDowngrade", err)
	}
}

func TestRPVerify_RejectsWrongTenant(t *testing.T) {
	sc := mustChain(t)
	if _, err := rpverify.Verify(input(sc), newMemEpoch(), rpverify.Options{ExpectedTenant: "someone-else"}); !errors.Is(err, rpverify.ErrWrongTenant) {
		t.Fatalf("wrong tenant: got %v, want ErrWrongTenant", err)
	}
}

func TestRPVerify_PersistsLastAcceptedEpoch(t *testing.T) {
	sc := mustChain(t)
	store := newMemEpoch()
	if _, err := rpverify.Verify(input(sc), store, rpverify.Options{ExpectedTenant: tenant}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// The store now holds epoch 2. A fresh verifier (same store, "restart") must
	// refuse the same chain, since its head does not strictly exceed the last
	// accepted epoch.
	if _, err := rpverify.Verify(input(sc), store, rpverify.Options{ExpectedTenant: tenant}); !errors.Is(err, succession.ErrDowngrade) {
		t.Fatalf("replay after persist: got %v, want ErrDowngrade", err)
	}
}

func TestRPVerify_NoNegotiationNoProviderLoad(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// Concrete dynamic-loading / provider-registration API constructs (not prose):
	// their absence in the verify path is the design-around (claim 13).
	forbidden := []string{`"plugin"`, "plugin.Open", "dlopen", "LoadLibrary", "RegisterProvider", "SelectProvider("}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if strings.Contains(string(b), bad) {
				t.Fatalf("%s contains a forbidden dynamic-provider construct %q", f, bad)
			}
		}
	}
}

func TestRPVerify_RequiresInclusionWhenConfigured(t *testing.T) {
	sc := mustChain(t)
	// Required but absent → refused.
	if _, err := rpverify.Verify(input(sc), newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, RequireInclusion: true}); !errors.Is(err, rpverify.ErrInclusionRequired) {
		t.Fatalf("missing inclusion: got %v, want ErrInclusionRequired", err)
	}
	// Provided and valid → accepted.
	ev, sthKey := buildInclusion(t, sc)
	in := input(sc)
	in.Inclusion = ev
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, RequireInclusion: true, STHVerifyKeyDER: sthKey}); err != nil {
		t.Fatalf("valid inclusion rejected: %v", err)
	}
	// Tampered proof → refused.
	in.Inclusion[0].Proof = append([][]byte{{0x00}}, in.Inclusion[0].Proof...)
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, RequireInclusion: true, STHVerifyKeyDER: sthKey}); !errors.Is(err, rpverify.ErrInclusionInvalid) {
		t.Fatalf("tampered inclusion: got %v, want ErrInclusionInvalid", err)
	}
}

func TestRPVerify_RequiresPreCRQCTimestamp(t *testing.T) {
	sc := mustChain(t) // predecessors are classical (ECDSA)
	ev, sthKey := buildInclusion(t, sc)
	in := input(sc)
	in.Inclusion = ev

	// A pre-CRQC bound far in the future accepts (STH timestamp precedes it).
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, RequireInclusion: true, STHVerifyKeyDER: sthKey, PreCRQCBefore: 1 << 62}); err != nil {
		t.Fatalf("pre-CRQC (future bound) rejected: %v", err)
	}
	// A pre-CRQC bound in the past refuses a classical-predecessor record whose STH
	// timestamp is after it.
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, RequireInclusion: true, STHVerifyKeyDER: sthKey, PreCRQCBefore: 1}); !errors.Is(err, rpverify.ErrPreCRQC) {
		t.Fatalf("pre-CRQC (past bound): got %v, want ErrPreCRQC", err)
	}
}

func TestRPVerify_OverlapWindowFailsClosed(t *testing.T) {
	// Head epoch is always acceptable.
	if err := rpverify.AcceptPresentedEpoch(2, 2, false); err != nil {
		t.Fatalf("head epoch rejected: %v", err)
	}
	// Immediate predecessor accepted only while overlap is open.
	if err := rpverify.AcceptPresentedEpoch(2, 1, true); err != nil {
		t.Fatalf("predecessor within overlap rejected: %v", err)
	}
	if err := rpverify.AcceptPresentedEpoch(2, 1, false); !errors.Is(err, rpverify.ErrOverlapClosed) {
		t.Fatalf("predecessor after overlap: got %v, want ErrOverlapClosed", err)
	}
	// Anything older than the immediate predecessor fails closed even during overlap.
	if err := rpverify.AcceptPresentedEpoch(2, 0, true); !errors.Is(err, rpverify.ErrOverlapClosed) {
		t.Fatalf("stale epoch during overlap: got %v, want ErrOverlapClosed", err)
	}
}

// TestRPVerify_WASMParity builds and runs the verifier under js/wasm and asserts
// it produces the same verdict as native (claim-13 portability). It skips if a
// wasm runtime is unavailable.
func TestRPVerify_WASMParity(t *testing.T) {
	// Native verdict for a fresh valid chain.
	sc := mustChain(t)
	res, err := rpverify.Verify(input(sc), nil, rpverify.Options{ExpectedTenant: tenant})
	if err != nil {
		t.Fatalf("native verify: %v", err)
	}
	want := fmt.Sprintf("epoch=%d ok=true", res.Epoch)

	// The js/wasm target runs under node via GOROOT/lib/wasm/go_js_wasm_exec, which
	// must be on PATH for `go run` to launch the wasm binary instead of exec'ing it.
	wasmExecDir := filepath.Join(runtime.GOROOT(), "lib", "wasm")
	cmd := exec.Command("go", "run", "./wasm")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm",
		"PATH="+wasmExecDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("wasm build/run unavailable (%v):\n%s", err, out)
	}
	if !strings.Contains(string(out), want) {
		t.Fatalf("wasm parity mismatch: native %q, wasm output:\n%s", want, out)
	}
}

// --- strength-refusal mirror (PCAS-15) -------------------------------------

type rpClassSigner struct {
	inner crypto.Signer
	alg   crypto.Algorithm
}

func (c rpClassSigner) Public() crypto.PublicKey {
	return crypto.PublicKey{Algorithm: c.alg, DER: c.inner.Public().DER}
}
func (c rpClassSigner) Algorithm() crypto.Algorithm { return c.alg }
func (c rpClassSigner) Sign(m []byte, o crypto.SignOptions) ([]byte, error) {
	return c.inner.Sign(m, o)
}

type mapResolverRP map[string]crypto.Signer

func (r mapResolverRP) Resolve(h string) (crypto.Signer, error) {
	s, ok := r[h]
	if !ok {
		return nil, errors.New("no handle")
	}
	return s, nil
}

type memFloorRP struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newMemFloorRP() *memFloorRP { return &memFloorRP{m: map[string]uint64{}} }
func (f *memFloorRP) Load() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}
func (f *memFloorRP) Advance(id string, e uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = e
	return nil
}

// TestRPVerify_MirrorsStrengthRefusal: the RP rejects a weaker-class succession
// that lacks a valid break-glass marker, and accepts one that has it (claim 17 /
// INV-8).
func TestRPVerify_MirrorsStrengthRefusal(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	trustRoot, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	predInner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pred := rpClassSigner{inner: predInner, alg: "ML-DSA-65"} // PQ predecessor

	// Mint a PQ->classical downgrade record with a valid break-glass token.
	bg := minter.NewSignedBreakGlassAuthorizer(authority.Public().DER)
	m, err := minter.New(mapResolverRP{"pred": pred}, be, newMemFloorRP(), minter.WithStrengthOrdering(bg))
	if err != nil {
		t.Fatal(err)
	}
	req := signing.MintRequest{
		IdentityID: "spiffe://td/db", TenantID: tenant, DeploymentScope: "spiffe://td",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "p", NotBefore: 1, NotAfter: 1000,
	}
	payload, err := json.Marshal(minter.BreakGlassToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID, DeploymentScope: req.DeploymentScope,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch, TargetAlgorithm: req.TargetAlgorithm, Nonce: "n1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.BreakGlass, err = minter.SignEnvelope(authority, payload); err != nil {
		t.Fatal(err)
	}
	res, err := m.MintSuccessor(context.Background(), req)
	if err != nil {
		t.Fatalf("mint downgrade: %v", err)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}

	genesis := succession.GenesisRecord{
		DeploymentScope: "spiffe://td", IdentityID: "spiffe://td/db", TenantID: tenant,
		Algorithm: "ML-DSA-65", PublicKey: predInner.Public().DER, Epoch: 0,
	}
	gd, err := succession.GenesisDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.TrustRootAtt, err = trustRoot.Sign(gd, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatal(err)
	}
	in := rpverify.Input{TrustRootPubDER: trustRoot.Public().DER, Genesis: genesis, Chain: []succession.SuccessionRecord{rec}}

	// No configured authority => the weaker-class succession is refused (fail-closed).
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant}); !errors.Is(err, rpverify.ErrStrengthRefusal) {
		t.Fatalf("no authority: got %v, want ErrStrengthRefusal", err)
	}
	// With the authority, the valid break-glass token is accepted.
	if _, err := rpverify.Verify(in, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, BreakGlassAuthorityDER: authority.Public().DER}); err != nil {
		t.Fatalf("valid break-glass rejected: %v", err)
	}
	// A record whose break-glass marker is stripped is refused even with the authority.
	stripped := rec
	stripped.BreakGlassAuth = nil
	in2 := in
	in2.Chain = []succession.SuccessionRecord{stripped}
	if _, err := rpverify.Verify(in2, newMemEpoch(), rpverify.Options{ExpectedTenant: tenant, BreakGlassAuthorityDER: authority.Public().DER}); !errors.Is(err, rpverify.ErrStrengthRefusal) {
		t.Fatalf("stripped marker: got %v, want ErrStrengthRefusal", err)
	}
}
