// SPDX-License-Identifier: LicenseRef-trstctl-EE

package minter_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/minter"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

var ctx = context.Background()

// --- fakes -----------------------------------------------------------------

type mapResolver map[string]crypto.Signer

func (r mapResolver) Resolve(h string) (crypto.Signer, error) {
	s, ok := r[h]
	if !ok {
		return nil, errors.New("no such handle")
	}
	return s, nil
}

type memFloor struct {
	mu sync.Mutex
	m  map[string]uint64
}

func newMemFloor() *memFloor { return &memFloor{m: map[string]uint64{}} }
func (f *memFloor) Load() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range f.m {
		out[k] = v
	}
	return out, nil
}
func (f *memFloor) Advance(id string, e uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = e
	return nil
}

func baseReq() signing.MintRequest {
	return signing.MintRequest{
		IdentityID: "spiffe://td.example/db", TenantID: "t1", DeploymentScope: "spiffe://td.example",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "policy:1", NotBefore: 1000, NotAfter: 100000,
	}
}

func setupWith(t *testing.T, be crypto.KeyGenerator, opts ...minter.Option) (*minter.Minter, mapResolver, *memFloor) {
	t.Helper()
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("predecessor keygen: %v", err)
	}
	res := mapResolver{"pred": pred}
	floor := newMemFloor()
	m, err := minter.New(res, be, floor, opts...)
	if err != nil {
		t.Fatalf("minter.New: %v", err)
	}
	return m, res, floor
}

func setup(t *testing.T, opts ...minter.Option) (*minter.Minter, mapResolver, *memFloor) {
	return setupWith(t, crypto.NewSoftwareBackend(), opts...)
}

// --- canonical tests -------------------------------------------------------

// TestMintSuccessor_ProducesVerifiableRecord: a mint returns a record that
// ee/succession.VerifyRecord accepts (PCAS-claims 1/25).
func TestMintSuccessor_ProducesVerifiableRecord(t *testing.T) {
	m, _, _ := setup(t)
	res, err := m.MintSuccessor(ctx, baseReq())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res.Epoch != 1 {
		t.Fatalf("epoch = %d, want 1", res.Epoch)
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("minted record does not verify: %v", err)
	}
}

// TestMint_EpochMonotonic_Refused: stale, skipped, or already-advanced epochs are
// refused; only the current floor mints (PCAS-claim-12 / INV-3).
func TestMint_EpochMonotonic_Refused(t *testing.T) {
	m, _, _ := setup(t)
	if _, err := m.MintSuccessor(ctx, baseReq()); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	// Stale (asserted 0, floor now 1).
	if _, err := m.MintSuccessor(ctx, baseReq()); !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("stale epoch: got %v, want ErrEpochNotCurrent", err)
	}
	// Skipped (asserted 2, floor 1).
	skip := baseReq()
	skip.AssertedPredecessorEpoch = 2
	if _, err := m.MintSuccessor(ctx, skip); !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("skipped epoch: got %v, want ErrEpochNotCurrent", err)
	}
	// Current (asserted 1) mints.
	cur := baseReq()
	cur.AssertedPredecessorEpoch = 1
	if _, err := m.MintSuccessor(ctx, cur); err != nil {
		t.Fatalf("current epoch: %v", err)
	}
}

// TestSigner_NoPrivateKeyCrossesBoundary: the result carries only public material;
// the record verifies with public data only (PCAS-claims 12/16 / INV-1).
func TestSigner_NoPrivateKeyCrossesBoundary(t *testing.T) {
	m, _, _ := setup(t)
	res, err := m.MintSuccessor(ctx, baseReq())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// SuccessorPublicDER is a public key: it parses (VerifyMessage gets past
	// parsing to reject a bogus signature rather than failing to parse).
	if err := crypto.VerifyMessage(res.SuccessorPublicDER, []byte("x"), []byte("bogus")); err == nil {
		t.Fatal("a bogus signature verified against the returned key")
	}
	rec, err := minter.DecodeRecord(res.EncodedRecord)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := succession.VerifyRecord(rec); err != nil {
		t.Fatalf("record does not verify from public result data: %v", err)
	}
	// The result's successor key matches the record's bound successor key.
	if string(res.SuccessorPublicDER) != string(rec.Fields.SuccessorPub) {
		t.Fatal("result successor key does not match the record")
	}
}

// TestSigner_ForgeResistance: without the signer (which holds the predecessor
// private key) a compromised control plane cannot produce a record VerifyRecord
// accepts — it can pick a successor key but cannot forge the predecessor
// attestation (PCAS-claims 1/12 / INV-1).
func TestSigner_ForgeResistance(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	// The signer's predecessor key; the control plane knows only its public DER.
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	attackerSucc, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{
		DeploymentScope: "spiffe://td", IdentityID: "spiffe://td/db", TenantID: "t1",
		PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: crypto.ECDSAP256, PredecessorPub: pred.Public().DER,
		SuccessorAlg: crypto.ECDSAP256, SuccessorPub: attackerSucc.Public().DER,
		PolicyRef: "p", HashAlg: succession.HashAlgSHA256, NotBefore: 1, NotAfter: 2,
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		t.Fatal(err)
	}
	succSig, err := attackerSucc.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	// The attacker cannot sign with the predecessor key; any forged attestation
	// fails, and even self-signing with the attacker's successor key is the wrong
	// key for the predecessor limb.
	for _, forged := range [][]byte{[]byte("forged"), succSig} {
		rec := succession.SuccessionRecord{
			Fields: fields, PredecessorAtt: forged,
			Possession: succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
		}
		if err := succession.VerifyRecord(rec); err == nil {
			t.Fatal("a control-plane-forged record verified without the signer")
		}
	}
}

// TestSigner_HighWaterSurvivesRestart: the sealed epoch floor persists across a
// signer restart (PCAS-claim-12 / INV-3).
func TestSigner_HighWaterSurvivesRestart(t *testing.T) {
	m1, res, floor := setup(t)
	if _, err := m1.MintSuccessor(ctx, baseReq()); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// "Restart": a fresh minter loading the same sealed floor store.
	m2, err := minter.New(res, crypto.NewSoftwareBackend(), floor)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, err := m2.MintSuccessor(ctx, baseReq()); !errors.Is(err, minter.ErrEpochNotCurrent) {
		t.Fatalf("restart lost the high-water: got %v, want ErrEpochNotCurrent", err)
	}
	cur := baseReq()
	cur.AssertedPredecessorEpoch = 1
	if _, err := m2.MintSuccessor(ctx, cur); err != nil {
		t.Fatalf("post-restart current-epoch mint: %v", err)
	}
}

// --- dual control (PCAS-claim-5) ------------------------------------------------

func mintToken(t *testing.T, authority crypto.Signer, req signing.MintRequest, digest []byte, nonce string) []byte {
	t.Helper()
	tok := minter.AuthorizationToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch, TargetAlgorithm: req.TargetAlgorithm,
		ParamsDigest: digest, Nonce: nonce,
	}
	payload, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	env, err := minter.SignEnvelope(authority, payload)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestMintSuccessor_RequiresDualControl: with dual control configured, a mint
// without a valid authorization is refused; with one it succeeds (PCAS-claim-5).
func TestMintSuccessor_RequiresDualControl(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	authz := minter.NewSignedTokenAuthorizer(authority.Public().DER)
	m, _, _ := setupWith(t, be, minter.WithDualControl(authz))

	if _, err := m.MintSuccessor(ctx, baseReq()); !errors.Is(err, minter.ErrAuthorizationRequired) {
		t.Fatalf("missing authorization: got %v, want ErrAuthorizationRequired", err)
	}
	req := baseReq()
	req.Authorization = mintToken(t, authority, req, minter.RequestParamsDigest(req), "nonce-1")
	if _, err := m.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("authorized mint: %v", err)
	}
}

// TestDualControl_TokenBoundSingleUse: a replayed token, or one bound to a
// different identity/tenant/epoch/algorithm/request-digest, is refused (PCAS-claim-5).
func TestDualControl_TokenBoundSingleUse(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	authz := minter.NewSignedTokenAuthorizer(authority.Public().DER)

	// Single-use: two independent minters share one authorizer. A nonce spent on
	// the first is refused on the second even with a correctly bound token.
	m1, _, _ := setupWith(t, be, minter.WithDualControl(authz))
	req := baseReq()
	req.Authorization = mintToken(t, authority, req, minter.RequestParamsDigest(req), "same-nonce")
	if _, err := m1.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("first authorized mint: %v", err)
	}
	m2, _, _ := setupWith(t, be, minter.WithDualControl(authz))
	req2 := baseReq()
	req2.Authorization = mintToken(t, authority, req2, minter.RequestParamsDigest(req2), "same-nonce")
	if _, err := m2.MintSuccessor(ctx, req2); !errors.Is(err, minter.ErrAuthorizationInvalid) {
		t.Fatalf("replayed nonce: got %v, want ErrAuthorizationInvalid", err)
	}

	// Bound to a different target algorithm than the request → refused.
	m3, _, _ := setupWith(t, be, minter.WithDualControl(authz))
	req3 := baseReq()
	wrong := req3
	wrong.TargetAlgorithm = crypto.RSA2048 // token binds a different algorithm
	req3.Authorization = mintToken(t, authority, wrong, minter.RequestParamsDigest(wrong), "nonce-x")
	if _, err := m3.MintSuccessor(ctx, req3); !errors.Is(err, minter.ErrAuthorizationInvalid) {
		t.Fatalf("mis-bound token: got %v, want ErrAuthorizationInvalid", err)
	}
}

// --- policy (PCAS-claim-23) -----------------------------------------------------

func mintPolicy(t *testing.T, authority crypto.Signer, identity string, target crypto.Algorithm) []byte {
	t.Helper()
	payload, err := json.Marshal(minter.PolicyDecision{IdentityID: identity, TargetAlgorithm: target})
	if err != nil {
		t.Fatal(err)
	}
	env, err := minter.SignEnvelope(authority, payload)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestMint_RequiresSignedPolicyDecision + TestMint_RejectsUnsignedPolicyRef.
func TestMint_RequiresSignedPolicyDecision(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := setupWith(t, be, minter.WithPolicy(minter.SignedPolicyAuthorizer{AuthorityPubDER: authority.Public().DER}))

	if _, err := m.MintSuccessor(ctx, baseReq()); !errors.Is(err, minter.ErrPolicyRequired) {
		t.Fatalf("missing policy: got %v, want ErrPolicyRequired", err)
	}
	req := baseReq()
	req.PolicyDecision = mintPolicy(t, authority, req.IdentityID, req.TargetAlgorithm)
	if _, err := m.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("valid policy mint: %v", err)
	}
}

func TestMint_RejectsUnsignedPolicyRef(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	other, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	m, _, _ := setupWith(t, be, minter.WithPolicy(minter.SignedPolicyAuthorizer{AuthorityPubDER: authority.Public().DER}))

	// A decision signed by the WRONG authority is refused.
	req := baseReq()
	req.PolicyDecision = mintPolicy(t, other, req.IdentityID, req.TargetAlgorithm)
	if _, err := m.MintSuccessor(ctx, req); !errors.Is(err, minter.ErrPolicyInvalid) {
		t.Fatalf("wrong-authority policy: got %v, want ErrPolicyInvalid", err)
	}
}

// orderRec / order wrappers make the policy-before-keygen ordering observable.
type orderRec struct {
	mu  sync.Mutex
	log []string
}

func (o *orderRec) note(s string) { o.mu.Lock(); o.log = append(o.log, s); o.mu.Unlock() }

type orderPolicy struct {
	inner minter.PolicyVerifier
	rec   *orderRec
}

func (p orderPolicy) Verify(d []byte, req signing.MintRequest) error {
	p.rec.note("policy")
	return p.inner.Verify(d, req)
}

type orderKeygen struct {
	inner crypto.KeyGenerator
	rec   *orderRec
}

func (k orderKeygen) GenerateKey(a crypto.Algorithm) (crypto.Signer, error) {
	k.rec.note("keygen")
	return k.inner.GenerateKey(a)
}

// TestPolicy_VerifiedBeforeKeygen: policy verification provably precedes successor
// key generation (PCAS-claim-23).
func TestPolicy_VerifiedBeforeKeygen(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	rec := &orderRec{}
	pred, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	m, err := minter.New(
		mapResolver{"pred": pred},
		orderKeygen{inner: be, rec: rec},
		newMemFloor(),
		minter.WithPolicy(orderPolicy{inner: minter.SignedPolicyAuthorizer{AuthorityPubDER: authority.Public().DER}, rec: rec}),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := baseReq()
	req.PolicyDecision = mintPolicy(t, authority, req.IdentityID, req.TargetAlgorithm)
	if _, err := m.MintSuccessor(ctx, req); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(rec.log) < 2 || rec.log[0] != "policy" || rec.log[1] != "keygen" {
		t.Fatalf("call order = %v, want [policy keygen]", rec.log)
	}
}
