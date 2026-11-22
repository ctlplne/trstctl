// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package delegation_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agentid/agentstack"
	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// wire_integration_test.go is the AGID-INT-WIRE canonical integration test
// (TestAGID_Wire_VerifyChainInRealSignerBeforeKeygen). It proves the last mile the
// AGID-04a/04b seam was built for: a chain-bound issuance request that reaches the REAL
// signing.Server over its REAL gRPC transport is VERIFIED INSIDE THE SIGNER (the attached
// delegation.Gate) BEFORE any key op, and, on approval, MINTS a credential inside the
// boundary (the attached delegation.IssuanceKeyOp), returning only public material; a
// widened chain is REFUSED with a signed refusal and ZERO key ops.
//
// It stands up the signer exactly as cmd/trstctl-signer does — signing.NewServer with
// WithIssuanceGate(delegation.NewSignerGate(...)) + WithIssuanceKeyOp(...) — serves it over
// a real UDS listener (ServeServerWithOptions), and drives it with the production
// signing.Client over the gRPC GatedIssue RPC. The client is the same one internal/server
// wires in as the control-plane IssuanceGate (s.issuanceGate()), so this exercises the whole
// wire path: Client.GatedIssue -> gRPC -> Server.GatedIssue -> gate verify-before-keygen ->
// keyOp mint -> only public material returned.
//
// NOTE (INT-WIRE scope): this binds an in-process signing.Server over a real gRPC UDS
// listener. The remaining INT-WIRE hardening is the real cmd/trstctl-signer SUBPROCESS
// boundary e2e (StartChild) and restart-durability; the mint path and the custody/transport
// contract are identical, so this increment proves the mint-over-transport property.

// countingKeyFactory wraps the default core key factory and counts every key generation the
// signer performs, so the test can assert ZERO key ops on a refusal (INV-A1). It generates
// real locked keys so the minted credential is real and offline-verifiable.
type countingKeyFactory struct {
	inner signing.KeyFactory
	gens  int
}

func newCountingKeyFactory() *countingKeyFactory {
	return &countingKeyFactory{inner: signing.NewDefaultKeyFactory()}
}

func (f *countingKeyFactory) GenerateSigningKey(alg crypto.Algorithm) (signing.Key, error) {
	f.gens++
	return f.inner.GenerateSigningKey(alg)
}

func (f *countingKeyFactory) GenerateSigningKeyFromProto(a signerpb.Algorithm) (signing.Key, error) {
	f.gens++
	return f.inner.GenerateSigningKeyFromProto(a)
}

func (f *countingKeyFactory) SigningKeyFromSealedBytes(a signerpb.Algorithm, priv []byte) (signing.Key, error) {
	return f.inner.SigningKeyFromSealedBytes(a, priv)
}

func (f *countingKeyFactory) ProtoFromAlgorithm(alg crypto.Algorithm) signerpb.Algorithm {
	return f.inner.ProtoFromAlgorithm(alg)
}

// wireFakeAttestor is an in-memory AttestationVerifier for the wire test: it accepts ONLY
// the exact (method,payload) it was seeded with and yields a software-class attestation. A
// forged/absent payload fails closed.
type wireFakeAttestor struct {
	method  string
	payload []byte
}

func (a wireFakeAttestor) VerifyEvidence(method string, payload []byte) (delegation.VerifiedAttestation, error) {
	if method != a.method || string(payload) != string(a.payload) {
		return delegation.VerifiedAttestation{}, delegation.ErrAttestationInvalid
	}
	return delegation.VerifiedAttestation{Method: method, Subject: "agent-subject"}, nil
}

// TestAGID_Wire_VerifyChainInRealSignerBeforeKeygen is the AGID-INT-WIRE canonical test.
func TestAGID_Wire_VerifyChainInRealSignerBeforeKeygen(t *testing.T) {
	const (
		tenantID        = "tnt-wire"
		designatedClass = "agent-worker"
		attMethod       = "software"
		rootKeyID       = "root-anchor-key"
	)
	// --- Build the signer-held root anchor + a valid narrowing chain (root -> narrower). ---
	be := crypto.NewSoftwareBackend()
	rootSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("root signer: %v", err)
	}
	rootDER := rootSigner.Public().DER
	childSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("child signer: %v", err)
	}

	reg := delegation.NewToolRegistry(map[string]string{})

	wide := delegation.Authority{
		Scopes: []string{"read", "write"},
		Tools:  []string{"search", "email"},
		Spend:  delegation.Budget{Amount: 1000, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 100, Per: "minute"},
		Depth:  3,
	}
	narrower := delegation.Authority{
		Scopes: []string{"read"},
		Tools:  []string{"search"},
		Spend:  delegation.Budget{Amount: 500, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 50, Per: "minute"},
		Depth:  2,
	}
	wider := delegation.Authority{ // widens the root in the scopes dimension (adds "admin")
		Scopes: []string{"read", "write", "admin"},
		Tools:  []string{"search", "email"},
		Spend:  delegation.Budget{Amount: 1000, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 100, Per: "minute"},
		Depth:  2,
	}

	buildChain := func(t *testing.T, childAuthority delegation.Authority) ([]delegation.RecordEnvelope, []byte) {
		t.Helper()
		rootRec := delegation.Record{
			TenantID:              tenantID,
			DelegatorID:           "root",
			DelegatorKey:          delegation.KeyRef{ID: rootKeyID, Algorithm: "ECDSA-P256"},
			DelegateID:            "mid",
			DelegateKeyThumbprint: delegation.DelegateKeyThumbprintOf(childSigner.Public().DER),
			Authority:             wide,
			DepthRemaining:        3,
			RootAnchor:            true,
		}
		rootSigned, err := rootRec.Sign(rootSigner, reg)
		if err != nil {
			t.Fatalf("sign root: %v", err)
		}
		rootDigest, err := rootSigned.Digest(reg)
		if err != nil {
			t.Fatalf("root digest: %v", err)
		}
		childRec := delegation.Record{
			TenantID:       tenantID,
			DelegatorID:    "mid",
			DelegatorKey:   delegation.KeyRef{ID: "mid-key", Algorithm: "ECDSA-P256"},
			DelegateID:     "agent",
			Authority:      childAuthority,
			DepthRemaining: 1,
			ParentDigest:   rootDigest,
		}
		childSigned, err := childRec.Sign(childSigner, reg)
		if err != nil {
			t.Fatalf("sign child: %v", err)
		}
		childDigest, err := childSigned.Digest(reg)
		if err != nil {
			t.Fatalf("child digest: %v", err)
		}
		return []delegation.RecordEnvelope{
			{Record: rootSigned, DelegatorPublicDER: rootDER},
			{Record: childSigned, DelegatorPublicDER: childSigner.Public().DER},
		}, childDigest
	}

	// --- Agent-stack representation + attestation evidence carried opaquely over the seam. ---
	repr, err := agentstack.New([]byte("system prompt v1"), agentstack.NewToolManifest("search"), agentstack.Model{
		Form:            agentstack.ModelFormProviderID,
		ProviderModelID: "anthropic/claude-x",
		ModelVersion:    "2026-01-01",
	})
	if err != nil {
		t.Fatalf("agentstack.New: %v", err)
	}
	// SubjectRepr is the JSON of the agent-stack representation (the gate reads its
	// system_prompt_digest / tool_manifest_digest and binds these exact bytes + their
	// digest, without linking the agentstack package inside the signer — AN-4).
	reprBytes, err := json.Marshal(repr)
	if err != nil {
		t.Fatalf("marshal repr: %v", err)
	}
	attPayload := []byte("valid-software-attestation-evidence")
	attBody, err := json.Marshal(delegation.AttestationBody{Method: attMethod, Payload: attPayload})
	if err != nil {
		t.Fatalf("marshal attestation body: %v", err)
	}

	// --- Build the in-signer gate exactly as the deployment provisions it (AGID-INT-WIRE):
	// root anchor held, software-class required for the designated class, fake attestor. ---
	gate, refusalPubDER := mustSignerGate(t, delegation.SignerConfig{
		SignerID: "trstctl-signer",
		Anchors: map[string]delegation.RootAnchor{
			rootKeyID: {PublicDER: rootDER, AuthRef: "fido2:root-token"},
		},
		Revocations: delegation.NeverRevoked{},
		Attestor:    wireFakeAttestor{method: attMethod, payload: attPayload},
		MinClass:    delegation.MinClassPolicy{designatedClass: delegation.ClassSoftware},
		Tools:       reg,
	})

	keyOp := delegation.NewSignerIssuanceKeyOp(delegation.SignerConfig{SignerID: "trstctl-signer"})

	// --- Stand up the REAL signer over a REAL UDS gRPC listener, and dial with the
	// production client. The counting key factory observes every in-signer key op. ---
	factory := newCountingKeyFactory()
	srv := signing.NewServer(
		signing.WithIssuanceGate(gate),
		signing.WithIssuanceKeyOp(keyOp),
		signing.WithKeyFactory(factory),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir, err := os.MkdirTemp("", "agidwire")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")
	// AllowInsecureDevNonLinux mirrors internal/signing's own test idiom: UDS peer
	// credentials only exist on Linux, so without it listenUDS refuses to start and
	// the only symptom is DialReady timing out with "signer not ready" — which is
	// what this test did, undiagnosed, for as long as nothing ran it.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{
			AllowInsecureDevNonLinux: runtime.GOOS != "linux",
		})
	}()

	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		// Surface why the signer never came up instead of reporting only that it
		// did not; the serve error is the actual diagnosis.
		select {
		case serr := <-serveErr:
			t.Fatalf("DialReady: %v (signer refused to serve: %v)", err, serr)
		default:
			t.Fatalf("DialReady: %v", err)
		}
	}
	defer func() { _ = client.Close() }()

	encodePre := func(t *testing.T, chain []delegation.RecordEnvelope) []byte {
		t.Helper()
		pre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{
			Chain:           chain,
			DesignatedClass: designatedClass,
		})
		if err != nil {
			t.Fatalf("encode preconditions: %v", err)
		}
		return pre
	}

	// ================= (1) WIDENED CHAIN: refused with a signed refusal, ZERO key ops. =====
	// Run the refusal case FIRST, while no key op has happened yet, so the key-op count
	// starting at zero must remain zero (INV-A1: no keygen on a refused issuance).
	if factory.gens != 0 {
		t.Fatalf("precondition: key factory should have 0 gens before any issuance, got %d", factory.gens)
	}
	widenedChain, _ := buildChain(t, wider)
	refusedReq := signing.IssuancePreconditions{
		TenantID:          tenantID,
		TrustAnchorRef:    "fido2:root-token",
		Preconditions:     encodePre(t, widenedChain),
		SubjectRepr:       reprBytes,
		Attestation:       attBody,
		AttestationMethod: attMethod,
	}
	refusedDecision, err := client.GatedIssue(ctx, refusedReq, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GatedIssue (widened) returned a transport error, want a refusal decision: %v", err)
	}
	if refusedDecision.Approved {
		t.Fatal("widened chain was APPROVED; a hop that widens authority must be refused (INV-A1)")
	}
	if len(refusedDecision.CredentialPublicDER) != 0 || len(refusedDecision.EncodedRecord) != 0 {
		t.Fatalf("refused issuance returned credential material (pub=%d bytes, rec=%d bytes); a refusal must carry NO credential",
			len(refusedDecision.CredentialPublicDER), len(refusedDecision.EncodedRecord))
	}
	if len(refusedDecision.RefusalRecord) == 0 {
		t.Fatal("refused issuance carried no signed refusal record (the fail-closed spine, INV-A1)")
	}
	// The refusal is a real signed artifact naming the narrowing check, verifiable against
	// the signer's refusal public key.
	art, err := delegation.DecodeRefusal(refusedDecision.RefusalRecord)
	if err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	if err := delegation.VerifyRefusal(refusalPubDER, art); err != nil {
		t.Fatalf("refusal artifact does not verify against the signer refusal key: %v", err)
	}
	if art.FailedCheck != delegation.CheckNarrowing {
		t.Fatalf("refusal failed_check = %q, want %q (the widened hop must be caught by the narrowing check)", art.FailedCheck, delegation.CheckNarrowing)
	}
	if factory.gens != 0 {
		t.Fatalf("observed %d key op(s) on a REFUSED issuance, want ZERO (INV-A1: no keygen without approval)", factory.gens)
	}

	// ================= (2) VALID NARROWING CHAIN: verified in-signer, then MINTS. ==========
	validChain, chainHeadDigest := buildChain(t, narrower)
	approvedReq := signing.IssuancePreconditions{
		TenantID:          tenantID,
		TrustAnchorRef:    "fido2:root-token",
		Preconditions:     encodePre(t, validChain),
		SubjectRepr:       reprBytes,
		Attestation:       attBody,
		AttestationMethod: attMethod,
	}
	approvedDecision, err := client.GatedIssue(ctx, approvedReq, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GatedIssue (valid) error: %v", err)
	}
	if !approvedDecision.Approved {
		t.Fatalf("valid narrowing chain was NOT approved; refusal=%s", string(approvedDecision.RefusalRecord))
	}
	if len(approvedDecision.CredentialPublicDER) == 0 {
		t.Fatal("approved issuance returned no credential public key; the signer must mint on approval")
	}
	if len(approvedDecision.EncodedRecord) == 0 {
		t.Fatal("approved issuance returned no encoded credential record (the issued certificate DER)")
	}
	// A key op DID happen after approval (the agent key was generated inside the signer,
	// plus the bootstrap issuing CA). INV-A1: verification precedes keygen, keygen happens
	// only on approval.
	if factory.gens == 0 {
		t.Fatal("no key op observed on an APPROVED issuance; the signer must generate the agent key inside the boundary")
	}

	// The minted credential (the encoded record) is a real certificate carrying the AGID
	// binding extension, bound to the VERIFIED chain-head digest + the agent-stack repr.
	bm, err := delegation.ExtractBindingMaterial(approvedDecision.EncodedRecord)
	if err != nil {
		t.Fatalf("extract binding material from minted credential: %v", err)
	}
	if string(bm.ChainHeadDigest) != string(chainHeadDigest) {
		t.Fatalf("bound chain-head digest = %x, want the VERIFIED chain head %x", bm.ChainHeadDigest, chainHeadDigest)
	}
	wantStackDigest := delegation.AgentStackDigestOf(reprBytes)
	if string(bm.AgentStackDigest) != string(wantStackDigest) {
		t.Fatalf("bound agent-stack digest = %x, want %x (the credential must bind the agent-stack representation)", bm.AgentStackDigest, wantStackDigest)
	}

	// The returned binding material (over the wire, opaque) decodes to the SAME binding the
	// credential carries — the signer returned only public material, no private key.
	wireBM, err := delegation.DecodeBindingMaterial(approvedDecision.BindingMaterial)
	if err != nil {
		t.Fatalf("decode wire binding material: %v", err)
	}
	if string(wireBM.ChainHeadDigest) != string(chainHeadDigest) {
		t.Fatalf("wire binding chain-head digest = %x, want %x", wireBM.ChainHeadDigest, chainHeadDigest)
	}

	// A byte-exact prompt swap flips the agent-stack digest, so a credential minted for a
	// different agent stack would NOT match — proving the binding is to THIS stack.
	otherRepr, err := agentstack.New([]byte("system prompt v2 (swapped)"), agentstack.NewToolManifest("search"), agentstack.Model{
		Form:            agentstack.ModelFormProviderID,
		ProviderModelID: "anthropic/claude-x",
		ModelVersion:    "2026-01-01",
	})
	if err != nil {
		t.Fatalf("agentstack.New (other): %v", err)
	}
	otherBytes, _ := json.Marshal(otherRepr)
	if string(delegation.AgentStackDigestOf(otherBytes)) == string(bm.AgentStackDigest) {
		t.Fatal("a swapped prompt produced the SAME agent-stack digest; the binding is not sensitive to the stack")
	}
}

// mustSignerGate builds the production in-signer gate, failing the test on a construction
// error. It returns the gate and the refusal-signing public key DER. The chain's validity
// windows are open (no bounds), so the gate's default time.Now clock is time-independent
// here.
func mustSignerGate(t *testing.T, cfg delegation.SignerConfig) (*delegation.Gate, []byte) {
	t.Helper()
	gate, refusalPub, err := delegation.NewSignerGate(cfg)
	if err != nil {
		t.Fatalf("NewSignerGate: %v", err)
	}
	return gate, refusalPub.DER
}
