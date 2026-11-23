// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

type cr053CountingAttestor struct{ calls int }

func (a *cr053CountingAttestor) VerifyEvidence(string, []byte) (VerifiedAttestation, error) {
	a.calls++
	return VerifiedAttestation{}, nil
}

func TestCR053MissingProofDoesNotSpendAttestation(t *testing.T) {
	const tenantID = "tenant-proof-attestation"
	envs, anchors, _ := singleAnchorChain(t, nil, tenantID, "fido2:root")
	floor := t.TempDir()
	roots := NewDurableAnchorStore(floor)
	if err := roots.PutRootAnchor(backgroundCtx(), tenantID, "root-key", anchors["root-key"]); err != nil {
		t.Fatal(err)
	}
	attestor := &cr053CountingAttestor{}
	gate, _, err := NewSignerGate(SignerConfig{SignerID: "signer", AnchorSource: roots, Attestor: attestor})
	if err != nil {
		t.Fatal(err)
	}
	pre, err := EncodePreconditionsBody(PreconditionsBody{Chain: envs})
	if err != nil {
		t.Fatal(err)
	}
	att, err := json.Marshal(AttestationBody{Method: "software", Payload: []byte("signed-evidence")})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := gate.VerifyIssuancePreconditions(backgroundCtx(), signing.IssuancePreconditions{
		TenantID: tenantID, TrustAnchorRef: "leaf", Preconditions: pre,
		Attestation: att, AttestationMethod: "software",
	})
	if err != nil || dec.Approved {
		t.Fatalf("missing proof approved=%t err=%v", dec.Approved, err)
	}
	if attestor.calls != 0 {
		t.Fatalf("missing proof consumed attestation %d times before refusal", attestor.calls)
	}
}

func TestCR053SignerConsumesFreshBoundNonRevocationProof(t *testing.T) {
	const tenantID = "tenant-proof"
	envs, anchors, _ := singleAnchorChain(t, nil, tenantID, "fido2:root")
	floor := t.TempDir()
	roots := NewDurableAnchorStore(floor)
	if err := roots.PutRootAnchor(backgroundCtx(), tenantID, "root-key", anchors["root-key"]); err != nil {
		t.Fatal(err)
	}
	proofSigner, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	key := reach.VerdictKeyRef{ID: "proof-key", Algorithm: string(crypto.ECDSAP256)}
	trust := func(id string) ([]byte, bool) {
		return proofSigner.Public().DER, id == key.ID
	}
	newGate := func() *Gate {
		t.Helper()
		gate, _, err := NewSignerGate(SignerConfig{
			SignerID: "signer", AnchorSource: roots,
			RevocationProofTrust: trust, ProofConsumer: NewDurableProofConsumer(floor),
		})
		if err != nil {
			t.Fatal(err)
		}
		return gate
	}
	pre, err := EncodePreconditionsBody(PreconditionsBody{Chain: envs})
	if err != nil {
		t.Fatal(err)
	}
	req := signing.IssuancePreconditions{TenantID: tenantID, TrustAnchorRef: "leaf", Preconditions: pre}
	gate := newGate()
	if dec, err := gate.VerifyIssuancePreconditions(backgroundCtx(), req); err != nil || dec.Approved {
		t.Fatalf("missing proof approved=%t err=%v", dec.Approved, err)
	}
	proof, err := SignRevocationProof(req, key, proofSigner, bytes.Repeat([]byte{0x42}, 32), time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	body, err := DecodePreconditionsBody(pre)
	if err != nil {
		t.Fatal(err)
	}
	body.RevocationProof = proof
	req.Preconditions, err = EncodePreconditionsBody(body)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := gate.VerifyIssuancePreconditions(backgroundCtx(), req)
	if err != nil || !dec.Approved {
		t.Fatalf("fresh bound proof approved=%t err=%v refusal=%s", dec.Approved, err, dec.RefusalRecord)
	}
	// The same nonce remains spent when the signer process recreates the gate.
	dec, err = newGate().VerifyIssuancePreconditions(backgroundCtx(), req)
	if err != nil || dec.Approved {
		t.Fatalf("replayed proof after restart approved=%t err=%v", dec.Approved, err)
	}
	if art := decodeRefusalForTest(t, dec.RefusalRecord); art.FailedCheck != CheckRevocation {
		t.Fatalf("replay failed_check = %q", art.FailedCheck)
	}
	// Altering any request field invalidates the signed authorization.
	other := req
	other.TrustAnchorRef = "other-agent"
	if err := VerifyRevocationProof(other, proof, trust, NewDurableProofConsumer(t.TempDir()), time.Now()); err == nil {
		t.Fatal("proof from one subject authorized another")
	}
	other = req
	other.TenantID = "other-tenant"
	if err := VerifyRevocationProof(other, proof, trust, NewDurableProofConsumer(t.TempDir()), time.Now()); err == nil {
		t.Fatal("proof crossed tenant boundary")
	}
	other = req
	other.Algorithm = crypto.RSA3072
	if err := VerifyRevocationProof(other, proof, trust, NewDurableProofConsumer(t.TempDir()), time.Now()); err == nil {
		t.Fatal("proof authorized a different key algorithm")
	}
	expired, err := SignRevocationProof(req, key, proofSigner, bytes.Repeat([]byte{0x43}, 32), time.Now().Add(-10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationProof(req, expired, trust, NewDurableProofConsumer(t.TempDir()), time.Now()); err == nil {
		t.Fatal("expired proof authorized issuance")
	}
}

func TestCR053DurableProofReceiptsExpireWithoutGrowingForever(t *testing.T) {
	floor := t.TempDir()
	consumer := NewDurableProofConsumer(floor)
	for i := 0; i < 64; i++ {
		nonce := bytes.Repeat([]byte{byte(i)}, 32)
		if err := consumer.ConsumeProofNonce("tenant", nonce, time.Now().Add(-time.Second).UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(floor, spentProofDir, crypto.SHA256Hex([]byte("tenant")))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expired proof receipts retained: %d", len(entries))
	}
	if err := consumer.ConsumeProofNonce("tenant", bytes.Repeat([]byte{0x42}, 32), time.Now().Add(time.Second).UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := NewDurableProofConsumer(floor).ConsumeProofNonce("tenant", bytes.Repeat([]byte{0x42}, 32), time.Now().Add(time.Second).UnixNano()); err == nil {
		t.Fatalf("restart replay accepted: %v", err)
	}
}

func TestCR053ConcurrentSignerPeersSpendProofOnlyOnce(t *testing.T) {
	floor := t.TempDir()
	nonce := bytes.Repeat([]byte{0x71}, 32)
	const peers = 12
	var wg sync.WaitGroup
	results := make(chan error, peers)
	for range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- NewDurableProofConsumer(floor).ConsumeProofNonce("tenant", nonce, time.Now().Add(time.Second).UnixNano())
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("concurrent replay minted %d one-use proof claims, want exactly one", success)
	}
}
