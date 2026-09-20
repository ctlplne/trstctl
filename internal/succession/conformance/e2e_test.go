// SPDX-License-Identifier: BUSL-1.1

// Package conformance is the PCAS release gate (PCAS-12): the end-to-end PCAS-claim-1
// proof, the published conformance vectors + a differential verifier, fuzz targets on
// the parsers, and the edition guards pinned as tests. It adds no product behavior —
// it only proves the behavior the other cards deliver.
package conformance

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rpverify"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/minter"
)

const (
	e2eScope    = "spiffe://trust-domain"
	e2eIdentity = "spiffe://trust-domain/workload/db"
	e2eTenant   = "11111111-1111-1111-1111-111111111111"
)

type memEpochStore struct{ m map[string]uint64 }

func (s *memEpochStore) LastAccepted(id string) (uint64, bool, error) {
	e, ok := s.m[id]
	return e, ok, nil
}
func (s *memEpochStore) SetLastAccepted(id string, epoch uint64) error { s.m[id] = epoch; return nil }

// TestE2E_Succession_OfflineVerify is the PCAS-claim-1 end-to-end: a real signer mints a
// multi-epoch algorithm succession for a workload identity (each key generated and
// used inside the module, epochs enforced by the signer floor), the chain is
// assembled with its tenant-trust-root-anchored genesis, and a relying party then
// verifies it OFFLINE — no algorithm negotiation, no provider load, no network — via
// internal/rpverify. A tampered chain is rejected; the durable last-accepted epoch advances
// and refuses a stale replay.
func TestE2E_Succession_OfflineVerify(t *testing.T) {
	ctx := context.Background()
	be := crypto.NewSoftwareBackend()

	// The signer's custody boundary is both the successor key factory and the
	// predecessor resolver (PCAS-22), so a minted successor becomes the next
	// predecessor by handle without any private key leaving the module.
	hsm := minter.NewSoftHSM(be)
	genesisKey, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	hsm.Import("genesis", genesisKey)

	m, err := minter.New(hsm, hsm, hsm.FloorStore())
	if err != nil {
		t.Fatal(err)
	}

	// Genesis: the identity's chain anchor, signed by the tenant trust root.
	trustRoot, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	genesis := succession.GenesisRecord{
		DeploymentScope: e2eScope, IdentityID: e2eIdentity, TenantID: e2eTenant,
		Algorithm: genesisKey.Algorithm(), PublicKey: genesisKey.Public().DER, Epoch: 0,
	}
	gd, err := succession.GenesisDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if genesis.TrustRootAtt, err = trustRoot.Sign(gd, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatal(err)
	}

	// Two successions: ECDSA-P256 (genesis) → ECDSA-P384 → RSA-2048. Each mint asserts
	// the current epoch; the module generates the successor and advances the floor.
	req := func(handle string, asserted uint64, target crypto.Algorithm) signing.MintRequest {
		return signing.MintRequest{
			IdentityID: e2eIdentity, TenantID: e2eTenant, DeploymentScope: e2eScope,
			PredecessorHandle: handle, AssertedPredecessorEpoch: asserted, TargetAlgorithm: target,
			PolicyRef: "policy:e2e", NotBefore: 1, NotAfter: 1_000_000,
		}
	}
	res1, err := m.MintSuccessor(ctx, req("genesis", 0, crypto.ECDSAP384))
	if err != nil {
		t.Fatalf("mint epoch 1: %v", err)
	}
	res2, err := m.MintSuccessor(ctx, req("hsm-1", 1, crypto.RSA2048)) // successor of mint 1 is handle hsm-1
	if err != nil {
		t.Fatalf("mint epoch 2: %v", err)
	}
	rec1, _ := minter.DecodeRecord(res1.EncodedRecord)
	rec2, _ := minter.DecodeRecord(res2.EncodedRecord)
	chain := []succession.SuccessionRecord{rec1, rec2}

	// Offline relying-party verification (PCAS-claim-1 / PCAS-claim-13 / INV-6).
	store := &memEpochStore{m: map[string]uint64{}}
	result, err := rpverify.Verify(rpverify.Input{
		TrustRootPubDER: trustRoot.Public().DER, Genesis: genesis, Chain: chain,
	}, store, rpverify.Options{ExpectedTenant: e2eTenant})
	if err != nil {
		t.Fatalf("offline verify: %v", err)
	}
	if result.Epoch != 2 || result.Algorithm != crypto.RSA2048 {
		t.Fatalf("current posture = (%s, epoch %d), want (RSA-2048, 2)", result.Algorithm, result.Epoch)
	}

	// A tampered chain is rejected offline.
	bad := []succession.SuccessionRecord{rec1, rec2}
	tampered := bad[1]
	tampered.Possession.Signature = append([]byte{0x00}, tampered.Possession.Signature...)
	bad[1] = tampered
	if _, err := rpverify.Verify(rpverify.Input{TrustRootPubDER: trustRoot.Public().DER, Genesis: genesis, Chain: bad}, &memEpochStore{m: map[string]uint64{}}, rpverify.Options{ExpectedTenant: e2eTenant}); err == nil {
		t.Fatal("a tampered chain verified")
	}

	// The last-accepted epoch advanced to 2; presenting only epoch 1 is a downgrade.
	if _, err := rpverify.Verify(rpverify.Input{TrustRootPubDER: trustRoot.Public().DER, Genesis: genesis, Chain: chain[:1]}, store, rpverify.Options{ExpectedTenant: e2eTenant}); err == nil {
		t.Fatal("a stale (downgraded) chain was accepted after last-accepted advanced")
	}
}
