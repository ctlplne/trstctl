// SPDX-License-Identifier: BUSL-1.1

package conformance

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
)

// The operator's KEM journey through the served path (A16): a bare genesis at
// epoch 0, a first re-wrap request that attests the empty inventory and mints
// the paired KEM successor at epoch 1, an envelope registered against that
// epoch's public key, and a second re-wrap that moves it to epoch 2 with a
// verified readback. Both requests are recorded by the API and replayed by the
// worker, so the worker must encode the same request event the API did.
func TestKEMOperatorJourneyThroughServiceAndWorker(t *testing.T) {
	st := startINT20Stack(t)
	const id = "spiffe://operator.example/kem-journey"
	if _, err := st.svc.RegisterGenesis(st.ctx, st.tenantID, succapi.GenesisRegistrationRequest{
		IdentityID: id, Algorithm: string(crypto.ECDSAP256), DeploymentScope: "spiffe://operator.example",
	}); err != nil {
		t.Fatalf("register genesis: %v", err)
	}
	st.dispatchAll(t)

	if _, err := st.svc.RequestKEMRewrap(st.ctx, st.tenantID, succapi.KEMRewrapRequest{
		IdentityID: id, PredecessorEpoch: 0, SigningAlgorithm: string(crypto.ECDSAP256),
		KEMAlgorithm: "ML-KEM-768", EmptyInventoryAttested: true,
	}); err != nil {
		t.Fatalf("request first re-wrap: %v", err)
	}
	st.dispatchAll(t)
	status, err := st.svc.RewrapStatus(st.ctx, st.tenantID, id, 0)
	if err != nil || !status.Complete {
		t.Fatalf("first re-wrap (attested empty inventory) did not complete: %+v err=%v", status, err)
	}

	pub, found, err := st.svc.KEMPublicKey(st.ctx, st.tenantID, id, 1)
	if err != nil || !found || pub.KEMAlgorithm != "ML-KEM-768" {
		t.Fatalf("epoch 1 KEM public key: found=%t %+v err=%v", found, pub, err)
	}
	dek := []byte("data-key-for-the-orders-backup!!")
	ct, ss, err := pqc.Encapsulate(crypto.PublicKey{Algorithm: crypto.Algorithm(pub.KEMAlgorithm), DER: pub.PublicKeyDER})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.KEMDataKeySeal(ss, dek, succession.KEMDataKeyAAD(id, 1, "backup:a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.svc.RegisterKEMDataKey(st.ctx, st.tenantID, succapi.KEMDataKeyRequest{
		IdentityID: id, Epoch: 1, TargetRef: "backup:a", KEMCiphertext: ct, WrappedDEK: wrapped, DEKSHA256: crypto.SHA256Sum(dek),
	}); err != nil {
		t.Fatalf("register envelope: %v", err)
	}

	if _, err := st.svc.RequestKEMRewrap(st.ctx, st.tenantID, succapi.KEMRewrapRequest{
		IdentityID: id, PredecessorEpoch: 1, SigningAlgorithm: string(crypto.ECDSAP256), KEMAlgorithm: "ML-KEM-768",
	}); err != nil {
		t.Fatalf("request second re-wrap: %v", err)
	}
	st.dispatchAll(t)
	status, err = st.svc.RewrapStatus(st.ctx, st.tenantID, id, 1)
	if err != nil || !status.Complete || len(status.Jobs) != 1 || status.Jobs[0].DataKeysRewrapped != 1 {
		t.Fatalf("second re-wrap did not move the registered envelope: %+v err=%v", status, err)
	}
	list, err := st.svc.ListKEMDataKeys(st.ctx, st.tenantID, id, 2, "")
	if err != nil || len(list.Items) != 1 || !list.Items[0].ReadbackVerified || list.Items[0].TargetRef != "backup:a" {
		t.Fatalf("epoch 2 envelopes: %+v err=%v", list, err)
	}
}
