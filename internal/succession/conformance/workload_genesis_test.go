// SPDX-License-Identifier: BUSL-1.1

package conformance

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
)

// A workload-custody genesis travels the served path end to end: the HTTP
// service validates and enqueues it, the durable genesis worker anchors the
// agent's public key without minting one in the signer, and the chain reads
// back the custody mode and that exact key (A17).
func TestOperatorGenesisWorkloadCustodyDeliversAnchor(t *testing.T) {
	st := startINT20Stack(t)
	const id = "spiffe://operator.example/workload/held"
	agentKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pem := string(crypto.MarshalPublicKeyPEM(agentKey.Public().DER))
	accepted, err := st.svc.RegisterGenesis(st.ctx, st.tenantID, succapi.GenesisRegistrationRequest{
		IdentityID: id, Algorithm: string(crypto.ECDSAP256), DeploymentScope: "spiffe://operator.example",
		PredecessorCustody: succession.PredecessorCustodyWorkload, PublicKeyPEM: pem,
	})
	if err != nil {
		t.Fatalf("register workload genesis: %v", err)
	}
	st.dispatchAll(t)
	status, found, err := st.svc.GetRequestStatus(st.ctx, st.tenantID, accepted.RequestID)
	if err != nil || !found || status.Status != "delivered" {
		t.Fatalf("workload genesis request status=%+v found=%t err=%v (want delivered)", status, found, err)
	}
	chain, err := st.svc.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || chain.Genesis == nil {
		t.Fatalf("genesis readback: %+v, %v", chain, err)
	}
	if chain.Genesis.PredecessorCustody != succession.PredecessorCustodyWorkload || string(chain.Genesis.PublicKey) != string(agentKey.Public().DER) {
		t.Fatalf("anchor must record workload custody and the agent's key: custody=%q", chain.Genesis.PredecessorCustody)
	}
	if err := succession.VerifyGenesis(chain.TrustRootPublicDER, *chain.Genesis); err != nil {
		t.Fatalf("workload genesis is not independently verifiable: %v", err)
	}
}
