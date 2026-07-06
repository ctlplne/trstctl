// SPDX-License-Identifier: LicenseRef-trstctl-EE

package retirement_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/succession/retirement"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

type int17Ledger struct{ evs []events.Event }

func (m *int17Ledger) Append(_ context.Context, e events.Event) (events.Event, error) {
	m.evs = append(m.evs, e)
	return e, nil
}

func int17AckEvent(t *testing.T, rp crypto.Signer, rpID, tenant, id string, epoch uint64) events.Event {
	t.Helper()
	sig, err := rp.Sign(retirement.AckMessage(tenant, id, epoch, rpID), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := succession.Encode(succession.RPAckV1{
		IdentityID: id, TenantID: tenant, Epoch: epoch, RelyingParty: rpID, AckSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestINT17_RetirementWorker_EvidenceGatedCutover drives a real evidence-gated cutover
// through the worker: two rostered relying parties' signed acks are read from the
// ledger, the quorum is met, the pure-PQC succession is announced, the predecessor is
// zeroized, and a retirement event binding the ack-set digest is emitted (claims
// 2/3/8). A below-quorum evaluation refuses and changes nothing.
func TestINT17_RetirementWorker_EvidenceGatedCutover(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	rp1, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	rp2, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	const tenant, id = "t", "spiffe://d/int17"
	const predEpoch = uint64(1)
	roster := retirement.Roster{"rp1": rp1.Public().DER, "rp2": rp2.Public().DER}
	ledger := &int17Ledger{}
	ctrl, err := retirement.New(retirement.Config{Roster: roster, Policy: retirement.QuorumPolicy{Threshold: 2}, Ledger: ledger})
	if err != nil {
		t.Fatal(err)
	}
	worker := retirement.NewWorker(ctrl)

	zeroized := false
	pred := retirement.FuncPredecessor{ZeroizeFn: func(_ context.Context, _ string) error { zeroized = true; return nil }}
	succ := retirement.Successor{Epoch: predEpoch + 1, Algorithm: "ML-DSA-65", Class: "pure_pq", PublicKeyDER: []byte{1, 2, 3}}
	target := retirement.Target{TenantID: tenant, IdentityID: id, Epoch: predEpoch}

	res, err := worker.EvaluateCutover(context.Background(), target, succ, "hybrid", []byte("succ-ref"),
		[]events.Event{int17AckEvent(t, rp1, "rp1", tenant, id, predEpoch), int17AckEvent(t, rp2, "rp2", tenant, id, predEpoch)},
		pred, nil, time.Now())
	if err != nil {
		t.Fatalf("cutover: %v", err)
	}
	if !res.QuorumMet || !res.Retired || !res.Advanced {
		t.Fatalf("cutover result = %+v, want quorum-met + advanced + retired", res)
	}
	if !zeroized {
		t.Fatal("predecessor was not zeroized")
	}
	var retired *succession.RetirementV1
	for _, ev := range ledger.evs {
		if p, derr := succession.Decode(ev); derr == nil {
			if r, ok := p.(succession.RetirementV1); ok {
				rr := r
				retired = &rr
			}
		}
	}
	if retired == nil {
		t.Fatal("no RetirementV1 event on the ledger")
	}
	if len(retired.AckSetDigest) == 0 {
		t.Fatal("retirement event does not bind the ack-set digest")
	}

	// Below quorum (1 ack) -> refused, no ledger state change.
	ledger2 := &int17Ledger{}
	ctrl2, _ := retirement.New(retirement.Config{Roster: roster, Policy: retirement.QuorumPolicy{Threshold: 2}, Ledger: ledger2})
	_, err = retirement.NewWorker(ctrl2).EvaluateCutover(context.Background(), target, succ, "hybrid", nil,
		[]events.Event{int17AckEvent(t, rp1, "rp1", tenant, id, predEpoch)}, pred, nil, time.Now())
	if !errors.Is(err, retirement.ErrQuorumNotMet) {
		t.Fatalf("below-quorum err = %v, want ErrQuorumNotMet", err)
	}
	if len(ledger2.evs) != 0 {
		t.Fatal("below-quorum cutover changed ledger state")
	}
}
