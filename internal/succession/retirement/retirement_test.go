// SPDX-License-Identifier: BUSL-1.1

package retirement_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/retirement"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
	identA  = "spiffe://d/idA"
)

var evalTime = time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

// memLedger is an in-memory AN-2 sink recording appended events.
type memLedger struct {
	mu  sync.Mutex
	evs []events.Event
}

func (l *memLedger) Append(_ context.Context, e events.Event) (events.Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Sequence = uint64(len(l.evs) + 1)
	if e.Time.IsZero() {
		e.Time = evalTime
	}
	l.evs = append(l.evs, e)
	return e, nil
}

func (l *memLedger) count(typ string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.evs {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func (l *memLedger) last(typ string) (events.Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.evs) - 1; i >= 0; i-- {
		if l.evs[i].Type == typ {
			return l.evs[i], true
		}
	}
	return events.Event{}, false
}

// spyPredecessor records the order of lifecycle calls and delegates to a real key.
type spyPredecessor struct {
	inner retirement.Predecessor
	order []string
}

func (s *spyPredecessor) Revoke(ctx context.Context, t string) error {
	s.order = append(s.order, "revoke")
	return s.inner.Revoke(ctx, t)
}
func (s *spyPredecessor) Zeroize(ctx context.Context, t string) error {
	s.order = append(s.order, "zeroize")
	return s.inner.Zeroize(ctx, t)
}

type rp struct {
	id     string
	signer crypto.Signer
}

func newRP(t *testing.T, id string) rp {
	t.Helper()
	s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return rp{id: id, signer: s}
}

func (r rp) ack(t *testing.T, tenant, identity string, epoch uint64, recordedAt time.Time) retirement.SignedAck {
	t.Helper()
	sig, err := retirement.SignAck(r.signer, tenant, identity, epoch, r.id)
	if err != nil {
		t.Fatal(err)
	}
	return retirement.SignedAck{
		TenantID: tenant, IdentityID: identity, Epoch: epoch, RelyingParty: r.id,
		RecordedAt: recordedAt, Signature: sig,
	}
}

func rosterOf(rps ...rp) retirement.Roster {
	r := retirement.Roster{}
	for _, x := range rps {
		r[x.id] = x.signer.Public().DER
	}
	return r
}

func newPredecessor(t *testing.T) *byok.ManagedSigner {
	t.Helper()
	m, err := byok.GenerateSigner(context.Background(), nil, tenantA, "pred-key", crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func pureSuccessor() retirement.Successor {
	return retirement.Successor{Epoch: 2, Algorithm: "ML-DSA-65", Class: succession.ClassPurePQ, PublicKeyDER: []byte{0x30, 0x2A}}
}

// TestSuccession_HybridThenPurePQC: the hybrid→pure-PQC succession is announced only
// once the ack quorum is met (PCAS-claim-2).
func TestSuccession_HybridThenPurePQC(t *testing.T) {
	rp1, rp2 := newRP(t, "rp1"), newRP(t, "rp2")
	ctx := context.Background()
	target := retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}

	// Below quorum: no succession announced.
	led := &memLedger{}
	ctrl, err := retirement.New(retirement.Config{Roster: rosterOf(rp1, rp2), Policy: retirement.QuorumPolicy{Threshold: 2}, Ledger: led})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ctrl.Execute(ctx, retirement.CutoverRequest{
		Target: target, Acks: []retirement.SignedAck{rp1.ack(t, tenantA, identA, 1, evalTime)},
		Predecessor: newPredecessor(t), Successor: pureSuccessor(), RetiredAlg: "ECDSA-P256",
	}, evalTime)
	if !errors.Is(err, retirement.ErrQuorumNotMet) {
		t.Fatalf("below quorum: err = %v, want ErrQuorumNotMet", err)
	}
	if led.count(succession.TypeSuccession) != 0 {
		t.Fatal("a pure-PQC succession was announced below quorum")
	}

	// At quorum: the pure-PQC succession is announced.
	led2 := &memLedger{}
	ctrl2, _ := retirement.New(retirement.Config{Roster: rosterOf(rp1, rp2), Policy: retirement.QuorumPolicy{Threshold: 2}, Ledger: led2})
	res, err := ctrl2.Execute(ctx, retirement.CutoverRequest{
		Target:      target,
		Acks:        []retirement.SignedAck{rp1.ack(t, tenantA, identA, 1, evalTime), rp2.ack(t, tenantA, identA, 1, evalTime)},
		Predecessor: newPredecessor(t), Successor: pureSuccessor(), RetiredAlg: "ECDSA-P256",
	}, evalTime)
	if err != nil {
		t.Fatalf("at quorum: %v", err)
	}
	if !res.Advanced || led2.count(succession.TypeSuccession) != 1 {
		t.Fatalf("pure-PQC succession not announced at quorum: advanced=%v count=%d", res.Advanced, led2.count(succession.TypeSuccession))
	}
	ev, _ := led2.last(succession.TypeSuccession)
	p, err := succession.Decode(ev)
	if err != nil {
		t.Fatal(err)
	}
	sv, ok := p.(succession.SuccessionV1)
	if !ok || sv.SuccessorAlgorithm != "ML-DSA-65" || sv.AlgorithmClass != succession.ClassPurePQ {
		t.Fatalf("announced succession is not pure-PQC: %+v", p)
	}
}

// TestRetirement_OnlyAfterQuorum: below quorum nothing is retired and no retirement
// event is emitted; the predecessor is untouched and can still sign (PCAS-claim-3 / INV-7).
func TestRetirement_OnlyAfterQuorum(t *testing.T) {
	rp1, rp2, rp3 := newRP(t, "rp1"), newRP(t, "rp2"), newRP(t, "rp3")
	led := &memLedger{}
	ctrl, _ := retirement.New(retirement.Config{Roster: rosterOf(rp1, rp2, rp3), Policy: retirement.QuorumPolicy{Threshold: 3}, Ledger: led})
	pred := newPredecessor(t)
	target := retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}

	_, err := ctrl.Execute(context.Background(), retirement.CutoverRequest{
		Target:      target,
		Acks:        []retirement.SignedAck{rp1.ack(t, tenantA, identA, 1, evalTime), rp2.ack(t, tenantA, identA, 1, evalTime)}, // 2 < 3
		Predecessor: pred, Successor: pureSuccessor(),
	}, evalTime)
	if !errors.Is(err, retirement.ErrQuorumNotMet) {
		t.Fatalf("err = %v, want ErrQuorumNotMet", err)
	}
	if led.count(succession.TypeRetirement) != 0 {
		t.Fatal("a retirement event was emitted below quorum")
	}
	// Predecessor untouched: still signs.
	if pred.State() != byok.StateActive {
		t.Fatalf("predecessor state = %q, want active (untouched below quorum)", pred.State())
	}
	if _, err := pred.SignDigest(crypto.SHA256Sum([]byte("x")), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("untouched predecessor should still sign: %v", err)
	}
}

// TestAck_MustBeSigned: an unsigned ack and one signed under a non-rostered/wrong
// key are not counted (PCAS-claim-3(a)).
func TestAck_MustBeSigned(t *testing.T) {
	rp1, rp2 := newRP(t, "rp1"), newRP(t, "rp2")
	roster := rosterOf(rp1, rp2)
	target := retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}

	good := rp1.ack(t, tenantA, identA, 1, evalTime)
	unsigned := good
	unsigned.RelyingParty = "rp2"
	unsigned.Signature = nil // rp2 ack with no signature

	// An impostor (not rostered) signs a well-formed ack claiming to be rp2.
	impostor := newRP(t, "rp2")
	forged := impostor.ack(t, tenantA, identA, 1, evalTime) // RP id "rp2" but wrong key

	q := retirement.EvaluateQuorum([]retirement.SignedAck{good, unsigned, forged}, target, roster, retirement.QuorumPolicy{Threshold: 2}, evalTime)
	if q.Met || q.Count != 1 {
		t.Fatalf("only the validly-signed ack should count: met=%v count=%d", q.Met, q.Count)
	}
}

// TestAck_BindsIdentityAndEpoch: an ack's signature binds identity and epoch, so it
// cannot be relabeled onto another identity/epoch; and an ack recorded outside the
// validity window is not counted (PCAS-claim-3(b),(c)).
func TestAck_BindsIdentityAndEpoch(t *testing.T) {
	rp1 := newRP(t, "rp1")
	roster := rosterOf(rp1)
	policy := retirement.QuorumPolicy{Threshold: 1, ValidityWindow: time.Hour}

	// Signature made for (identA, epoch 1).
	base := rp1.ack(t, tenantA, identA, 1, evalTime)

	// Relabel the identity: verification recomputes the message and fails.
	wrongIdentity := base
	wrongIdentity.IdentityID = "spiffe://d/other"
	if q := retirement.EvaluateQuorum([]retirement.SignedAck{wrongIdentity},
		retirement.Target{TenantID: tenantA, IdentityID: "spiffe://d/other", Epoch: 1}, roster, policy, evalTime); q.Met {
		t.Fatal("an ack relabeled onto another identity was counted")
	}
	// Relabel the epoch: same failure.
	wrongEpoch := base
	wrongEpoch.Epoch = 2
	if q := retirement.EvaluateQuorum([]retirement.SignedAck{wrongEpoch},
		retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 2}, roster, policy, evalTime); q.Met {
		t.Fatal("an ack relabeled onto another epoch was counted")
	}
	// Correctly-targeted, in-window ack counts.
	target := retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}
	if q := retirement.EvaluateQuorum([]retirement.SignedAck{base}, target, roster, policy, evalTime); !q.Met {
		t.Fatal("a valid in-window ack was not counted")
	}
	// Outside the validity window: not counted.
	stale := rp1.ack(t, tenantA, identA, 1, evalTime.Add(-2*time.Hour))
	if q := retirement.EvaluateQuorum([]retirement.SignedAck{stale}, target, roster, policy, evalTime); q.Met {
		t.Fatal("an ack recorded outside the validity window was counted")
	}
}

// TestQuorum_EvaluatedPerTenant: a tally for one tenant never counts another
// tenant's acks (PCAS-claim-3 / INV-5).
func TestQuorum_EvaluatedPerTenant(t *testing.T) {
	rp1, rp2 := newRP(t, "rp1"), newRP(t, "rp2")
	roster := rosterOf(rp1, rp2)
	policy := retirement.QuorumPolicy{Threshold: 2}

	// Two acks for tenant B, evaluated against a tenant-A target.
	acks := []retirement.SignedAck{
		rp1.ack(t, tenantB, identA, 1, evalTime),
		rp2.ack(t, tenantB, identA, 1, evalTime),
	}
	if q := retirement.EvaluateQuorum(acks, retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}, roster, policy, evalTime); q.Met || q.Count != 0 {
		t.Fatalf("tenant-B acks counted toward tenant-A quorum: met=%v count=%d", q.Met, q.Count)
	}
	// The same acks satisfy tenant B's own quorum.
	if q := retirement.EvaluateQuorum(acks, retirement.Target{TenantID: tenantB, IdentityID: identA, Epoch: 1}, roster, policy, evalTime); !q.Met {
		t.Fatal("tenant-B acks did not satisfy tenant B's quorum")
	}
}

// TestRetirement_RevokeThenZeroize_FailClosed: at quorum the predecessor is revoked
// THEN zeroized (in that order), signing fails closed, and the retirement event binds
// the satisfying ack-set digest with the succession record reference (PCAS-claims-8, 3 / INV-9).
func TestRetirement_RevokeThenZeroize_FailClosed(t *testing.T) {
	rp1, rp2 := newRP(t, "rp1"), newRP(t, "rp2")
	led := &memLedger{}
	ctrl, _ := retirement.New(retirement.Config{Roster: rosterOf(rp1, rp2), Policy: retirement.QuorumPolicy{Threshold: 2}, Ledger: led})
	spy := &spyPredecessor{inner: newPredecessor(t)}
	target := retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}
	acks := []retirement.SignedAck{rp1.ack(t, tenantA, identA, 1, evalTime), rp2.ack(t, tenantA, identA, 1, evalTime)}

	res, err := ctrl.Execute(context.Background(), retirement.CutoverRequest{
		Target: target, Acks: acks, Predecessor: spy, Successor: pureSuccessor(),
		RetiredAlg: "ECDSA-P256", SuccessionRef: []byte("succ-record-ref"),
	}, evalTime)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Retired {
		t.Fatal("result did not report retirement")
	}
	// Order: revoke before zeroize.
	if len(spy.order) != 2 || spy.order[0] != "revoke" || spy.order[1] != "zeroize" {
		t.Fatalf("lifecycle order = %v, want [revoke zeroize]", spy.order)
	}
	// Retirement event binds the ack-set digest and the succession reference.
	ev, ok := led.last(succession.TypeRetirement)
	if !ok {
		t.Fatal("no retirement event emitted")
	}
	p, err := succession.Decode(ev)
	if err != nil {
		t.Fatal(err)
	}
	rv := p.(succession.RetirementV1)
	wantDigest := retirement.AckSetDigest(res.Quorum.Satisfying)
	if !bytes.Equal(rv.AckSetDigest, wantDigest) {
		t.Fatal("retirement event does not bind the satisfying ack-set digest")
	}
	if !bytes.Equal(rv.SuccessionRef, []byte("succ-record-ref")) {
		t.Fatal("retirement event does not persist the succession record reference (durable proof)")
	}
	// The digest is recomputable by an auditor from the acks alone (offline-verifiable).
	if !bytes.Equal(retirement.AckSetDigest(acks), wantDigest) {
		t.Fatal("ack-set digest is not reproducible from the acknowledgement set")
	}
}

// TestZeroize_Residue: after an evidence-gated retirement the predecessor's material
// is gone — signing fails closed with ErrZeroized and the handle is terminal
// (PCAS-claims-8, 16 / INV-9).
func TestZeroize_Residue(t *testing.T) {
	rp1, rp2 := newRP(t, "rp1"), newRP(t, "rp2")
	led := &memLedger{}
	ctrl, _ := retirement.New(retirement.Config{Roster: rosterOf(rp1, rp2), Policy: retirement.QuorumPolicy{Threshold: 2}, Ledger: led})
	pred := newPredecessor(t)
	target := retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1}
	acks := []retirement.SignedAck{rp1.ack(t, tenantA, identA, 1, evalTime), rp2.ack(t, tenantA, identA, 1, evalTime)}

	if _, err := ctrl.Execute(context.Background(), retirement.CutoverRequest{
		Target: target, Acks: acks, Predecessor: pred, Successor: pureSuccessor(),
	}, evalTime); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if pred.State() != byok.StateZeroized {
		t.Fatalf("predecessor state = %q, want zeroized", pred.State())
	}
	if _, err := pred.SignDigest(crypto.SHA256Sum([]byte("y")), crypto.SignOptions{Hash: crypto.SHA256}); !errors.Is(err, byok.ErrZeroized) {
		t.Fatalf("zeroized predecessor signed (or wrong error): %v", err)
	}
	// Terminal: no path back to a usable key.
	if err := pred.Revoke(context.Background(), tenantA); !errors.Is(err, byok.ErrZeroized) {
		t.Fatalf("revoke after zeroize: %v, want ErrZeroized (terminal)", err)
	}
}

// TestAcksFromEvents_LedgerSourced: acknowledgements are reconstructed from AN-2
// ledger events, using the event's recorded time as the ack's window anchor.
func TestAcksFromEvents_LedgerSourced(t *testing.T) {
	rp1 := newRP(t, "rp1")
	sig, err := retirement.SignAck(rp1.signer, tenantA, identA, 1, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := succession.Encode(succession.RPAckV1{
		IdentityID: identA, TenantID: tenantA, Epoch: 1, RelyingParty: "rp1", AckSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.Time = evalTime
	acks, err := retirement.AcksFromEvents([]events.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	if len(acks) != 1 || acks[0].RelyingParty != "rp1" || !acks[0].RecordedAt.Equal(evalTime) {
		t.Fatalf("acks from events wrong: %+v", acks)
	}
	q := retirement.EvaluateQuorum(acks, retirement.Target{TenantID: tenantA, IdentityID: identA, Epoch: 1},
		rosterOf(rp1), retirement.QuorumPolicy{Threshold: 1, ValidityWindow: time.Hour}, evalTime)
	if !q.Met {
		t.Fatal("ledger-sourced ack did not satisfy quorum")
	}
}
