// SPDX-License-Identifier: BUSL-1.1

package rewrap_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/retirement"
	"trstctl.com/trstctl/internal/succession/rewrap"
)

const (
	rwTenant   = "11111111-1111-1111-1111-111111111111"
	rwIdentity = "spiffe://d/id"
	rwPredEp   = uint64(1)
)

func job() rewrap.Job {
	return rewrap.Job{
		IdentityID: rwIdentity, TenantID: rwTenant, PredecessorEpoch: rwPredEp, SuccessorEpoch: 2,
		PredecessorKEMAlg: "ML-KEM-768", SuccessorKEMAlg: "ML-KEM-768", Stages: []string{"s1", "s2", "s3"},
	}
}

func healthy(context.Context, string) error { return nil }

// TestRewrap_StagedResumable: a job interrupted mid-stage resumes without redoing a
// completed stage (no double-wrap) and reaches completion (PCAS-claim-39).
func TestRewrap_StagedResumable(t *testing.T) {
	progress := rewrap.NewMemProgress()
	ledger := rewrap.NewLedger()
	runner := rewrap.NewRunner(progress, ledger)
	calls := map[string]int{}

	// Run 1 crashes when doing s2 — s1 completes and is recorded, s2 is not.
	run1 := func(_ context.Context, stage string) error {
		calls[stage]++
		if stage == "s2" {
			return errors.New("crash")
		}
		return nil
	}
	if _, err := runner.Run(context.Background(), job(), run1, healthy); err == nil {
		t.Fatal("run 1 should have failed at s2")
	}

	// Run 2 resumes with a healthy stage function.
	run2 := func(_ context.Context, stage string) error { calls[stage]++; return nil }
	res, err := runner.Run(context.Background(), job(), run2, healthy)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !res.Completed {
		t.Fatal("job did not complete after resume")
	}
	// s1 completed in run 1 and is NOT redone (no double-wrap).
	if calls["s1"] != 1 {
		t.Fatalf("completed stage s1 was redone %d times (double-wrap)", calls["s1"])
	}
	if calls["s3"] != 1 {
		t.Fatalf("stage s3 ran %d times, want 1", calls["s3"])
	}
	if !ledger.IsComplete(rwIdentity, rwPredEp) {
		t.Fatal("completion event not recorded")
	}
}

// TestRewrap_StageHealthHalts: a per-stage health verification failure halts the job
// with a structured error and records no completion (PCAS-claim-39, AC4).
func TestRewrap_StageHealthHalts(t *testing.T) {
	ledger := rewrap.NewLedger()
	runner := rewrap.NewRunner(rewrap.NewMemProgress(), ledger)
	unhealthy := func(_ context.Context, stage string) error {
		if stage == "s2" {
			return errors.New("integrity check failed")
		}
		return nil
	}
	if _, err := runner.Run(context.Background(), job(), func(context.Context, string) error { return nil }, unhealthy); !errors.Is(err, rewrap.ErrStageHealth) {
		t.Fatalf("health halt: got %v, want ErrStageHealth", err)
	}
	if ledger.IsComplete(rwIdentity, rwPredEp) {
		t.Fatal("job reported complete despite a health halt")
	}
}

// nopLedger is a retirement AN-2 sink.
type nopLedger struct{}

func (nopLedger) Append(_ context.Context, e events.Event) (events.Event, error) { return e, nil }

func retire(t *testing.T, gate func(context.Context) error) (*retirement.Controller, retirement.CutoverRequest, *byok.ManagedSigner) {
	t.Helper()
	rp, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := retirement.New(retirement.Config{
		Roster: retirement.Roster{"rp1": rp.Public().DER},
		Policy: retirement.QuorumPolicy{Threshold: 1}, Ledger: nopLedger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := retirement.SignAck(rp, rwTenant, rwIdentity, rwPredEp, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	pred, err := byok.GenerateSigner(context.Background(), nil, rwTenant, "kem-pred", crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	req := retirement.CutoverRequest{
		Target:      retirement.Target{TenantID: rwTenant, IdentityID: rwIdentity, Epoch: rwPredEp},
		Acks:        []retirement.SignedAck{{TenantID: rwTenant, IdentityID: rwIdentity, Epoch: rwPredEp, RelyingParty: "rp1", Signature: sig}},
		Predecessor: pred,
		Successor:   retirement.Successor{Epoch: 2, Algorithm: "ML-KEM-768", Class: succession.ClassPurePQ, PublicKeyDER: []byte{1}},
		PreRetire:   gate,
	}
	return ctrl, req, pred
}

// TestRewrap_CompletionGatesRetirement: retirement of the predecessor KEM key is
// refused until the completion events are recorded; with them it proceeds (PCAS-claim-39).
func TestRewrap_CompletionGatesRetirement(t *testing.T) {
	ledger := rewrap.NewLedger()
	runner := rewrap.NewRunner(rewrap.NewMemProgress(), ledger)
	ctrl, req, pred := retire(t, rewrap.RetirementGate(ledger, rwIdentity, rwPredEp))

	// Re-wrap not yet complete → retirement blocked, predecessor untouched.
	if _, err := ctrl.Execute(context.Background(), req, time.Now()); !errors.Is(err, rewrap.ErrRewrapIncomplete) {
		t.Fatalf("retire before re-wrap complete: got %v, want ErrRewrapIncomplete", err)
	}
	if pred.State() != byok.StateActive {
		t.Fatalf("predecessor retired before re-wrap completed (state %q)", pred.State())
	}

	// Complete the re-wrap job — the completion event is recorded.
	if res, err := runner.Run(context.Background(), job(), func(context.Context, string) error { return nil }, healthy); err != nil || !res.Completed {
		t.Fatalf("run to completion: res=%+v err=%v", res, err)
	}

	// Now retirement proceeds.
	if _, err := ctrl.Execute(context.Background(), req, time.Now()); err != nil {
		t.Fatalf("retire after re-wrap complete: %v", err)
	}
	if pred.State() != byok.StateZeroized {
		t.Fatalf("predecessor not retired after re-wrap (state %q)", pred.State())
	}
}

// TestRewrap_GatesRetirement: the standing invariant guard — no partial state allows
// retirement while re-wrap is incomplete; only recorded completion opens the gate
// (INV-15).
func TestRewrap_GatesRetirement(t *testing.T) {
	// Partial: a job halted mid-way records stage events but no completion.
	ledger := rewrap.NewLedger()
	runner := rewrap.NewRunner(rewrap.NewMemProgress(), ledger)
	haltAtS3 := func(_ context.Context, stage string) error {
		if stage == "s3" {
			return errors.New("integrity check failed")
		}
		return nil
	}
	_, _ = runner.Run(context.Background(), job(), func(context.Context, string) error { return nil }, haltAtS3)

	gate := rewrap.RetirementGate(ledger, rwIdentity, rwPredEp)
	if err := gate(context.Background()); !errors.Is(err, rewrap.ErrRewrapIncomplete) {
		t.Fatalf("gate open on partial re-wrap: got %v, want ErrRewrapIncomplete", err)
	}
	// A different predecessor epoch's completion does not open this gate.
	_, _ = ledger.Append(context.Background(), mustEncode(t, succession.RewrapCompletedV1{
		JobID: "other", IdentityID: rwIdentity, TenantID: rwTenant, PredecessorEpoch: 99, Stages: 1,
	}))
	if err := gate(context.Background()); !errors.Is(err, rewrap.ErrRewrapIncomplete) {
		t.Fatalf("gate opened by an unrelated completion: %v", err)
	}
	// Completing THIS predecessor's re-wrap opens the gate.
	if _, err := runner.Run(context.Background(), job(), func(context.Context, string) error { return nil }, healthy); err != nil {
		t.Fatal(err)
	}
	if err := gate(context.Background()); err != nil {
		t.Fatalf("gate still closed after completion: %v", err)
	}
}

func mustEncode(t *testing.T, p succession.Payload) events.Event {
	t.Helper()
	e, err := succession.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
