// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reconcile

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/rounds"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/server"
)

// witnessEmitter is the production rounds.DisagreementSink (epic C4): the seam
// that turns a detected digest disagreement into a signed, recorded witness and
// hands it to quarantine admission.
//
// Before C4 nothing implemented this step. The scheduler detected two
// authorities committing to different state and appended NOTHING; witness.Build,
// witness.Sign, Recorder.RecordWitness and quarantine ObserveWitness all existed
// with no production caller. XREC could detect disagreement and had no way to
// say so, durably or otherwise.
type witnessEmitter struct {
	signer     server.SignerProvider
	recorder   *witness.Recorder
	quarantine *quarantine.Manager
	now        func() time.Time
}

func (e *witnessEmitter) RecordDisagreement(ctx context.Context, d rounds.Disagreement) error {
	if e == nil || e.recorder == nil {
		return fmt.Errorf("xrec runtime: witness recorder is not configured")
	}
	if e.signer == nil || e.signer.Client() == nil {
		// XREC-02: witnesses are signed inside the isolated signer or not at
		// all. An unsigned witness would be a divergence claim nobody can
		// verify offline, which is the class of evidence this system refuses
		// to produce.
		return fmt.Errorf("xrec runtime: signer is not configured, cannot witness disagreement")
	}
	left, right := planeState(d.Left), planeState(d.Right)
	body, err := witness.Build(witness.BuildRequest{
		RoundID:     d.RoundID,
		TenantID:    d.TenantID,
		SpecVersion: canon.SpecVersionV1,
		Left:        left,
		Right:       right,
		GeneratedAt: e.now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("xrec runtime: build witness: %w", err)
	}
	signed, err := witness.Sign(ctx, e.signer.Client(), body, "")
	if err != nil {
		return fmt.Errorf("xrec runtime: sign witness: %w", err)
	}
	evidence, err := witness.EvidenceFromSignedWitness(signed)
	if err != nil {
		return fmt.Errorf("xrec runtime: witness evidence: %w", err)
	}
	// The key is deterministic per (round, pair): a replayed or retried round
	// re-derives the same key and the ledger append no-ops (AN-5), so one
	// disagreement is one witness however many times the round is retried.
	pair := left.AuthorityID + ":" + right.AuthorityID
	if _, err := e.recorder.RecordWitness(ctx,
		"xrec-round-witness:"+d.RoundID+":"+pair,
		evidence, d.Left.Digest, d.Right.Digest); err != nil {
		return fmt.Errorf("xrec runtime: record witness: %w", err)
	}
	if e.quarantine != nil {
		// Witness in the ledger first, THEN admission: a quarantine decision
		// must always be explicable by a recorded witness, never the reverse.
		if _, err := e.quarantine.ObserveWitness(ctx,
			"xrec-round-quarantine:"+d.RoundID+":"+pair, evidence); err != nil {
			return fmt.Errorf("xrec runtime: quarantine observe witness: %w", err)
		}
	}
	return nil
}

func planeState(p rounds.PlaneObservation) witness.PlaneState {
	return witness.PlaneState{
		AuthorityID: p.Digest.Body.AuthorityID,
		Set:         p.Set,
		Tree:        p.Tree,
		Digest:      p.Digest,
	}
}
