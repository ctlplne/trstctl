// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package monitor turns the PCAS detection primitives into reachable monitors over the
// AN-2 ledger (INT-19). The misissuance monitor scans dual-signed succession records
// for an algorithm-epoch equivocation — two distinct records for one identity at the
// same epoch (PCAS-claims-11, 28) — and, on detection, emits a durable, attributable
// misissuance event binding both record commitments and, where the records carry
// verifiable signer attestations, the named minting signers. The emitted proof is
// self-contained: a third party re-derives it from the two records alone.
package monitor

import (
	"bytes"
	"context"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/translog"
	"trstctl.com/trstctl/internal/events"
)

// EventAppender is the AN-2 ledger sink the monitor emits misissuance events to.
// *events.Log satisfies it; a nil ledger makes Scan build the event without persisting.
type EventAppender interface {
	Append(ctx context.Context, e events.Event) (events.Event, error)
}

// MisissuanceMonitor scans succession records for the first algorithm-epoch
// equivocation and emits a durable misissuance event naming the minting signers.
type MisissuanceMonitor struct {
	roster map[string][]byte // signer attestation keys, for attribution (PCAS-claim-28)
	ledger EventAppender
}

// New returns a misissuance monitor. roster maps signer id -> attestation public key
// (SubjectPublicKeyInfo DER); ledger may be nil (build-only, no persistence).
func New(roster map[string][]byte, ledger EventAppender) *MisissuanceMonitor {
	return &MisissuanceMonitor{roster: roster, ledger: ledger}
}

// Detection is a detected equivocation: the self-contained proof, the (best-effort)
// named minting signers, and the emitted ledger event.
type Detection struct {
	Proof   translog.MisissuanceProof
	SignerA string
	SignerB string
	Event   events.Event
}

// Scan checks records for the FIRST algorithm-epoch equivocation. On detection it
// builds a self-verifying misissuance proof (both records must be independently valid),
// names the minting signers from the roster (best-effort — the proof stands without
// them), emits a MisissuanceV1 ledger event, and returns the detection with ok=true.
// With no equivocation it emits nothing and returns ok=false, so it is safe to run
// repeatedly over an append-only stream.
func (m *MisissuanceMonitor) Scan(ctx context.Context, records []succession.SuccessionRecord) (Detection, bool, error) {
	type key struct {
		id    string
		epoch uint64
	}
	firstRecord := map[key]succession.SuccessionRecord{}
	firstCommit := map[key][]byte{}

	for _, rec := range records {
		k := key{rec.Fields.IdentityID, rec.Fields.Epoch}
		c, err := succession.Commit(rec.Fields)
		if err != nil {
			continue
		}
		prevCommit, seen := firstCommit[k]
		if !seen {
			firstRecord[k] = rec
			firstCommit[k] = c
			continue
		}
		if bytes.Equal(prevCommit, c) {
			continue // identical content at the same epoch: a duplicate, not an equivocation
		}

		// Equivocation: two distinct records for one identity at one epoch.
		proof, err := translog.BuildMisissuanceProof(firstRecord[k], rec)
		if err != nil {
			return Detection{}, false, fmt.Errorf("monitor: build misissuance proof: %w", err)
		}
		det := Detection{Proof: proof}
		if sa, sb, nerr := proof.NamesMintingSigners(m.roster); nerr == nil {
			det.SignerA, det.SignerB = sa, sb
		}
		ev, err := m.emit(ctx, proof, det)
		if err != nil {
			return Detection{}, false, err
		}
		det.Event = ev
		return det, true, nil
	}
	return Detection{}, false, nil
}

func (m *MisissuanceMonitor) emit(ctx context.Context, proof translog.MisissuanceProof, det Detection) (events.Event, error) {
	da, err := succession.Commit(proof.RecordA.Fields)
	if err != nil {
		return events.Event{}, err
	}
	db, err := succession.Commit(proof.RecordB.Fields)
	if err != nil {
		return events.Event{}, err
	}
	ev, err := succession.Encode(succession.MisissuanceV1{
		IdentityID:    proof.RecordA.Fields.IdentityID,
		TenantID:      proof.RecordA.Fields.TenantID,
		Epoch:         proof.RecordA.Fields.Epoch,
		RecordADigest: da,
		RecordBDigest: db,
		SignerA:       det.SignerA,
		SignerB:       det.SignerB,
	})
	if err != nil {
		return events.Event{}, fmt.Errorf("monitor: encode misissuance event: %w", err)
	}
	if m.ledger == nil {
		return ev, nil
	}
	appended, err := m.ledger.Append(ctx, ev)
	if err != nil {
		return events.Event{}, fmt.Errorf("monitor: append misissuance event: %w", err)
	}
	return appended, nil
}
