// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package rpverify is the proprietary relying-party verifier for PCAS succession
// chains (independent claim 13). It verifies a chain OFFLINE: no algorithm
// negotiation, no runtime cryptographic-provider load, and no network fetch — the
// caller supplies the chain. Verification primitives come from ee/succession
// (PCAS-04) and ee/translog (PCAS-06); all hashing and signature verification
// route through the core internal/crypto AN-3 boundary.
//
// LICENSE (HARNESS §1.6.4, decision 2026-07-05): this package is proprietary
// LicenseRef-trstctl-EE so that NO MPL patent grant attaches to independent claim
// 13. It is deliberately NOT in MPL core, and it is NOT the internal/license
// offline license checker (a different thing that AGENTS.md keeps in core).
package rpverify

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/ee/translog"
	"trstctl.com/trstctl/internal/crypto"
)

// Verification errors.
var (
	ErrWrongTenant       = errors.New("rpverify: record tenant does not match the expected tenant")
	ErrInclusionRequired = errors.New("rpverify: transparency-log inclusion proof required but missing")
	ErrInclusionInvalid  = errors.New("rpverify: transparency-log inclusion proof invalid")
	ErrPreCRQC           = errors.New("rpverify: classical-predecessor record lacks a pre-cryptanalysis-relevance log timestamp")
	ErrOverlapClosed     = errors.New("rpverify: predecessor credential rejected (overlap window closed / fail-closed)")
)

// EpochStore is the caller-supplied durable last-accepted-epoch state per identity
// (claim 13). The verifier reads it before accepting a chain and advances it on
// success, so a stale or downgraded chain is refused even across a verifier
// restart. A nil store disables the discipline (single-shot verification).
type EpochStore interface {
	LastAccepted(identityID string) (epoch uint64, ok bool, err error)
	SetLastAccepted(identityID string, epoch uint64) error
}

// InclusionEvidence is a transparency-log inclusion proof for one record: the STH
// it is proven under, the audit path, and the leaf index. The verified leaf is the
// record's commitment (a canonical per-record identifier).
type InclusionEvidence struct {
	STH   translog.STH
	Proof [][]byte
	Index int
}

// Options configure verification policy. The absence of any negotiation or
// provider-selection option is deliberate — it is the design-around.
type Options struct {
	ExpectedTenant   string
	RequireInclusion bool
	STHVerifyKeyDER  []byte // when set, each inclusion STH's signature is checked
	PreCRQCBefore    int64  // classical-predecessor records need a log timestamp < this (unix nanos); 0 disables
}

// Input is everything the relying party needs, supplied by the caller (no network
// fetch): the genesis anchor + trust-root key, the succession chain, and optional
// per-record inclusion evidence (index-aligned with Chain).
type Input struct {
	TrustRootPubDER []byte
	Genesis         succession.GenesisRecord
	Chain           []succession.SuccessionRecord
	Inclusion       []InclusionEvidence
}

// Result is the current cryptographic posture the verifier selected.
type Result struct {
	Algorithm crypto.Algorithm
	PublicDER []byte
	Epoch     uint64
}

// classical registry algorithms (pre-quantum). Used only to decide which records
// require a pre-CRQC log timestamp (claim 18).
var classical = map[crypto.Algorithm]bool{
	crypto.RSA2048: true, crypto.RSA3072: true, crypto.RSA4096: true,
	crypto.ECDSAP256: true, crypto.ECDSAP384: true, crypto.ECDSAP521: true, crypto.Ed25519: true,
}

// Verify verifies the chain offline and, on success, advances the last-accepted
// epoch for the identity. It performs no algorithm negotiation and loads no
// runtime provider (claim 13 / INV-6).
func Verify(in Input, store EpochStore, opts Options) (Result, error) {
	if err := succession.VerifyGenesis(in.TrustRootPubDER, in.Genesis); err != nil {
		return Result{}, err
	}
	if opts.ExpectedTenant != "" && in.Genesis.TenantID != opts.ExpectedTenant {
		return Result{}, fmt.Errorf("%w: genesis tenant %q", ErrWrongTenant, in.Genesis.TenantID)
	}
	identity := in.Genesis.IdentityID

	var last uint64
	if store != nil {
		l, ok, err := store.LastAccepted(identity)
		if err != nil {
			return Result{}, err
		}
		if ok {
			last = l
		}
	}

	// Dual signatures + monotonic epoch + linkage + genesis anchor + downgrade vs
	// the durable last-accepted epoch (PCAS-04 VerifyChain).
	if err := succession.VerifyChain(in.Genesis, in.Chain, last); err != nil {
		return Result{}, err
	}

	if opts.RequireInclusion && len(in.Inclusion) != len(in.Chain) {
		return Result{}, ErrInclusionRequired
	}
	for i, rec := range in.Chain {
		if opts.ExpectedTenant != "" && rec.Fields.TenantID != opts.ExpectedTenant {
			return Result{}, fmt.Errorf("%w: record %d tenant %q", ErrWrongTenant, i, rec.Fields.TenantID)
		}
		if opts.RequireInclusion {
			if err := verifyInclusion(rec, in.Inclusion[i], opts); err != nil {
				return Result{}, err
			}
		}
	}

	res := Result{Algorithm: in.Genesis.Algorithm, PublicDER: in.Genesis.PublicKey, Epoch: in.Genesis.Epoch}
	if n := len(in.Chain); n > 0 {
		head := in.Chain[n-1]
		res = Result{Algorithm: head.Fields.SuccessorAlg, PublicDER: head.Fields.SuccessorPub, Epoch: head.Fields.Epoch}
	}
	if store != nil {
		if err := store.SetLastAccepted(identity, res.Epoch); err != nil {
			return Result{}, err
		}
	}
	return res, nil
}

func verifyInclusion(rec succession.SuccessionRecord, ev InclusionEvidence, opts Options) error {
	leaf, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	if len(opts.STHVerifyKeyDER) > 0 {
		if err := translog.VerifySTH(opts.STHVerifyKeyDER, ev.STH); err != nil {
			return fmt.Errorf("%w: STH signature: %v", ErrInclusionInvalid, err)
		}
	}
	if !translog.VerifyInclusion(leaf, ev.Index, ev.STH.TreeSize, ev.Proof, ev.STH.RootHash) {
		return ErrInclusionInvalid
	}
	if opts.PreCRQCBefore > 0 && classical[rec.Fields.PredecessorAlg] {
		if ev.STH.Timestamp >= opts.PreCRQCBefore {
			return fmt.Errorf("%w: timestamp %d >= %d", ErrPreCRQC, ev.STH.Timestamp, opts.PreCRQCBefore)
		}
	}
	return nil
}

// AcceptPresentedEpoch enforces the hybrid-overlap acceptance rule: the current
// head epoch is always acceptable; the immediate predecessor (head-1) is
// acceptable only while an overlap window is open; anything older, or the
// predecessor once the window closes, fails closed (r11 verification semantics).
func AcceptPresentedEpoch(head, presented uint64, overlapOpen bool) error {
	if presented == head {
		return nil
	}
	if overlapOpen && presented+1 == head {
		return nil
	}
	return fmt.Errorf("%w: presented epoch %d, head %d, overlapOpen=%v", ErrOverlapClosed, presented, head, overlapOpen)
}
