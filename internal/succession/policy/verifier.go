// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"encoding/hex"
	"sync"

	"trstctl.com/trstctl/internal/signing"
)

// DecisionLedger records signed policy decisions and reports whether a decision (by
// its digest) was recorded (PCAS-claim-24). In production it is backed by the AN-2 ledger
// / transparency log; a decision must be recorded before or with the mint.
type DecisionLedger interface {
	Record(sd SignedDecision) error
	IsRecorded(decisionDigest []byte) (bool, error)
}

// ProvenanceVerifier is the in-signer plan-chain check (PCAS-claims-24, 40). It decodes the
// provenance chain carried in the request's PolicyDecision, verifies the authority
// signatures and both digest bindings, checks the decision authorizes the request's
// (identity, target), checks the request's policy_ref equals the recorded-decision
// digest, and — when a ledger is configured — that the decision was recorded. The
// minter runs it BEFORE successor keygen.
type ProvenanceVerifier struct {
	FindingAuthorityDER  []byte
	PlanAuthorityDER     []byte
	DecisionAuthorityDER []byte
	Recorded             DecisionLedger // optional; when set, the decision must be recorded
}

// Verify implements the minter's plan-provenance seam.
func (v ProvenanceVerifier) Verify(req signing.MintRequest) error {
	chain, err := DecodeChain(req.PolicyDecision)
	if err != nil {
		return err
	}
	if err := VerifyChain(chain, v.FindingAuthorityDER, v.PlanAuthorityDER, v.DecisionAuthorityDER); err != nil {
		return err
	}
	d := chain.Decision.Decision
	if !d.Allow || d.IdentityID != req.IdentityID || d.TargetAlgorithm != string(req.TargetAlgorithm) {
		return ErrDecisionMismatch
	}
	if req.PolicyRef != PolicyRef(chain) {
		return ErrPolicyRefMismatch
	}
	if v.Recorded != nil {
		ok, err := v.Recorded.IsRecorded(DecisionDigest(chain.Decision))
		if err != nil {
			return err
		}
		if !ok {
			return ErrDecisionNotRecorded
		}
	}
	return nil
}

// MemDecisionLedger is an in-memory DecisionLedger for tests and single-node use.
type MemDecisionLedger struct {
	mu       sync.Mutex
	recorded map[string]SignedDecision
}

// NewMemDecisionLedger builds an empty ledger.
func NewMemDecisionLedger() *MemDecisionLedger {
	return &MemDecisionLedger{recorded: map[string]SignedDecision{}}
}

// Record stores a signed decision keyed by its digest.
func (l *MemDecisionLedger) Record(sd SignedDecision) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recorded[hex.EncodeToString(DecisionDigest(sd))] = sd
	return nil
}

// IsRecorded reports whether a decision with digest was recorded.
func (l *MemDecisionLedger) IsRecorded(decisionDigest []byte) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.recorded[hex.EncodeToString(decisionDigest)]
	return ok, nil
}

// Get resolves a recorded decision by digest — the "queryable from the ledger" side
// of PCAS-claim-24 (an auditor resolves policy_ref → recorded artifact).
func (l *MemDecisionLedger) Get(decisionDigest []byte) (SignedDecision, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sd, ok := l.recorded[hex.EncodeToString(decisionDigest)]
	return sd, ok
}
