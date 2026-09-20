// SPDX-License-Identifier: BUSL-1.1

// Package policy adds PCAS provenance around the PCAS-claim-23 policy decision that the
// signer already verifies (PCAS-claims-24, 40; supports INV-15's "no path bypasses
// auditability"). The core internal/policy OPA engine remains the decision engine;
// this package records and chains its outputs, in ee/.
//
//   - PCAS-claim-24: the signed policy decision is RECORDED (ledger event / translog
//     commitment) and the commitment's policy_ref is the DIGEST of that recorded
//     decision, so an auditor resolves commitment → recorded artifact.
//   - PCAS-claim-40: a finding ⟵ remediation-plan ⟵ policy-decision HASH CHAIN. The signer
//     verifies the authority signatures AND both digest bindings (decision→plan,
//     plan→finding) before successor keygen, so the in-signer decision is traceable
//     to the finding that occasioned it.
//
// All hashing/verification routes through the core internal/crypto AN-3 boundary.
package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Domain separators for each signed artifact. Frozen.
const (
	findingDomain  = "trstctl/pcas/provenance/finding/v1"
	planDomain     = "trstctl/pcas/provenance/plan/v1"
	decisionDomain = "trstctl/pcas/provenance/decision/v1"
)

// Errors.
var (
	ErrFindingSig          = errors.New("policy: finding authority signature invalid")
	ErrPlanSig             = errors.New("policy: plan authority signature invalid")
	ErrDecisionSig         = errors.New("policy: decision authority signature invalid")
	ErrPlanFindingBind     = errors.New("policy: plan does not bind the finding (plan→finding digest mismatch)")
	ErrDecisionPlanBind    = errors.New("policy: decision does not bind the plan (decision→plan digest mismatch)")
	ErrDecisionMismatch    = errors.New("policy: decision does not authorize this identity/target, or is a deny")
	ErrPolicyRefMismatch   = errors.New("policy: policy_ref is not the digest of the recorded decision")
	ErrDecisionNotRecorded = errors.New("policy: policy decision was not recorded")
	ErrChainDecode         = errors.New("policy: cannot decode provenance chain")
)

// Finding is a signed crypto finding: the origin of the provenance chain.
type Finding struct {
	FindingID  string `json:"finding_id"`
	IdentityID string `json:"identity_id"`
	TenantID   string `json:"tenant_id"`
	Algorithm  string `json:"algorithm"`
	Reason     string `json:"reason"`
	ObservedAt int64  `json:"observed_at"`
}

// Plan is a remediation plan that binds its finding by digest.
type Plan struct {
	PlanID          string `json:"plan_id"`
	IdentityID      string `json:"identity_id"`
	TenantID        string `json:"tenant_id"`
	FindingDigest   []byte `json:"finding_digest"`
	TargetAlgorithm string `json:"target_algorithm"`
	CreatedAt       int64  `json:"created_at"`
}

// Decision is a policy decision that binds its plan by digest.
type Decision struct {
	DecisionID      string `json:"decision_id"`
	IdentityID      string `json:"identity_id"`
	TenantID        string `json:"tenant_id"`
	PlanDigest      []byte `json:"plan_digest"`
	TargetAlgorithm string `json:"target_algorithm"`
	Allow           bool   `json:"allow"`
	DecidedAt       int64  `json:"decided_at"`
}

// Signed* wrap a content object with the signing authority id and its signature over
// the content's domain-separated message.
type SignedFinding struct {
	Finding     Finding `json:"finding"`
	AuthorityID string  `json:"authority_id"`
	Signature   []byte  `json:"sig"`
}
type SignedPlan struct {
	Plan        Plan   `json:"plan"`
	AuthorityID string `json:"authority_id"`
	Signature   []byte `json:"sig"`
}
type SignedDecision struct {
	Decision    Decision `json:"decision"`
	AuthorityID string   `json:"authority_id"`
	Signature   []byte   `json:"sig"`
}

// PlanChain is the full finding ⟵ plan ⟵ decision provenance triple.
type PlanChain struct {
	Finding  SignedFinding  `json:"finding"`
	Plan     SignedPlan     `json:"plan"`
	Decision SignedDecision `json:"decision"`
}

// --- messages + digests -----------------------------------------------------

func findingMessage(f Finding) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(findingDomain))
	writeField(&b, []byte(f.FindingID))
	writeField(&b, []byte(f.IdentityID))
	writeField(&b, []byte(f.TenantID))
	writeField(&b, []byte(f.Algorithm))
	writeField(&b, []byte(f.Reason))
	writeInt(&b, f.ObservedAt)
	return b.Bytes()
}

func planMessage(p Plan) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(planDomain))
	writeField(&b, []byte(p.PlanID))
	writeField(&b, []byte(p.IdentityID))
	writeField(&b, []byte(p.TenantID))
	writeField(&b, p.FindingDigest)
	writeField(&b, []byte(p.TargetAlgorithm))
	writeInt(&b, p.CreatedAt)
	return b.Bytes()
}

func decisionMessage(d Decision) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(decisionDomain))
	writeField(&b, []byte(d.DecisionID))
	writeField(&b, []byte(d.IdentityID))
	writeField(&b, []byte(d.TenantID))
	writeField(&b, d.PlanDigest)
	writeField(&b, []byte(d.TargetAlgorithm))
	if d.Allow {
		writeUint(&b, 1)
	} else {
		writeUint(&b, 0)
	}
	writeInt(&b, d.DecidedAt)
	return b.Bytes()
}

// FindingDigest / PlanDigest / DecisionDigest are the digests of the SIGNED artifacts
// (content message + authority id + signature), so a digest binds the exact recorded
// artifact including who signed it.
func FindingDigest(sf SignedFinding) []byte {
	return signedDigest(findingMessage(sf.Finding), sf.AuthorityID, sf.Signature)
}
func PlanDigest(sp SignedPlan) []byte {
	return signedDigest(planMessage(sp.Plan), sp.AuthorityID, sp.Signature)
}
func DecisionDigest(sd SignedDecision) []byte {
	return signedDigest(decisionMessage(sd.Decision), sd.AuthorityID, sd.Signature)
}

func signedDigest(msg []byte, authorityID string, sig []byte) []byte {
	var b bytes.Buffer
	writeField(&b, msg)
	writeField(&b, []byte(authorityID))
	writeField(&b, sig)
	return crypto.SHA256Sum(b.Bytes())
}

// PolicyRef is the value bound into the commitment: the digest of the recorded
// (signed) decision, hex-encoded (PCAS-claim-24). An auditor resolves commitment.policy_ref
// → this recorded decision.
func PolicyRef(chain PlanChain) string {
	return "sha256:" + hex.EncodeToString(DecisionDigest(chain.Decision))
}

// --- signing helpers (producers) --------------------------------------------

// SignFinding / SignPlan / SignDecision sign the content with the given authority.
func SignFinding(authority crypto.Signer, authorityID string, f Finding) (SignedFinding, error) {
	sig, err := authority.Sign(findingMessage(f), crypto.SignOptions{Hash: crypto.SHA256})
	return SignedFinding{Finding: f, AuthorityID: authorityID, Signature: sig}, err
}
func SignPlan(authority crypto.Signer, authorityID string, p Plan) (SignedPlan, error) {
	sig, err := authority.Sign(planMessage(p), crypto.SignOptions{Hash: crypto.SHA256})
	return SignedPlan{Plan: p, AuthorityID: authorityID, Signature: sig}, err
}
func SignDecision(authority crypto.Signer, authorityID string, d Decision) (SignedDecision, error) {
	sig, err := authority.Sign(decisionMessage(d), crypto.SignOptions{Hash: crypto.SHA256})
	return SignedDecision{Decision: d, AuthorityID: authorityID, Signature: sig}, err
}

// EncodeChain / DecodeChain serialize a plan chain for carriage in a mint request.
func EncodeChain(c PlanChain) ([]byte, error) { return json.Marshal(c) }
func DecodeChain(b []byte) (PlanChain, error) {
	var c PlanChain
	if err := json.Unmarshal(b, &c); err != nil {
		return PlanChain{}, fmt.Errorf("%w: %v", ErrChainDecode, err)
	}
	return c, nil
}

// --- verification -----------------------------------------------------------

// VerifyChain verifies the full provenance chain: each authority signature, and both
// digest bindings (plan→finding and decision→plan). This is the hash chain that makes
// the decision traceable to the finding (PCAS-claim-40).
func VerifyChain(chain PlanChain, findingAuthorityDER, planAuthorityDER, decisionAuthorityDER []byte) error {
	if crypto.VerifyMessage(findingAuthorityDER, findingMessage(chain.Finding.Finding), chain.Finding.Signature) != nil {
		return ErrFindingSig
	}
	if crypto.VerifyMessage(planAuthorityDER, planMessage(chain.Plan.Plan), chain.Plan.Signature) != nil {
		return ErrPlanSig
	}
	if !bytes.Equal(chain.Plan.Plan.FindingDigest, FindingDigest(chain.Finding)) {
		return ErrPlanFindingBind
	}
	if crypto.VerifyMessage(decisionAuthorityDER, decisionMessage(chain.Decision.Decision), chain.Decision.Signature) != nil {
		return ErrDecisionSig
	}
	if !bytes.Equal(chain.Decision.Decision.PlanDigest, PlanDigest(chain.Plan)) {
		return ErrDecisionPlanBind
	}
	return nil
}

// TraceToFinding resolves a published record's policy_ref back to its finding: it
// checks that policyRef is the digest of the chain's recorded decision, verifies the
// chain's digest bindings, and returns the originating finding (PCAS-claim-40). The signing
// authorities are supplied by the auditor out of band.
func TraceToFinding(policyRef string, chain PlanChain, findingAuthorityDER, planAuthorityDER, decisionAuthorityDER []byte) (Finding, error) {
	if policyRef != PolicyRef(chain) {
		return Finding{}, ErrPolicyRefMismatch
	}
	if err := VerifyChain(chain, findingAuthorityDER, planAuthorityDER, decisionAuthorityDER); err != nil {
		return Finding{}, err
	}
	return chain.Finding.Finding, nil
}

func writeField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}

func writeUint(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

// writeInt appends v in the same frozen 8-byte big-endian two's-complement encoding
// writeUint produces for the corresponding unsigned bit pattern. The bytes are masked
// out of v directly instead of round-tripping through an unsigned conversion: >> on a
// signed value sign-extends and & 0xFF keeps the low 8 bits, so each byte is exactly
// the two's-complement octet. Signed-message encodings are frozen; see
// TestWriteInt_TwosComplementBytes for the byte-for-byte boundary vectors.
func writeInt(b *bytes.Buffer, v int64) {
	x := [8]byte{
		byte(v >> 56 & 0xFF),
		byte(v >> 48 & 0xFF),
		byte(v >> 40 & 0xFF),
		byte(v >> 32 & 0xFF),
		byte(v >> 24 & 0xFF),
		byte(v >> 16 & 0xFF),
		byte(v >> 8 & 0xFF),
		byte(v & 0xFF),
	}
	b.Write(x[:])
}
