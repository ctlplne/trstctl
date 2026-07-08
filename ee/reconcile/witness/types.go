// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	ClassPresence          = "presence"
	ClassAttributeConflict = "attribute_conflict"
	ClassPolicyViolation   = "policy_violation"
	ClassStaleness         = "staleness"
)

type PlaneState struct {
	AuthorityID string
	Set         canon.Set
	Tree        *digest.Tree
	Digest      digest.SignedDigest
}

type BuildRequest struct {
	RoundID     string
	TenantID    string
	SpecVersion string
	Left        PlaneState
	Right       PlaneState
	GeneratedAt int64

	PolicyViolations []PolicyViolation
	Staleness        []Staleness
}

type PolicyViolation struct {
	AuthorityID   string
	RecordKey     canon.RecordKey
	RuleID        string
	PolicySetHash []byte
}

type Staleness struct {
	AuthorityID string
	Reason      string
	Watermark   digest.Watermark
	LivenessSec int64
}

type Body struct {
	WitnessID   string      `json:"witness_id"`
	RoundID     string      `json:"round_id"`
	TenantID    string      `json:"tenant_id"`
	SpecVersion string      `json:"spec_version"`
	DigestRefs  []DigestRef `json:"digest_refs"`
	Entries     []Entry     `json:"entries"`
	GeneratedAt int64       `json:"generated_at"`
}

type DigestRef struct {
	AuthorityID  string           `json:"authority_id"`
	DigestHash   []byte           `json:"digest_hash"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
	Watermark    digest.Watermark `json:"watermark"`
}

type Entry struct {
	RecordKey        canon.RecordKey     `json:"record_key,omitempty"`
	Class            string              `json:"class"`
	PresentAuthority string              `json:"present_authority,omitempty"`
	Inclusions       []InclusionProofRef `json:"inclusions,omitempty"`
	Absence          *AbsenceProof       `json:"absence,omitempty"`
	DisclosedRecords []DisclosedRecord   `json:"disclosed_records,omitempty"`
	Policy           *PolicyEvidence     `json:"policy,omitempty"`
	Staleness        *StalenessEvidence  `json:"staleness,omitempty"`
}

type InclusionProofRef struct {
	AuthorityID string         `json:"authority_id"`
	Proof       InclusionProof `json:"proof"`
}

type DisclosedRecord struct {
	AuthorityID          string          `json:"authority_id"`
	RecordKey            canon.RecordKey `json:"record_key"`
	CanonicalRecordBytes []byte          `json:"canonical_record_bytes"`
}

type PolicyEvidence struct {
	AuthorityID   string          `json:"authority_id"`
	RuleID        string          `json:"rule_id"`
	PolicySetHash []byte          `json:"policy_set_hash"`
	RecordKey     canon.RecordKey `json:"record_key"`
}

type StalenessEvidence struct {
	AuthorityID string           `json:"authority_id"`
	Reason      string           `json:"reason"`
	Watermark   digest.Watermark `json:"watermark"`
	LivenessSec int64            `json:"liveness_sec"`
}

type SignedWitness struct {
	Body         Body
	WitnessHash  []byte
	AuthorityID  string
	KeyID        string
	Algorithm    crypto.Algorithm
	PublicKeyDER []byte
	Signature    []byte
	SignedAt     time.Time
}
