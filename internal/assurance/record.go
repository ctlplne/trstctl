// SPDX-License-Identifier: BUSL-1.1

// Package assurance builds a credential's lifecycle assurance record (A179):
// one signed, offline-verifiable document joining every stage of a
// certificate's life — discovery, ownership, issuance, each deployment and
// verification, renewals, revocation — with the evidence behind each, and
// saying for each stage whether trstctl recorded it or independently observed
// it.
package assurance

import (
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// Format names the record's schema.
const Format = "trstctl.credential-assurance-record/v1"

// Basis is how a stage's evidence is known.
type Basis string

const (
	// BasisRecorded is trstctl's record of its own action, or an operator's
	// statement: an issuance, a delivery a connector reported, a renewal run.
	BasisRecorded Basis = "recorded"
	// BasisObserved was read from outside trstctl's own record: a discovery
	// scan found the certificate, an endpoint was seen serving it.
	BasisObserved Basis = "observed"
	// BasisSignedObservation was observed by an agent or relay whose signed
	// receipt the server verified.
	BasisSignedObservation Basis = "signed_observation"
)

// The stages a record covers, in lifecycle order.
const (
	StageDiscovery    = "discovery"
	StageOwner        = "owner"
	StageIssuance     = "issuance"
	StageDeployment   = "deployment"
	StageVerification = "verification"
	StageRenewal      = "renewal"
	StageRevocation   = "revocation"
)

// Stages is every stage, in order.
var Stages = []string{StageDiscovery, StageOwner, StageIssuance, StageDeployment, StageVerification, StageRenewal, StageRevocation}

// Record is one credential's assurance record.
type Record struct {
	Format        string           `json:"format"`
	TenantID      string           `json:"tenant_id"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Credential    Credential       `json:"credential"`
	Discovery     []Discovery      `json:"discovery"`
	Owner         *Owner           `json:"owner"`
	Issuance      Issuance         `json:"issuance"`
	Deployments   []Deployment     `json:"deployments"`
	Verifications []Verification   `json:"verifications"`
	Renewals      Renewals         `json:"renewals"`
	Revocation    *Revocation      `json:"revocation"`
	Audit         []AuditReference `json:"audit"`
	// IndependentlyObserved names the stages with evidence from outside
	// trstctl's own record; RecordedOnly the stages known only from it;
	// Absent the stages with no evidence at all.
	IndependentlyObserved []string `json:"independently_observed"`
	RecordedOnly          []string `json:"recorded_only"`
	Absent                []string `json:"absent"`
	// Truncated names any evidence list that hit its bound.
	Truncated []string `json:"truncated"`
}

// Credential identifies the certificate.
type Credential struct {
	CertificateID string     `json:"certificate_id"`
	Fingerprint   string     `json:"fingerprint"`
	Serial        string     `json:"serial"`
	Subject       string     `json:"subject"`
	SANs          []string   `json:"sans"`
	Issuer        string     `json:"issuer"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	Status        string     `json:"status"`
	// IdentityIDs are the lifecycle identities its issuance and delivery
	// evidence binds it to.
	IdentityIDs []string `json:"identity_ids"`
}

// Discovery is one observation of the certificate by a discovery source.
type Discovery struct {
	EvidenceID string    `json:"evidence_id"`
	Basis      Basis     `json:"basis"`
	Source     string    `json:"source"`
	SourceKind string    `json:"source_kind"`
	Location   string    `json:"location"`
	Provenance string    `json:"provenance,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// Owner is the certificate's recorded owner.
type Owner struct {
	EvidenceID string `json:"evidence_id"`
	Basis      Basis  `json:"basis"`
	OwnerID    string `json:"owner_id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
}

// Issuance is how the certificate came to exist.
type Issuance struct {
	EvidenceID string `json:"evidence_id"`
	Basis      Basis  `json:"basis"`
	// IssuedByTrstctl is false for a certificate trstctl only imported or
	// discovered; then CA is the issuer it names and nothing else is known.
	IssuedByTrstctl bool       `json:"issued_by_trstctl"`
	Source          string     `json:"source"`
	CA              string     `json:"ca"`
	ExternalCAID    string     `json:"external_ca_id,omitempty"`
	IssuedAt        *time.Time `json:"issued_at,omitempty"`
	KeyOrigin       string     `json:"key_origin,omitempty"`
	Profile         *Profile   `json:"profile,omitempty"`
	Approval        *Approval  `json:"approval,omitempty"`
}

// Profile is the certificate profile revision an issuance was bound to.
type Profile struct {
	EvidenceID string `json:"evidence_id"`
	Name       string `json:"name"`
	Version    int    `json:"version"`
	SpecDigest string `json:"spec_digest"`
}

// Approval is the dual-control approval an issuance consumed.
type Approval struct {
	EvidenceID        string `json:"evidence_id"`
	RequestID         string `json:"request_id"`
	IntentDigest      string `json:"intent_digest"`
	Requester         string `json:"requester"`
	RequiredApprovals int    `json:"required_approvals"`
}

// Deployment is one connector delivery of the certificate.
type Deployment struct {
	EvidenceID  string    `json:"evidence_id"`
	Basis       Basis     `json:"basis"`
	IdentityID  string    `json:"identity_id,omitempty"`
	Destination string    `json:"destination"`
	Connector   string    `json:"connector"`
	Target      string    `json:"target"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	RollbackRef string    `json:"rollback_ref,omitempty"`
	At          time.Time `json:"at"`
}

// Verification is one check of what an endpoint serves.
type Verification struct {
	EvidenceID string `json:"evidence_id"`
	Basis      Basis  `json:"basis"`
	// Vantage is local (the serving host's agent), relay (a network agent),
	// or connector (the delivering connector's own readback).
	Vantage  string `json:"vantage"`
	Agent    string `json:"agent,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Address  string `json:"address,omitempty"`
	Target   string `json:"target,omitempty"`
	Outcome  string `json:"outcome"`
	// ServedFingerprint is what the endpoint served; empty when it was not
	// reached or the evidence names only the expected certificate.
	ExpectedFingerprint string    `json:"expected_fingerprint"`
	ServedFingerprint   string    `json:"served_fingerprint,omitempty"`
	Mismatch            string    `json:"mismatch,omitempty"`
	CheckedSANs         bool      `json:"checked_sans"`
	CheckedChain        bool      `json:"checked_chain"`
	TranscriptDigest    string    `json:"transcript_digest,omitempty"`
	SignerFingerprint   string    `json:"signer_fingerprint,omitempty"`
	At                  time.Time `json:"at"`
}

// Renewals links the certificate to what it replaced and what replaced it.
type Renewals struct {
	Predecessor *Link        `json:"predecessor,omitempty"`
	Successors  []Link       `json:"successors"`
	Runs        []RenewalRun `json:"runs"`
}

// Link identifies a related certificate.
type Link struct {
	CertificateID string     `json:"certificate_id"`
	Fingerprint   string     `json:"fingerprint"`
	Status        string     `json:"status"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
}

// RenewalRun is one lifecycle renewal this certificate entered or left.
type RenewalRun struct {
	EvidenceID             string     `json:"evidence_id"`
	Basis                  Basis      `json:"basis"`
	IdentityID             string     `json:"identity_id"`
	Role                   string     `json:"role"`
	Status                 string     `json:"status"`
	Trigger                string     `json:"trigger"`
	PredecessorFingerprint string     `json:"predecessor_fingerprint"`
	SuccessorFingerprint   string     `json:"successor_fingerprint"`
	StartedAt              time.Time  `json:"started_at"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
}

// Revocation is the certificate's revocation.
type Revocation struct {
	EvidenceID string    `json:"evidence_id"`
	Basis      Basis     `json:"basis"`
	RevokedAt  time.Time `json:"revoked_at"`
	Reason     string    `json:"reason"`
}

// AuditReference is one tenant audit-chain entry about the certificate.
type AuditReference struct {
	Sequence uint64    `json:"sequence"`
	EventID  string    `json:"event_id"`
	Type     string    `json:"type"`
	At       time.Time `json:"at"`
	Hash     string    `json:"hash"`
}

// IssuanceEvidence is the retained issuance binding behind a certificate, when
// one exists: the identity transition or certificate event that bound its
// profile revision and any approval it consumed.
type IssuanceEvidence struct {
	EventID  string
	Binding  *store.OperationApprovalIssuanceBinding
	Approval *store.OperationApprovalUse
}

// Inputs is what Build joins.
type Inputs struct {
	TenantID       string
	Now            time.Time
	Evidence       store.CredentialEvidence
	IdentityIDs    []string
	Issuance       IssuanceEvidence
	Audit          []AuditReference
	AuditTruncated bool
}

// Build joins one certificate's evidence into its record.
func Build(in Inputs) Record {
	cert := in.Evidence.Certificate
	r := Record{
		Format: Format, TenantID: in.TenantID, GeneratedAt: in.Now.UTC(),
		Credential: Credential{
			CertificateID: cert.ID, Fingerprint: cert.Fingerprint, Serial: cert.Serial, Subject: cert.Subject,
			SANs: nonNil(cert.SANs), Issuer: cert.Issuer, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
			Status: cert.Status, IdentityIDs: sortedUnique(in.IdentityIDs),
		},
		Discovery: []Discovery{}, Deployments: []Deployment{}, Verifications: []Verification{},
		Renewals: Renewals{Successors: []Link{}, Runs: []RenewalRun{}}, Audit: nonNilAudit(in.Audit),
		IndependentlyObserved: []string{}, RecordedOnly: []string{}, Absent: []string{},
		Truncated: append([]string{}, in.Evidence.Truncated...),
	}
	if in.AuditTruncated {
		r.Truncated = append(r.Truncated, "audit")
	}
	for _, d := range in.Evidence.Discoveries {
		r.Discovery = append(r.Discovery, Discovery{
			EvidenceID: "discovery-finding:" + d.FindingID, Basis: BasisObserved,
			Source: d.SourceName, SourceKind: d.SourceKind, Location: d.Ref, Provenance: d.Provenance,
			ObservedAt: d.DiscoveredAt.UTC(),
		})
	}
	if len(r.Discovery) == 0 && cert.LastSeenAt != nil && cert.ObservedBy != "" {
		// The inventory's own provenance: the last source that confirmed this
		// certificate exists, when no finding row survives.
		r.Discovery = append(r.Discovery, Discovery{
			EvidenceID: "certificate-observation:" + cert.ID, Basis: BasisObserved,
			Source: cert.ObservedBy, SourceKind: cert.ObservedKind, ObservedAt: cert.LastSeenAt.UTC(),
		})
	}
	if owner := in.Evidence.Owner; owner != nil {
		r.Owner = &Owner{EvidenceID: "owner:" + owner.ID, Basis: BasisRecorded, OwnerID: owner.ID, Name: owner.Name, Kind: string(owner.Kind)}
	}
	r.Issuance = issuance(cert, in.Issuance, in.Evidence.Rotations)
	for _, d := range in.Evidence.Deliveries {
		receipt := d.Receipt
		identityID := ""
		if receipt.IdentityID != nil {
			identityID = *receipt.IdentityID
		}
		if receipt.Status == "verified" || receipt.Status == "verify_failed" {
			v := Verification{
				EvidenceID: "connector-receipt:" + receipt.ID, Basis: BasisObserved, Vantage: "connector",
				Target: receipt.Target, Outcome: receipt.Status, ExpectedFingerprint: receipt.Fingerprint,
				At: receipt.UpdatedAt.UTC(),
			}
			if d.SignedBy != "" {
				v.Basis, v.Agent, v.SignerFingerprint = BasisSignedObservation, d.SignedBy, d.SignerFingerprint
				v.Vantage = "agent"
				if d.SignedObservedAt != nil {
					v.At = d.SignedObservedAt.UTC()
				}
			}
			if receipt.Status == "verified" {
				v.ServedFingerprint = receipt.Fingerprint
			}
			r.Verifications = append(r.Verifications, v)
			continue
		}
		r.Deployments = append(r.Deployments, Deployment{
			EvidenceID: "connector-receipt:" + receipt.ID, Basis: BasisRecorded, IdentityID: identityID,
			Destination: receipt.Destination, Connector: receipt.Connector, Target: receipt.Target,
			Status: receipt.Status, Reason: receipt.Reason, RollbackRef: receipt.RollbackRef, At: receipt.UpdatedAt.UTC(),
		})
	}
	for _, e := range in.Evidence.Endpoints {
		v := Verification{
			EvidenceID: "endpoint-verification:" + e.EndpointID + ":" + e.Vantage, Basis: BasisObserved,
			Vantage: e.Vantage, Agent: e.AgentCommonName, Endpoint: e.EndpointID, Address: e.Address,
			ExpectedFingerprint: e.ExpectedFingerprint, ServedFingerprint: e.ObservedFingerprint,
			Mismatch: e.Mismatch, CheckedSANs: e.CheckedSANs, CheckedChain: e.CheckedChain,
			TranscriptDigest: e.EvidenceDigest, At: e.LastCheckedAt.UTC(),
		}
		switch {
		case !e.Reached:
			v.Outcome = "unreachable"
		case e.Mismatch != "":
			v.Outcome = "mismatch"
		default:
			v.Outcome = "verified"
		}
		if e.EvidenceDigest != "" && e.AgentCommonName != "" {
			v.Basis = BasisSignedObservation
		}
		r.Verifications = append(r.Verifications, v)
	}
	if p := in.Evidence.Predecessor; p != nil {
		r.Renewals.Predecessor = &Link{CertificateID: p.ID, Fingerprint: p.Fingerprint, Status: p.Status, NotAfter: p.NotAfter}
	}
	for _, s := range in.Evidence.Successors {
		r.Renewals.Successors = append(r.Renewals.Successors, Link{CertificateID: s.ID, Fingerprint: s.Fingerprint, Status: s.Status, NotAfter: s.NotAfter})
	}
	for _, run := range in.Evidence.Rotations {
		role := "successor"
		if run.PredecessorFingerprint == cert.Fingerprint {
			role = "predecessor"
		}
		r.Renewals.Runs = append(r.Renewals.Runs, RenewalRun{
			EvidenceID: "rotation-run:" + run.ID, Basis: BasisRecorded, IdentityID: run.IdentityID, Role: role,
			Status: run.Status, Trigger: run.Trigger, PredecessorFingerprint: run.PredecessorFingerprint,
			SuccessorFingerprint: run.SuccessorFingerprint, StartedAt: run.CreatedAt.UTC(), CompletedAt: utcPtr(run.CompletedAt),
		})
	}
	if cert.RevokedAt != nil {
		r.Revocation = &Revocation{
			EvidenceID: "certificate-revocation:" + cert.ID, Basis: BasisRecorded,
			RevokedAt: cert.RevokedAt.UTC(), Reason: cert.RevocationReason,
		}
	}
	r.classifyStages()
	return r
}

// issuance names the strongest issuance evidence held: the certificate's own
// issuance event, else the transition event that decided the issuing command,
// else the renewal run that produced it, else only the inventory row.
func issuance(cert store.Certificate, evidence IssuanceEvidence, rotations []store.RotationRun) Issuance {
	issued := cert.IssuanceIdempotencyKey != "" || cert.Source == "issued"
	out := Issuance{
		EvidenceID: "certificate:" + cert.ID, Basis: BasisRecorded, IssuedByTrstctl: issued,
		Source: cert.Source, CA: cert.Issuer, ExternalCAID: cert.IssuingExternalCAID, KeyOrigin: cert.KeyOrigin,
	}
	switch {
	case cert.IssuanceEventID != "":
		out.EvidenceID = "event:" + cert.IssuanceEventID
	case evidence.EventID != "":
		out.EvidenceID = "event:" + evidence.EventID
	default:
		for _, run := range rotations {
			if run.SuccessorFingerprint == cert.Fingerprint && cert.Fingerprint != "" {
				out.EvidenceID = "rotation-run:" + run.ID
			}
		}
	}
	if issued {
		switch {
		case cert.ValidityAnchor != nil:
			out.IssuedAt = utcPtr(cert.ValidityAnchor)
		case !cert.CreatedAt.IsZero():
			at := cert.CreatedAt.UTC()
			out.IssuedAt = &at
		}
	}
	binding := evidence.Binding
	if binding == nil && evidence.Approval != nil {
		binding = evidence.Approval.Issuance
	}
	if binding != nil && binding.ProfileName != "" {
		out.Profile = &Profile{
			EvidenceID: "event:" + evidence.EventID, Name: binding.ProfileName,
			Version: binding.ProfileVersion, SpecDigest: binding.ProfileSpecDigest,
		}
	}
	if a := evidence.Approval; a != nil && a.RequestID != "" {
		out.Approval = &Approval{
			EvidenceID: "operation-approval:" + a.RequestID, RequestID: a.RequestID, IntentDigest: a.IntentDigest,
			Requester: a.Requester, RequiredApprovals: a.RequiredApprovals,
		}
	}
	return out
}

// classifyStages states, for each stage, whether anything outside trstctl's
// own record observed it.
func (r *Record) classifyStages() {
	served := false
	for _, v := range r.Verifications {
		if v.Outcome == "verified" && v.ServedFingerprint == r.Credential.Fingerprint {
			served = true
		}
	}
	present := map[string]bool{
		StageDiscovery: len(r.Discovery) > 0, StageOwner: r.Owner != nil, StageIssuance: true,
		StageDeployment: len(r.Deployments) > 0, StageVerification: len(r.Verifications) > 0,
		StageRenewal:    r.Renewals.Predecessor != nil || len(r.Renewals.Successors) > 0 || len(r.Renewals.Runs) > 0,
		StageRevocation: r.Revocation != nil,
	}
	observed := map[string]bool{
		StageDiscovery: len(r.Discovery) > 0,
		// A delivery is independently observed only when an endpoint was then
		// seen serving this certificate.
		StageDeployment:   len(r.Deployments) > 0 && served,
		StageVerification: served,
	}
	for _, stage := range Stages {
		switch {
		case !present[stage]:
			r.Absent = append(r.Absent, stage)
		case observed[stage]:
			r.IndependentlyObserved = append(r.IndependentlyObserved, stage)
		default:
			r.RecordedOnly = append(r.RecordedOnly, stage)
		}
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}

func nonNilAudit(values []AuditReference) []AuditReference {
	if values == nil {
		return []AuditReference{}
	}
	return append([]AuditReference(nil), values...)
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}
