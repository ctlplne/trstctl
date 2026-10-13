// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"time"

	"trstctl.com/trstctl/internal/breakglass"
)

// BreakglassReconcileEventSchemaVersion adds the exact signed-bundle digest to
// the offline reconciliation audit. Historical v1 offline/online envelopes keep
// their closed shapes during replay and privacy rewrites.
const BreakglassReconcileEventSchemaVersion = 2
const BreakglassOfflineEvidenceEventSchemaVersion = 3

// The offline reconciler records only verified public facts, while the online
// issuer retains the signed bundle so an interrupted response can be recovered
// from the event log. Both formats already use breakglass.issued v1. Keep their
// alternatives closed and distinct rather than accepting an arbitrary object.
type privacyBreakglassIssuedOffline struct {
	RequestID string    `json:"request_id"`
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	IssuedAt  time.Time `json:"issued_at"`
	Approvals int       `json:"approvals"`
}

type privacyBreakglassIssuedReconciledV2 struct {
	RequestID    string    `json:"request_id"`
	Subject      string    `json:"subject"`
	Reason       string    `json:"reason"`
	IssuedAt     time.Time `json:"issued_at"`
	Approvals    int       `json:"approvals"`
	BundleSHA256 string    `json:"bundle_sha256"`
}

// V3 retains the complete public offline bundle, including both custodian
// signatures and the exact CSR, so a cold replay and forensic export can prove
// the authority decision without relying on a vanished incident laptop.
type privacyBreakglassIssuedReconciledV3 struct {
	RequestID     string            `json:"request_id"`
	Subject       string            `json:"subject"`
	Reason        string            `json:"reason"`
	IssuedAt      time.Time         `json:"issued_at"`
	Approvals     int               `json:"approvals"`
	BundleSHA256  string            `json:"bundle_sha256"`
	OfflineBundle breakglass.Bundle `json:"offline_bundle"`
}

type privacyBreakglassBundle struct {
	RequestID string    `json:"request_id"`
	Subject   string    `json:"subject"`
	CertDER   []byte    `json:"cert_der"`
	Reason    string    `json:"reason"`
	Approvals []string  `json:"approvals"`
	IssuedAt  time.Time `json:"issued_at"`
	Signature []byte    `json:"signature"`
}

type privacyBreakglassIssuedOnline struct {
	RequestID     string                  `json:"request_id"`
	Subject       string                  `json:"subject"`
	Reason        string                  `json:"reason"`
	IssuedAt      time.Time               `json:"issued_at"`
	Approvals     int                     `json:"approvals"`
	Bundle        privacyBreakglassBundle `json:"bundle"`
	CeremonyID    string                  `json:"ceremony_id"`
	RequestDigest string                  `json:"request_digest"`
}

type privacyBreakglassCARotated struct {
	PreviousSignerHandle   string   `json:"previous_signer_handle"`
	ActiveSignerHandle     string   `json:"active_signer_handle"`
	PreviousCertificateDER []byte   `json:"previous_certificate_der"`
	ActiveCertificateDER   []byte   `json:"active_certificate_der"`
	NewSignedByPreviousDER []byte   `json:"new_signed_by_previous_der"`
	PreviousSignedByNewDER []byte   `json:"previous_signed_by_new_der"`
	CeremonyID             string   `json:"ceremony_id"`
	RequestDigest          string   `json:"request_digest"`
	Reason                 string   `json:"reason"`
	TTLSeconds             int64    `json:"ttl_seconds"`
	Approvers              []string `json:"approvers"`
}

type privacyBreakglassCACrossSigned struct {
	IssuerSignerHandle   string   `json:"issuer_signer_handle"`
	IssuerCertificateDER []byte   `json:"issuer_certificate_der"`
	TargetCertificateDER []byte   `json:"target_certificate_der"`
	CrossCertificateDER  []byte   `json:"cross_certificate_der"`
	CeremonyID           string   `json:"ceremony_id"`
	RequestDigest        string   `json:"request_digest"`
	Approvers            []string `json:"approvers"`
}
