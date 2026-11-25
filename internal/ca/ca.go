// SPDX-License-Identifier: BUSL-1.1

// Package ca defines the certificate-authority plugin interface and a built-in
// CA that implements it. Every CA — the built-in one here, the signer-backed
// internal authority, and the WASM CA plugins (run on internal/pluginhost) —
// satisfies the same CA interface, so the issuance path is uniform regardless of
// which authority mints the certificate. Issuance runs on the idempotency (AN-5)
// and outbox (AN-6) paths via IssuanceService.
package ca

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
)

// IssueRequest asks a CA to sign a PKCS#10 certificate request. DNSNames lists
// the identifiers to authorize (used by ACME CAs such as Let's Encrypt, which
// authorize the order's domains before finalizing with the CSR); in-process CAs
// read the names from the CSR and may ignore it.
type IssueRequest struct {
	TenantID string
	CSR      []byte // PKCS#10 DER
	DNSNames []string
	TTL      time.Duration

	// ProviderIdempotencyKey is the deterministic, provider-safe token derived
	// from the platform Idempotency-Key. External CA implementations that support
	// upstream idempotency must use it instead of generating a random token.
	ProviderIdempotencyKey string

	// Profile binding (S8.1). When ProfileName is set, the issuance service
	// validates the request against that tenant's active profile version before
	// signing. Protocol names the enrollment path ("api"/"acme"/"est"/...), which a
	// profile may restrict; RequestedEKUs are the extended key usages the caller
	// asks for, checked against the profile's allow-list.
	profileRevision *externalProfileRevision
	resolvedProfile *profile.CertificateProfile
	resolvedEKUs    []string
	ProfileName     string
	Protocol        string
	RequestedEKUs   []string

	// RequestBinding is a non-secret digest of the authenticated principal and
	// canonical external-CA command. The durable certificate projection retains
	// it after response/outbox GC so a reused raw key cannot change authority,
	// caller, CSR, names, profile, or lifetime.
	RequestBinding string

	// KeyOrigin is the custody origin (internal/custody vocabulary) of the
	// CSR's key as the caller knows it, recorded on the issued certificate
	// (A121). The service itself never generates a subject key; empty leaves
	// custody unrecorded.
	KeyOrigin string

	// DeviceAttestation is a verified TPM attestation that the CSR's key was
	// generated in, and cannot leave, the requesting device (ACME
	// device-attest-01). An issuer that records custody records it as a
	// device-bound claim with this evidence; nil records none.
	DeviceAttestation *DeviceAttestation
}

// NativeLeafProfile returns the effective signing template for a CA that constructs
// the certificate itself. A named profile must have been resolved by the issuance service.
func (req IssueRequest) NativeLeafProfile(base crypto.LeafProfile) (crypto.LeafProfile, error) {
	if req.ProfileName == "" {
		return base, nil
	}
	if req.resolvedProfile == nil {
		return crypto.LeafProfile{}, errors.New("ca: native issuance requires the admitted certificate profile revision")
	}
	usages := req.resolvedEKUs
	if len(usages) == 0 {
		usages = req.resolvedProfile.EffectiveEKUs()
	}
	return req.resolvedProfile.LeafProfile(base, usages), nil
}

// DeviceAttestation is the retained proof behind a device-bound custody claim:
// the attestation exactly as the device sent it, the binding whose SHA-256 is
// the challenge it signed, and the facts verified when it was accepted.
type DeviceAttestation struct {
	Format                       string
	Credential                   []byte
	Binding                      []byte
	PublicKeySHA256              []byte
	AttestationCertificateSHA256 []byte
	TrustedRootsSHA256           []byte
	VerifiedAt                   time.Time
}

// Certificate is an issued certificate (the leaf followed by its chain, PEM).
type Certificate struct {
	CertificatePEM []byte    `json:"certificate_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
	Issuer         string    `json:"issuer"`
}

// CA is a certificate authority. Implementations may be in-process (the built-in
// CA), signer-backed, or WASM plugins behind the plugin host.
type CA interface {
	// Name identifies the authority (used in events and the issued Certificate).
	Name() string
	// Issue signs the request's CSR and returns the certificate.
	Issue(ctx context.Context, req IssueRequest) (Certificate, error)
}
