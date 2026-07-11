// SPDX-License-Identifier: MPL-2.0

// Package ca defines the certificate-authority plugin interface and a built-in
// CA that implements it. Every CA — the built-in one here, the signer-backed
// internal authority, and the WASM CA plugins (run on internal/pluginhost) —
// satisfies the same CA interface, so the issuance path is uniform regardless of
// which authority mints the certificate. Issuance runs on the idempotency (AN-5)
// and outbox (AN-6) paths via IssuanceService.
package ca

import (
	"context"
	"time"
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
	ProfileName   string
	Protocol      string
	RequestedEKUs []string

	// RequestBinding is a non-secret digest of the authenticated principal and
	// canonical external-CA command. The durable certificate projection retains
	// it after response/outbox GC so a reused raw key cannot change authority,
	// caller, CSR, names, profile, or lifetime.
	RequestBinding string
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
