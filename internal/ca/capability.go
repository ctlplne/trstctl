// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"context"
	"errors"
	"sort"
)

// Revocation through an external authority, and an honest matrix of who can do
// what (epic R2).
//
// The CA interface was Name() and Issue(). Everything else an operator might
// want from an authority — revoke it, tell me what this issuer can even do —
// had no expression, so the answer to "can I revoke this DigiCert certificate
// from here" was found by trying it.
//
// The rule this file exists to enforce is narrow and load-bearing: a revocation
// that does not reach the authority must FAIL, visibly. Not return nil. An
// operator revoking a compromised key and being told it worked, when the
// authority still considers the certificate valid, is worse than being told
// trstctl cannot do it — because the second sends them to the vendor console
// and the first sends them home.

// Revoker is the optional revocation capability of a CA.
//
// Optional on purpose. Several supported authorities have no revocation API
// reachable the way trstctl integrates with them, and the honest outcome is
// that they do not implement this — not a method that returns nil and lets a
// certificate stay live behind a receipt saying otherwise.
type Revoker interface {
	CA
	// Revoke asks the authority to revoke the certificate identified by serial.
	//
	// It must contact the authority. A Revoke that succeeds without a request
	// having been made is the failure this whole epic exists to remove.
	Revoke(ctx context.Context, req RevokeRequest) error
}

// RevokeRequest identifies what to revoke and why.
type RevokeRequest struct {
	// TenantID scopes the operation. Never taken from a caller-supplied field
	// at the API edge — it comes from the authenticated principal (AN-1).
	TenantID string
	// Serial is the certificate's serial as the authority knows it.
	Serial string
	// CertificatePEM is required by authorities that identify the certificate
	// by its bytes rather than by serial — ACME's revokeCert is the notable
	// one, which takes the DER of the certificate itself.
	CertificatePEM []byte
	// ReasonCode is an RFC 5280 CRLReason. Authorities that accept no reason
	// ignore it; none may silently substitute a different one.
	ReasonCode int
}

// ErrRevocationUnsupported is returned when an authority cannot revoke.
//
// Distinct from a failure, because the operator response differs: unsupported
// means go to the vendor's own console, and a failure means try again.
var ErrRevocationUnsupported = errors.New("ca: this issuer does not support revocation through trstctl")

// Capability is one thing an issuer can or cannot do.
type Capability string

const (
	// CapDiscover: trstctl can enumerate certificates this authority has issued.
	CapDiscover Capability = "discover"
	// CapIssue: trstctl can obtain a certificate from it.
	CapIssue Capability = "issue"
	// CapRenew: trstctl can obtain a replacement without operator steps.
	CapRenew Capability = "renew"
	// CapRevoke: trstctl can revoke through it, and the revocation reaches the
	// authority rather than only trstctl's own records.
	CapRevoke Capability = "revoke"
)

// KeyHandling says where the private key is generated for this authority.
//
// It is a capability an operator chooses on, not a footnote: an authority that
// requires the control plane to generate the key is one that cannot be used
// where key custody is the point.
type KeyHandling string

const (
	// KeyRequesterGenerated: trstctl sends a CSR; the key never leaves the
	// requester's environment.
	KeyRequesterGenerated KeyHandling = "requester_csr"
	// KeyAuthorityGenerated: the authority generates and returns the key.
	KeyAuthorityGenerated KeyHandling = "authority_generated"
)

// ValidationModel says what the authority checks before issuing.
type ValidationModel string

const (
	// ValidationACME: automated challenge, no human step.
	ValidationACME ValidationModel = "acme_challenge"
	// ValidationAccountScoped: the authority trusts the authenticated account
	// and its configured domain scope.
	ValidationAccountScoped ValidationModel = "account_scoped"
	// ValidationOrganizational: a human validation step outside trstctl gates
	// issuance; automation cannot compress it.
	ValidationOrganizational ValidationModel = "organizational"
	// ValidationInternal: an internal authority issuing under its own policy.
	ValidationInternal ValidationModel = "internal"
)

// IssuerCapabilities is one authority's served capability row.
//
// It is a declaration checked against the code, not documentation. A row
// claiming revoke for an issuer that does not implement Revoker fails a test —
// because a capability matrix that drifts from the binary is worse than none:
// an operator plans around it during an incident.
type IssuerCapabilities struct {
	Issuer      string
	Discover    bool
	Issue       bool
	Renew       bool
	Revoke      bool
	KeyHandling KeyHandling
	Validation  ValidationModel
	// RevokeNote explains an absent revoke capability. Required when Revoke is
	// false: "not supported" without a reason tells an operator nothing they
	// can act on, and the useful part is usually where to go instead.
	RevokeNote string
	// UnattendedDV reports whether this build can satisfy the authority's
	// domain-validation challenge with no human step (epic B7).
	//
	// This is the question the CA/Browser Forum's shrinking validation-reuse
	// window turns into an operational one. An authority that reads false here
	// needs a person in the loop every time its reuse window closes, and the
	// number of those events per year is going up. It is a capability of the
	// BUILD, not of a particular configuration: whether a given authority is
	// actually configured for it is per-config state on the external-CA row.
	UnattendedDV bool
	// UnattendedDVNote explains an absent one. Required when UnattendedDV is
	// false, for the same reason RevokeNote is.
	UnattendedDVNote string
}

// issuerCapabilityMatrix is the served census.
//
// Revoke is true ONLY where this build ships a Revoker implementation that
// contacts the authority and is proven against that authority's own protocol by
// a test. Everything else is false with a note, including authorities whose
// vendor API documents a revocation endpoint — because a documented endpoint we
// have not implemented and cannot test is not a capability, it is a plan.
var issuerCapabilityMatrix = []IssuerCapabilities{
	{
		Issuer: "letsencrypt", Discover: false, Issue: true, Renew: true, Revoke: true,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationACME,
		UnattendedDV: true,
		// The only true in this column. It requires all three: an ACME
		// challenge model, a shipped dns-01 solver, and a DNS provider config
		// that has consented to upstream publication.
	},
	{
		Issuer: "vaultpki", Discover: false, Issue: true, Renew: true, Revoke: true,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationInternal,
		UnattendedDVNote: "Vault PKI issues under its own role policy with no domain-validation challenge, so there is nothing to automate.",
	},
	{
		Issuer: "ejbca", Discover: false, Issue: true, Renew: true, Revoke: true,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationInternal,
		UnattendedDVNote: "EJBCA issues under its own certificate profile with no domain-validation challenge.",
	},
	{
		Issuer: "digicert", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationOrganizational,
		RevokeNote: "DigiCert's API documents certificate revocation, but trstctl ships no " +
			"implementation and none is tested against it. Revoke from the DigiCert console.",
		UnattendedDVNote: "Public DV/OV issuance through DigiCert's API requires validation steps trstctl does not drive. Complete DCV in the DigiCert console; trstctl cannot keep this authority validated unattended.",
	},
	{
		Issuer: "sectigo", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationOrganizational,
		RevokeNote: "Sectigo's API documents revocation; trstctl ships no implementation. " +
			"Revoke from the Sectigo console.",
		UnattendedDVNote: "Sectigo SCM validation is completed in Sectigo's own console; trstctl drives no DCV method for it.",
	},
	{
		Issuer: "venafi", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationAccountScoped,
		RevokeNote: "Venafi's API documents revocation; trstctl ships no implementation. " +
			"Revoke from Venafi.",
		UnattendedDVNote: "Venafi issues against a policy folder the account is already scoped to; trstctl performs no domain validation.",
	},
	{
		Issuer: "entrust", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationOrganizational,
		RevokeNote:       "No revocation implementation ships. Revoke from the Entrust console.",
		UnattendedDVNote: "Entrust validation is an organizational step outside trstctl.",
	},
	{
		Issuer: "globalsign", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationOrganizational,
		RevokeNote:       "No revocation implementation ships. Revoke from the GlobalSign console.",
		UnattendedDVNote: "GlobalSign validation is an organizational step outside trstctl.",
	},
	{
		Issuer: "awspca", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationInternal,
		RevokeNote: "AWS Private CA exposes RevokeCertificate; trstctl ships no implementation. " +
			"Revoke with the AWS API or console.",
		UnattendedDVNote: "AWS Private CA is internal and performs no domain validation.",
	},
	{
		Issuer: "gcpcas", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationInternal,
		RevokeNote: "Google CAS exposes RevokeCertificate; trstctl ships no implementation. " +
			"Revoke with the gcloud API or console.",
		UnattendedDVNote: "Google CAS is internal and performs no domain validation.",
	},
	{
		Issuer: "adcs", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationInternal,
		RevokeNote: "AD CS revocation runs through the CA's own management interface, which " +
			"trstctl does not drive. Revoke with certutil or the Certification Authority console.",
		UnattendedDVNote: "AD CS issues from template policy against a domain identity; there is no DCV challenge to solve.",
	},
	{
		Issuer: "smallstep", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyRequesterGenerated, Validation: ValidationInternal,
		RevokeNote: "step-ca exposes a revoke endpoint; trstctl ships no implementation. " +
			"Revoke with the step CLI.",
		UnattendedDVNote: "step-ca issues under provisioner policy; trstctl drives no ACME challenge against it.",
	},
	{
		Issuer: "azurekv", Discover: false, Issue: true, Renew: true, Revoke: false,
		KeyHandling: KeyAuthorityGenerated, Validation: ValidationInternal,
		RevokeNote: "Azure Key Vault certificates are disabled rather than revoked, and " +
			"trstctl does not drive that. Use the Azure portal or CLI.",
		UnattendedDVNote: "Azure Key Vault issues from its own policy with no domain-validation challenge trstctl drives.",
	},
}

// IssuerCapabilityMatrix returns the served census, sorted, so the API and the
// console cannot present it in an order that depends on declaration.
func IssuerCapabilityMatrix() []IssuerCapabilities {
	out := append([]IssuerCapabilities(nil), issuerCapabilityMatrix...)
	sort.Slice(out, func(i, j int) bool { return out[i].Issuer < out[j].Issuer })
	return out
}

// CanRevoke reports whether an issuer kind can revoke through trstctl.
func CanRevoke(issuer string) bool {
	for _, row := range issuerCapabilityMatrix {
		if row.Issuer == issuer {
			return row.Revoke
		}
	}
	return false
}

// RevokeThrough revokes via c when it can, and returns
// ErrRevocationUnsupported when it cannot.
//
// The type assertion is the gate. An authority that does not implement Revoker
// gets a refusal the caller can render, never a silent success.
func RevokeThrough(ctx context.Context, c CA, req RevokeRequest) error {
	r, ok := c.(Revoker)
	if !ok {
		return ErrRevocationUnsupported
	}
	return r.Revoke(ctx, req)
}
