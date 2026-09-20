// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/ca"
)

// The served per-issuer capability matrix (epic R2).
//
// An operator planning a migration, or deciding where to put a certificate they
// may one day need to revoke in a hurry, is asking a question the product had
// no way to answer: what can this authority actually do through trstctl. The
// answer used to be found by trying it.
//
// Revoke is the field that matters most, and it is true only where this build
// ships an implementation that CONTACTS the authority and is proven against
// that authority's own protocol by a test. A documented vendor endpoint nobody
// has implemented is not a capability; it is a plan, and an operator reading it
// as a capability during an incident discovers the difference at the worst
// possible moment.

// IssuerCapability is one authority's row in the served matrix.
type IssuerCapability struct {
	Issuer   string `json:"issuer"`
	Discover bool   `json:"discover"`
	Issue    bool   `json:"issue"`
	Renew    bool   `json:"renew"`
	Revoke   bool   `json:"revoke"`
	// KeyHandling says where the private key is generated —
	// "requester_csr" or "authority_generated". It is a capability an operator
	// chooses on, not a footnote: an authority that requires the control plane
	// to generate the key cannot be used where key custody is the point.
	KeyHandling string `json:"key_handling"`
	// Validation is what the authority checks before issuing, which decides
	// whether issuance can be unattended at all.
	Validation string `json:"validation"`
	// RevokeNote explains an absent revoke capability and, where possible, says
	// where to go instead. "Unsupported" with no reason tells an operator
	// nothing they can act on.
	RevokeNote string `json:"revoke_note,omitempty"`
	// UnattendedDV reports whether this build can satisfy the authority's
	// domain-validation challenge with no human step (epic B7). As the
	// CA/Browser Forum compresses the validation-reuse window, this decides
	// how often somebody has to be in the loop for each authority.
	UnattendedDV bool `json:"unattended_dv"`
	// UnattendedDVNote explains an absent one, and the distinction it carries
	// is operational: "there is no challenge to solve" (an internal CA) and "a
	// human completes DCV in the vendor console" are opposite situations.
	UnattendedDVNote string `json:"unattended_dv_note,omitempty"`
	// IssueProven reports whether an end-to-end issuance against this authority
	// is exercised in CI (epic K3). Separate from Issue on purpose: "we
	// implement this API" and "we have run an issuance against it" are
	// different claims, and a surface showing only the first says the stronger
	// one everywhere.
	IssueProven bool `json:"issue_proven"`
	// Evidence names the test that backs this row, so a reader can go and run
	// it rather than take the row's word for it.
	Evidence string `json:"evidence,omitempty"`
}

// IssuerCapabilityMatrix is the served response.
type IssuerCapabilityMatrix struct {
	Issuers []IssuerCapability `json:"issuers"`
	// RevokeCapableCount is the headline: how many of the configured authority
	// kinds this build can actually revoke through.
	RevokeCapableCount int `json:"revoke_capable_count"`
	// UnattendedDVCapableCount is the second headline: how many authority
	// kinds this build can keep validated without a person.
	UnattendedDVCapableCount int `json:"unattended_dv_capable_count"`
	// Guidance travels with the data rather than living in documentation
	// nobody opens.
	Guidance string `json:"guidance"`
}

const issuerCapabilityGuidance = "Revoke is true only where trstctl ships an implementation that contacts the " +
	"authority and is proven against its protocol by a test. Several authorities document a revocation API that " +
	"trstctl does not drive; those read false with a note naming where to revoke instead. A revocation that " +
	"cannot reach the authority fails visibly rather than returning success — a certificate left valid behind a " +
	"receipt saying otherwise is the failure this matrix exists to prevent. Unattended DV is true only where " +
	"trstctl can satisfy the authority's domain-validation challenge with no human step; it additionally " +
	"requires a DNS-01 provider config that has consented to upstream publication, which is per-authority " +
	"configuration rather than a property of the build."

func (a *API) listIssuerCapabilities(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows := ca.IssuerCapabilityMatrix()
	out := IssuerCapabilityMatrix{
		Issuers:  make([]IssuerCapability, 0, len(rows)),
		Guidance: issuerCapabilityGuidance,
	}
	for _, row := range rows {
		out.Issuers = append(out.Issuers, IssuerCapability{
			Issuer: row.Issuer, Discover: row.Discover, Issue: row.Issue,
			Renew: row.Renew, Revoke: row.Revoke,
			KeyHandling: string(row.KeyHandling), Validation: string(row.Validation),
			RevokeNote:   row.RevokeNote,
			UnattendedDV: row.UnattendedDV, UnattendedDVNote: row.UnattendedDVNote,
			IssueProven: row.IssueProven, Evidence: row.Evidence,
		})
		if row.Revoke {
			out.RevokeCapableCount++
		}
		if row.UnattendedDV {
			out.UnattendedDVCapableCount++
		}
	}
	a.writeJSON(w, http.StatusOK, out)
}
