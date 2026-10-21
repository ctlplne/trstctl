// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/lifecycle"
)

// The CA calendar's read surface (H5).
//
// The CA console printed not_after as a raw string and called anything more than
// 90 days out "healthy" — the same yardstick it uses for leaves. That reads a
// root expiring in 30 months as fine, which is the one case where it is already
// late to start: replacing a trust anchor means distributing it to every relying
// party first.
//
// So every authority carries a horizon alongside its expiry: which year-scale
// band it sits in, how long that leaves, the date after which leaves under it
// stop getting their full validity, and whether that truncation has already
// begun. The band is computed here at read time rather than stored, because a
// band is a judgment about now and a stored one would be wrong tomorrow.

// caAuthorityHorizon is the year-scale expiry posture of one CA authority.
type caAuthorityHorizon struct {
	// BandMonths is the tightest threshold the authority has crossed
	// (36/24/12/6/3). Absent when the expiry is further out than the widest
	// threshold, or unknown.
	BandMonths *int `json:"band_months,omitempty"`
	// MonthsRemaining is whole months of life left, rounded down.
	MonthsRemaining int `json:"months_remaining"`
	// Severity scales to runway, not to a fixed day count: low beyond a year,
	// warning inside one, critical inside three months or already expired.
	Severity string `json:"severity"`
	// RenewBy is the date after which a new leaf under this authority no longer
	// receives its full validity, because the authority itself expires first.
	RenewBy *time.Time `json:"renew_by,omitempty"`
	// ValidityCompressed reports that the truncation has already started: leaves
	// issued now are shorter than they are supposed to be, and nothing errors.
	ValidityCompressed bool `json:"validity_compressed"`
	// LeafValidityDays is the reference leaf lifetime the two fields above are
	// measured against, stated so the numbers are interpretable.
	LeafValidityDays int `json:"leaf_validity_days"`
	// Expired reports an authority already past its not_after.
	Expired bool `json:"expired"`
	// ExpiryUnknown reports an authority with no recorded expiry (A22): a real
	// state at warning severity, never shown as healthy.
	ExpiryUnknown bool `json:"expiry_unknown"`
	// TruncatedLeaves counts active leaves already issued under this authority
	// whose validity was clamped to its expiry (A24); TruncatedLeafIDs names the
	// first of them by validity start so an operator can walk to the shortened
	// certificates rather than infer them.
	TruncatedLeaves  int      `json:"truncated_leaves"`
	TruncatedLeafIDs []string `json:"truncated_leaf_ids"`
}

// caAuthorityResponse is a CA authority plus its computed horizon.
type caAuthorityResponse struct {
	CAAuthority
	Horizon *caAuthorityHorizon `json:"horizon,omitempty"`
}

// leafValidityReference is the leaf lifetime the horizon is measured against.
// Zero (never configured) falls back to the lifecycle default so the console
// still gets a usable renew-by date rather than an empty field.
func (a *API) leafValidityReference() time.Duration {
	if a.caLeafValidity > 0 {
		return a.caLeafValidity
	}
	return lifecycle.DefaultLeafValidity
}

// toCAAuthorityResponse attaches the horizon. An authority with no recorded
// expiry gets no horizon rather than a fabricated one — an unknown expiry is a
// real state and pretending otherwise is exactly the overstatement this codebase
// keeps having to unwind.
func (a *API) toCAAuthorityResponse(ca CAAuthority, now time.Time) caAuthorityResponse {
	out := caAuthorityResponse{CAAuthority: ca}
	if ca.NotAfter == nil || ca.NotAfter.IsZero() {
		// A22: no recorded expiry is a state the console must show as a
		// warning, not as an authority with nothing to say.
		out.Horizon = &caAuthorityHorizon{
			Severity: lifecycle.CAHorizonSeverity(lifecycle.CAHorizonUnknownExpiryBand), ExpiryUnknown: true,
			LeafValidityDays: int(a.leafValidityReference().Hours() / 24),
		}
		return out
	}
	notAfter := ca.NotAfter.UTC()
	leaf := a.leafValidityReference()

	horizon := &caAuthorityHorizon{
		MonthsRemaining:  lifecycle.MonthsRemaining(now, notAfter),
		LeafValidityDays: int(leaf.Hours() / 24),
		Expired:          !notAfter.After(now),
	}
	if band, ok := lifecycle.CAHorizonBand(now, notAfter); ok {
		horizon.BandMonths = &band
		horizon.Severity = lifecycle.CAHorizonSeverity(band)
	} else {
		// Beyond the widest band: known, healthy, and not news yet.
		horizon.Severity = "low"
	}
	if renewBy := lifecycle.CARenewBy(notAfter, leaf); !renewBy.IsZero() {
		renewBy = renewBy.UTC()
		horizon.RenewBy = &renewBy
	}
	horizon.ValidityCompressed, _ = lifecycle.CompressedValidity(now, notAfter, leaf)
	horizon.TruncatedLeafIDs = []string{}
	out.Horizon = horizon
	return out
}

// attachTruncatedLeaves fills the retrospective compression facts (A24) from
// the store: leaves issued under the authority that already carry its expiry.
func (a *API) attachTruncatedLeaves(ctx context.Context, tenantID string, resp *caAuthorityResponse) {
	if a.store == nil || resp == nil || resp.Horizon == nil || resp.Horizon.ExpiryUnknown || resp.NotAfter == nil {
		return
	}
	leaves, total, err := a.store.ListTruncatedLeavesForAuthority(ctx, tenantID, resp.ID, resp.NotAfter.UTC(), a.leafValidityReference(), 50)
	if err != nil {
		return
	}
	resp.Horizon.TruncatedLeaves = total
	ids := make([]string, 0, len(leaves))
	for _, l := range leaves {
		ids = append(ids, l.CertificateID)
	}
	resp.Horizon.TruncatedLeafIDs = ids
}
