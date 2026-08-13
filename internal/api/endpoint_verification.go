// SPDX-License-Identifier: MPL-2.0

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// What each listener is actually serving (epic D2).
//
// Every other surface in this product reports what trstctl DID: an outbox row
// delivered, a connector returned success, a certificate was issued. All of
// those can be true while the listener serves something else, because a
// connector's reload is one exec call inside its own Deploy and nothing
// downstream observes whether it took effect.
//
// So this endpoint reports observations. Its most important property is that
// every row says which vantage produced it and which comparisons ran: a
// "verified" that never checked the name set, or that only the serving host
// itself confirmed, is a weaker claim than it looks, and the surface says so
// rather than letting the reader assume.

// EndpointVerification is one endpoint's state from one vantage.
type EndpointVerification struct {
	EndpointID string `json:"endpoint_id"`
	Address    string `json:"address"`
	// Vantage is "local" (the serving host's own agent, right after deploying)
	// or "relay" (a network agent, as a client would). Never merged: an
	// appliance has only the second, and a local pass means the box thinks it
	// is fine rather than that anyone can reach it.
	Vantage string `json:"vantage"`
	// Status is the served vocabulary: verified, diverged, unreachable, or
	// not_checked.
	Status string `json:"status"`
	// Mismatch names the divergence class when there is one: fingerprint,
	// sans, chain, expired, or not_yet_valid. Empty otherwise.
	Mismatch string `json:"mismatch,omitempty"`
	// CheckedSANs and CheckedChain report what was actually compared, so
	// "verified" always carries its own scope.
	CheckedSANs         bool   `json:"checked_sans"`
	CheckedChain        bool   `json:"checked_chain"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
	ObservedFingerprint string `json:"observed_fingerprint,omitempty"`
	NotAfter            string `json:"not_after,omitempty"`
	Detail              string `json:"detail,omitempty"`
	// EvidenceDigest is the probe transcript digest from the agent's signed
	// receipt — what makes this a record rather than an assertion.
	EvidenceDigest  string `json:"evidence_digest,omitempty"`
	AgentCommonName string `json:"agent_common_name,omitempty"`
	LastCheckedAt   string `json:"last_checked_at,omitempty"`
	// LastGoodAt is absent when this endpoint has NEVER been observed serving
	// what it should — a much stronger statement than "not recently", and the
	// console renders it as one.
	LastGoodAt string `json:"last_good_at,omitempty"`
	// StaleForSeconds is how long since the last good observation. Absent when
	// there has never been one, because "infinity" and "a long time" are
	// different facts.
	StaleForSeconds *int64 `json:"stale_for_seconds,omitempty"`
}

// EndpointVerificationList is the served response.
type EndpointVerificationList struct {
	Items []EndpointVerification `json:"items"`
	// Summary is the estate roll-up behind the dashboard tile.
	Summary EndpointVerificationSummary `json:"summary"`
	// Guidance travels with the data rather than living in documentation
	// nobody opens during an incident.
	Guidance string `json:"guidance"`
}

// EndpointVerificationSummary rolls the per-vantage rows up per endpoint.
type EndpointVerificationSummary struct {
	Endpoints int `json:"endpoints"`
	// Verified counts endpoints serving what they should from EVERY vantage
	// that looked. Strict on purpose: an endpoint whose relay probe fails while
	// its local check passes is not verified, because a client cannot get it.
	Verified    int `json:"verified"`
	Diverged    int `json:"diverged"`
	Unreachable int `json:"unreachable"`
	// VerifiedPercent is the dashboard headline. It is a percentage OF OBSERVED
	// ENDPOINTS, not of the estate: endpoints nobody has configured a listener
	// address for are not counted, because counting them as unverified would
	// punish operators for the parts they have not reached yet, and counting
	// them as verified would be a lie.
	VerifiedPercent int `json:"verified_percent"`
}

const endpointVerificationGuidance = "Every row here is a TLS handshake somebody actually performed, not a record " +
	"of what this control plane did. That distinction is the point: a renewal can succeed at the CA, be delivered by " +
	"a connector, and never reach the listener, and every delivery record stays truthfully green while clients keep " +
	"getting the old certificate. 'unreachable' is not a pass and not a divergence — it means nothing was observed. " +
	"An endpoint with no configured listener address never appears here at all, which is the honest answer rather " +
	"than a passing one."

func (a *API) listEndpointVerifications(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "endpoint verification is not configured"))
		return
	}
	rows, err := a.store.ListEndpointVerifications(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	summary, err := a.store.SummarizeEndpointVerifications(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}

	now := time.Now().UTC()
	out := EndpointVerificationList{
		Items:    make([]EndpointVerification, 0, len(rows)),
		Guidance: endpointVerificationGuidance,
		Summary: EndpointVerificationSummary{
			Endpoints:   summary.Endpoints,
			Verified:    summary.Verified,
			Diverged:    summary.Diverged,
			Unreachable: summary.Unreachable,
		},
	}
	if summary.Endpoints > 0 {
		out.Summary.VerifiedPercent = summary.Verified * 100 / summary.Endpoints
	}
	for _, rec := range rows {
		item := EndpointVerification{
			EndpointID: rec.EndpointID, Address: rec.Address, Vantage: rec.Vantage,
			Status:              endpointVerificationStatus(rec),
			Mismatch:            rec.Mismatch,
			CheckedSANs:         rec.CheckedSANs,
			CheckedChain:        rec.CheckedChain,
			ExpectedFingerprint: rec.ExpectedFingerprint,
			ObservedFingerprint: rec.ObservedFingerprint,
			Detail:              rec.Detail,
			EvidenceDigest:      rec.EvidenceDigest,
			AgentCommonName:     rec.AgentCommonName,
		}
		if !rec.NotAfter.IsZero() {
			item.NotAfter = rec.NotAfter.UTC().Format(time.RFC3339)
		}
		if !rec.LastCheckedAt.IsZero() {
			item.LastCheckedAt = rec.LastCheckedAt.UTC().Format(time.RFC3339)
		}
		if !rec.LastGoodAt.IsZero() {
			item.LastGoodAt = rec.LastGoodAt.UTC().Format(time.RFC3339)
			stale := int64(now.Sub(rec.LastGoodAt).Seconds())
			if stale < 0 {
				stale = 0
			}
			item.StaleForSeconds = &stale
		}
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) getEndpointVerification(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "endpoint verification is not configured"))
		return
	}
	record, err := a.store.GetEndpointVerification(r.Context(), tenantID, r.PathValue("id"), "relay")
	if errors.Is(err, pgx.ErrNoRows) {
		a.writeError(w, errStatus(http.StatusNotFound, "endpoint verification not found"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, endpointVerificationDTO(record, time.Now().UTC()))
}

func endpointVerificationDTO(rec store.EndpointVerification, now time.Time) EndpointVerification {
	item := EndpointVerification{
		EndpointID: rec.EndpointID, Address: rec.Address, Vantage: rec.Vantage,
		Status: endpointVerificationStatus(rec), Mismatch: rec.Mismatch,
		CheckedSANs: rec.CheckedSANs, CheckedChain: rec.CheckedChain,
		ExpectedFingerprint: rec.ExpectedFingerprint, ObservedFingerprint: rec.ObservedFingerprint,
		Detail: rec.Detail, EvidenceDigest: rec.EvidenceDigest, AgentCommonName: rec.AgentCommonName,
	}
	if !rec.NotAfter.IsZero() {
		item.NotAfter = rec.NotAfter.UTC().Format(time.RFC3339)
	}
	if !rec.LastCheckedAt.IsZero() {
		item.LastCheckedAt = rec.LastCheckedAt.UTC().Format(time.RFC3339)
	}
	if !rec.LastGoodAt.IsZero() {
		item.LastGoodAt = rec.LastGoodAt.UTC().Format(time.RFC3339)
		stale := int64(now.Sub(rec.LastGoodAt).Seconds())
		if stale < 0 {
			stale = 0
		}
		item.StaleForSeconds = &stale
	}
	return item
}

// endpointVerificationStatus maps a stored observation onto the served
// vocabulary.
//
// Unreachable is checked FIRST and deliberately: a row that could not be
// reached has no mismatch class by construction, so classifying on mismatch
// alone would render it identically to a clean verification.
func endpointVerificationStatus(rec store.EndpointVerification) string {
	switch {
	case !rec.Reached:
		return servedstatus.EndpointUnreachable
	case rec.Mismatch != "":
		return servedstatus.EndpointDiverged
	default:
		return servedstatus.EndpointVerified
	}
}
