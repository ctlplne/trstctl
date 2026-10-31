// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"strings"
	"time"
)

// A161: the AD CS issuer health view. For every adcs external CA the tenant can
// use it reports whether issuance through it is working, from evidence the
// platform already records: certificates its issuance service recorded, and
// the enrollment diagnoses its refusals produced (with the classified cause
// and remediation).

const adcsIssuerHealthWindow = 7 * 24 * time.Hour

// Issuer health states.
const (
	ADCSIssuerHealthy  = "healthy"
	ADCSIssuerDegraded = "degraded"
	ADCSIssuerFailing  = "failing"
	ADCSIssuerIdle     = "idle"
)

// ADCSIssuerHealth is one adcs external CA's issuance health.
type ADCSIssuerHealth struct {
	ID                     string     `json:"id"`
	Name                   string     `json:"name"`
	Status                 string     `json:"status"`
	IssuedInWindow         int        `json:"issued_in_window"`
	LastSuccessAt          *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt          *time.Time `json:"last_failure_at,omitempty"`
	LastFailureCause       string     `json:"last_failure_cause,omitempty"`
	LastFailureSummary     string     `json:"last_failure_summary,omitempty"`
	LastFailureRemediation string     `json:"last_failure_remediation,omitempty"`
}

// ADCSIssuerHealthList is the tenant's adcs issuers.
type ADCSIssuerHealthList struct {
	Items      []ADCSIssuerHealth `json:"items"`
	WindowDays int                `json:"window_days"`
	Guidance   string             `json:"guidance"`
}

const adcsIssuerHealthGuidance = "failing: the latest attempt through this issuer was refused; degraded: a refusal " +
	"inside the window but a later success; healthy: issued inside the window with no later refusal; idle: no evidence. " +
	"Refusals come from enrollment diagnoses, which are kept per cause, so the last refusal shown is the latest one " +
	"whose cause no other issuer hit since."

func (a *API) getADCSIssuerHealth(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out := ADCSIssuerHealthList{Items: []ADCSIssuerHealth{}, WindowDays: int(adcsIssuerHealthWindow / (24 * time.Hour)), Guidance: adcsIssuerHealthGuidance}
	if a.externalCAs == nil || a.store == nil {
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	issuers, err := a.externalCAs.ListExternalCAs(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	now := time.Now().UTC()
	for _, issuer := range issuers {
		if !strings.EqualFold(issuer.Type, "adcs") {
			continue
		}
		issued, err := a.store.ExternalCAIssuanceStats(r.Context(), tenantID, issuer.ID, now.Add(-adcsIssuerHealthWindow))
		if err != nil {
			a.writeError(w, err)
			return
		}
		failure, failed, err := a.store.LatestExternalCAFailure(r.Context(), tenantID, issuer.ID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		item := ADCSIssuerHealth{ID: issuer.ID, Name: issuer.Name, IssuedInWindow: issued.IssuedSince, LastSuccessAt: issued.LatestIssued}
		if failed {
			at := failure.ObservedAt.UTC()
			item.LastFailureAt, item.LastFailureCause = &at, failure.Cause
			item.LastFailureSummary, item.LastFailureRemediation = failure.Summary, failure.Remediation
		}
		item.Status = adcsIssuerStatus(item, now)
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}

func adcsIssuerStatus(item ADCSIssuerHealth, now time.Time) string {
	recentFailure := item.LastFailureAt != nil && now.Sub(*item.LastFailureAt) <= adcsIssuerHealthWindow
	switch {
	case item.LastFailureAt != nil && (item.LastSuccessAt == nil || !item.LastFailureAt.Before(*item.LastSuccessAt)) && recentFailure:
		return ADCSIssuerFailing
	case recentFailure:
		return ADCSIssuerDegraded
	case item.IssuedInWindow > 0:
		return ADCSIssuerHealthy
	default:
		return ADCSIssuerIdle
	}
}
