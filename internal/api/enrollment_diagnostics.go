// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/store"
)

// What went wrong with an enrolment, in the operator's terms (epic I4).
//
// A refused enrolment is the moment an operator has the least information and
// the most urgency. The protocol told the client something — an RFC 8555 problem
// type, an EST status, a SCEP failInfo — and none of that reaches the person who
// has to fix it, because the client logged it on a host they are not looking at.
//
// This is that, kept and served. Each refusal is an immutable tenant-attributed
// event, while PostgreSQL projects the newest 200 distinct failure classes under
// FORCE RLS. The projection survives restart and can be rebuilt from the log;
// the bound keeps a live troubleshooting surface from pretending to be an
// unbounded historical archive.

// EnrollmentDiagnostic is one recorded failure.
type EnrollmentDiagnostic struct {
	Protocol string `json:"protocol"`
	Step     string `json:"step"`
	Cause    string `json:"cause"`
	Summary  string `json:"summary"`
	// Remediation is what to do. Empty when the cause is unknown, and that
	// emptiness is deliberate: a diagnosis that cannot name an action must not
	// invent one, because a confident wrong instruction costs more than silence.
	Remediation string `json:"remediation,omitempty"`
	// Actionable separates a diagnosis that names a fix from one that does not,
	// so a console can show the difference rather than rendering an empty
	// remediation as if the operator simply has nothing to do.
	Actionable bool   `json:"actionable"`
	ObservedAt string `json:"observed_at"`
	// Count is how many times this exact diagnosis has been seen.
	//
	// Collapsed rather than listed: a broken challenge fails on every retry, and
	// a hundred identical rows would bury the second, different failure that
	// explains the first.
	Count int64 `json:"count"`
}

// EnrollmentDiagnosticList is the served response.
type EnrollmentDiagnosticList struct {
	Items []EnrollmentDiagnostic `json:"items"`
	// UnknownCount is how many recent failures could not be classified.
	//
	// Reported as a headline because it is a measure of THIS system rather than
	// of the estate: a rising number means the classifier is meeting failures it
	// has no vocabulary for, and that is a gap to close here rather than
	// something for the operator to act on.
	UnknownCount int64  `json:"unknown_count"`
	Guidance     string `json:"guidance"`
}

const enrollmentDiagnosticGuidance = "Each row is a refusal this control plane issued, classified " +
	"from what the protocol actually said. A row with no remediation is one the classifier could " +
	"not place: that is reported as unknown rather than guessed at, because a diagnosis that sends " +
	"you to the wrong system costs more than no diagnosis. These are durable tenant-scoped events, " +
	"collapsed into the 200 most recent distinct diagnoses for this tenant."

// RecordEnrollmentDiagnosis is the tenant-carrying seam protocol servers emit
// into. It returns persistence errors so the composition root can log a closed
// diagnostic without changing the protocol response already being written.
func (a *API) RecordEnrollmentDiagnosis(ctx context.Context, tenantID string, diagnostic enrollmentdiag.Diagnosis) error {
	if a == nil || a.orch == nil {
		return fmt.Errorf("api: enrollment diagnostics are not configured")
	}
	return a.orch.RecordEnrollmentDiagnosis(ctx, tenantID, diagnostic)
}

func (a *API) listEnrollmentDiagnostics(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "enrollment diagnostics are not configured"))
		return
	}
	rows, err := a.store.ListEnrollmentDiagnostics(r.Context(), tenantID, store.EnrollmentDiagnosticRetentionLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]EnrollmentDiagnostic, 0, len(rows))
	for _, row := range rows {
		items = append(items, EnrollmentDiagnostic{
			Protocol: row.Protocol, Step: row.Step, Cause: row.Cause,
			Summary: row.Summary, Remediation: row.Remediation, Actionable: row.Actionable,
			ObservedAt: row.ObservedAt.UTC().Format(time.RFC3339), Count: row.Count,
		})
	}
	out := EnrollmentDiagnosticList{
		Items: items, Guidance: enrollmentDiagnosticGuidance,
	}
	if out.Items == nil {
		out.Items = []EnrollmentDiagnostic{}
	}
	for _, item := range items {
		if item.Cause == string(enrollmentdiag.CauseUnknown) {
			out.UnknownCount += item.Count
		}
	}
	a.writeJSON(w, http.StatusOK, out)
}
