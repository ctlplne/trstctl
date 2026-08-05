// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/enrollmentdiag"
)

// What went wrong with an enrolment, in the operator's terms (epic I4).
//
// A refused enrolment is the moment an operator has the least information and
// the most urgency. The protocol told the client something — an RFC 8555 problem
// type, an EST status, a SCEP failInfo — and none of that reaches the person who
// has to fix it, because the client logged it on a host they are not looking at.
//
// This is that, kept and served. It holds recent diagnoses in memory rather than
// in the database, and that is a real limitation stated rather than hidden: a
// restart loses them. Persisting would mean a schema, a projection and a
// retention policy for data whose whole value is being minutes old, and an
// operator debugging an enrolment that failed a week ago is not helped by a row
// — they are helped by running it again.

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
	Count int `json:"count"`
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
	UnknownCount int    `json:"unknown_count"`
	Guidance     string `json:"guidance"`
}

const enrollmentDiagnosticGuidance = "Each row is a refusal this control plane issued, classified " +
	"from what the protocol actually said. A row with no remediation is one the classifier could " +
	"not place: that is reported as unknown rather than guessed at, because a diagnosis that sends " +
	"you to the wrong system costs more than no diagnosis. These are held in memory and are lost on " +
	"restart — they describe what is failing now, not a history."

// diagnosticRecorder keeps recent enrolment diagnoses.
//
// Bounded by distinct diagnosis rather than by count. The interesting failures
// are the DIFFERENT ones, and a ring buffer of the last N would be filled by
// whichever client retries fastest — which is usually the one already
// diagnosed.
type diagnosticRecorder struct {
	mu    sync.Mutex
	seen  map[string]*EnrollmentDiagnostic
	now   func() time.Time
	limit int
}

func newDiagnosticRecorder() *diagnosticRecorder {
	return &diagnosticRecorder{seen: map[string]*EnrollmentDiagnostic{}, now: time.Now, limit: 200}
}

// Record adds a diagnosis, collapsing repeats.
func (d *diagnosticRecorder) Record(diag enrollmentdiag.Diagnosis) {
	if d == nil {
		return
	}
	key := string(diag.Protocol) + "|" + string(diag.Step) + "|" + string(diag.Cause)
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.seen[key]; ok {
		existing.Count++
		existing.ObservedAt = d.now().UTC().Format(time.RFC3339)
		return
	}
	if len(d.seen) >= d.limit {
		// Full. Drop the oldest rather than refusing the new one: a recorder
		// that stopped accepting would go quiet exactly when an estate started
		// failing in new ways.
		var oldestKey string
		var oldest string
		for k, v := range d.seen {
			if oldest == "" || v.ObservedAt < oldest {
				oldest, oldestKey = v.ObservedAt, k
			}
		}
		delete(d.seen, oldestKey)
	}
	d.seen[key] = &EnrollmentDiagnostic{
		Protocol: string(diag.Protocol), Step: string(diag.Step), Cause: string(diag.Cause),
		Summary: diag.Summary, Remediation: diag.Remediation,
		Actionable: diag.Actionable(),
		ObservedAt: d.now().UTC().Format(time.RFC3339), Count: 1,
	}
}

// snapshot returns the recorded diagnoses, most recent first.
func (d *diagnosticRecorder) snapshot() []EnrollmentDiagnostic {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]EnrollmentDiagnostic, 0, len(d.seen))
	for _, v := range d.seen {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservedAt > out[j].ObservedAt })
	return out
}

// RecordEnrollmentDiagnosis is the seam the protocol servers emit into.
func (a *API) RecordEnrollmentDiagnosis(diag enrollmentdiag.Diagnosis) {
	if a == nil || a.enrollmentDiagnostics == nil {
		return
	}
	a.enrollmentDiagnostics.Record(diag)
}

func (a *API) listEnrollmentDiagnostics(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items := a.enrollmentDiagnostics.snapshot()
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
