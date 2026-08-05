// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/enrollmentdiag"
)

// A deliberately broken enrolment yields a specific, actionable trace (epic I4).
//
// The diagnosis vocabulary and its remediations existed for a while with no
// production caller: every cause defined, every remediation written, and nothing
// in the served binary ever producing one. Worth naming, because a diagnosis
// catalogue with no classifier is the same shape of defect it exists to describe
// — it looks finished from the inside.
//
// So the test that matters is not "does Diagnose work" but "does a real refusal
// on the served path produce one".

func TestARefusalOnTheServedPathProducesADiagnosis(t *testing.T) {
	t.Parallel()
	s := &Server{}
	var got []enrollmentdiag.Diagnosis
	s.SetFailureDiagnosis(func(d enrollmentdiag.Diagnosis) { got = append(got, d) })

	// A challenge the authority could not see — the classic broken enrolment.
	req := httptest.NewRequest(http.MethodPost, "/acme/challenge/abc", nil)
	s.problem(httptest.NewRecorder(), req, http.StatusForbidden, "dns",
		"no TXT record found for _acme-challenge.api.example.test")

	if len(got) != 1 {
		t.Fatalf("a served refusal produced %d diagnoses, want 1. The catalogue is only worth "+
			"having if the served path emits into it", len(got))
	}
	d := got[0]
	if d.Cause != enrollmentdiag.CauseChallengeNotVisible {
		t.Errorf("cause = %q, want challenge_not_visible", d.Cause)
	}
	if d.Step != enrollmentdiag.StepValidation {
		t.Errorf("step = %q; the request was on a challenge path, which places the failure at "+
			"validation and tells an operator that account and order both worked", d.Step)
	}
	if d.Remediation == "" {
		t.Error("the diagnosis names nothing to do")
	}
	if !d.Actionable() {
		t.Error("a classified failure reported itself as not actionable")
	}
}

// The step is inferred from the path, and an unrecognised path does not invent
// one.
func TestTheStepComesFromThePathAndIsNotGuessed(t *testing.T) {
	t.Parallel()
	cases := map[string]enrollmentdiag.Step{
		"/acme/new-account": enrollmentdiag.StepAccount,
		"/acme/new-order":   enrollmentdiag.StepOrder,
		"/acme/challenge/x": enrollmentdiag.StepValidation,
		"/acme/finalize/x":  enrollmentdiag.StepIssue,
		"/acme/revoke-cert": enrollmentdiag.StepRevocation,
	}
	for path, want := range cases {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if got := acmeStepForPath(req); got != want {
			t.Errorf("path %q placed the failure at %q, want %q", path, got, want)
		}
	}
	// An unrecognised path yields NO step; the classifier then substitutes its
	// own default rather than this function guessing at a stage nobody observed.
	if got := acmeStepForPath(httptest.NewRequest(http.MethodGet, "/acme/something", nil)); got != "" {
		t.Errorf("an unrecognised path was placed at step %q rather than left unplaced", got)
	}
}

// Every refusal path emits, because the hook sits at the single choke point.
//
// This is why it is hooked at problem() rather than at each refusal site: a
// refusal added later is diagnosed without anybody remembering to wire it, and
// the alternative — a list of call sites — is a list that goes out of date.
func TestEveryRefusalEmitsBecauseTheHookIsAtTheChokePoint(t *testing.T) {
	t.Parallel()
	s := &Server{}
	count := 0
	s.SetFailureDiagnosis(func(enrollmentdiag.Diagnosis) { count++ })

	for _, typ := range []string{"dns", "rateLimited", "unauthorized", "serverInternal", "malformed"} {
		s.problem(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, "/acme/new-order", nil),
			http.StatusBadRequest, typ, "detail")
	}
	if count != 5 {
		t.Fatalf("%d of 5 refusals produced a diagnosis; a refusal that emits nothing is one an "+
			"operator gets no help with", count)
	}
}

// A server with no hook still serves refusals normally.
func TestRefusalsWorkWithNoDiagnosisHook(t *testing.T) {
	t.Parallel()
	s := &Server{}
	rec := httptest.NewRecorder()
	s.problem(rec, httptest.NewRequest(http.MethodPost, "/acme/new-order", nil),
		http.StatusBadRequest, "malformed", "bad")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d without a diagnosis hook, want 400", rec.Code)
	}
}
