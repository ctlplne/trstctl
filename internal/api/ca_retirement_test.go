// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The retirement checklist's failure direction (epic H4).
//
// Destruction is irreversible, so the only question that matters about this
// surface is what it says when it does not know. An unlicensed deployment
// rendering an empty checklist would read as "this key has no dependents" —
// permission to destroy — which is the worst available way for a licence check
// to fail.

func TestAnUnlicensedDeploymentRefusesRatherThanReportingNoDependents(t *testing.T) {
	t.Parallel()
	reason, unavailable := retirementUnavailable(nil)
	if !unavailable {
		t.Fatal("an unlicensed deployment would produce a checklist; an empty outstanding list " +
			"reads as permission to destroy a key whose dependents were never enumerated")
	}
	// The refusal has to distinguish itself from an empty result, in words.
	if !strings.Contains(reason, "not a statement that the key has no dependents") {
		t.Errorf("the refusal reads %q; it must say it is a missing answer rather than an "+
			"answer of zero", reason)
	}
}

func TestAnUnlicensedDeploymentDoesNotMountIrreversibleRetirement(t *testing.T) {
	t.Parallel()
	served := New(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/ca-old/retirement",
		strings.NewReader(`{"final_epoch":7,"confirm_irreversible":true}`))
	req.Header.Set("Idempotency-Key", "must-not-be-admitted")
	rr := httptest.NewRecorder()
	served.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unlicensed POST retirement = %d body=%s, want absent licensed route (404)", rr.Code, rr.Body.String())
	}
}

// The guidance has to say that the refusal lives in the signer, not here.
//
// An operator who believes this page is the gate will route around it — raise a
// ticket, have someone with signer access destroy the key by hand — and the
// evidence chain the whole feature exists to produce never gets written.
func TestGuidanceLocatesTheEnforcementPoint(t *testing.T) {
	t.Parallel()
	for _, phrase := range []string{"isolated signer", "irreversible", "verifiable offline"} {
		if !strings.Contains(retirementGuidance, phrase) {
			t.Errorf("the retirement guidance does not mention %q; an operator who thinks this "+
				"page is the gate will route around it and destroy the key by hand, and the "+
				"evidence chain never gets written", phrase)
		}
	}
}
