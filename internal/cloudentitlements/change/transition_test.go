// SPDX-License-Identifier: BUSL-1.1
package change

import (
	"testing"
	"time"
)

func TestReplacementCompletionRequiresOriginalActorVersionAndNativeAbsenceA264(t *testing.T) {
	now := time.Now().UTC()
	plan := Record{State: WaitingAdoption, Intent: Intent{Action: ReplaceKey, Consumer: "orders", ConsumerSubject: "machine", ReplacementRole: "reader", ReplacementExpectedVersion: 1, ReplacementRoleID: "AROAOWNED"}, Adoption: &Adoption{Consumer: "orders", Subject: "machine", Name: "reader", Version: 2, EventID: "event", Sequence: 3, VerifiedAt: now}}
	result := Result{ReplacementVersion: 2, ReplacementNativeRoleID: "AROAOWNED", KeyAbsent: true, CheckedAt: now}
	if err := ValidateProgress(plan, Verified, &result); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Record, *Result){func(p *Record, _ *Result) { p.Adoption.Subject = "other" }, func(p *Record, _ *Result) { p.Adoption.Version = 1 }, func(p *Record, _ *Result) { p.Adoption.Consumer = "other" }, func(p *Record, _ *Result) { p.Adoption.EventID = "" }, func(_ *Record, r *Result) { r.KeyAbsent = false }, func(_ *Record, r *Result) { r.ReplacementNativeRoleID = "AROAOTHER" }, func(_ *Record, r *Result) { r.EffectUncertain = true }} {
		copyPlan := plan
		receipt := *plan.Adoption
		copyPlan.Adoption = &receipt
		copyResult := result
		mutate(&copyPlan, &copyResult)
		if err := ValidateProgress(copyPlan, Verified, &copyResult); err == nil {
			t.Fatal("incomplete or substituted replacement proof completed")
		}
	}
}
