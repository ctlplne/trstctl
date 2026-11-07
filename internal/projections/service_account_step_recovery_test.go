// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

func recoverySourceFixture(t *testing.T) (events.Event, ServiceDependentStepRecoveryQueued, events.Event, events.Event) {
	t.Helper()
	s := servicedependents.RotationStep{RotationID: "57800000-0000-4000-8000-000000000001", PlanDigest: strings.Repeat("a", 64), Direction: servicedependents.Inverse, Action: servicedependents.Probe, Ref: servicedependents.DependentRef{AgentID: "57800000-0000-4000-8000-000000000002", Family: "tasks", Name: "\\owned\\task"}, AccountSID: "S-1-5-21-1-2-3-1001", ProbeID: "owned-work", Task: &windependents.Task{Path: "\\owned\\task", AccountSID: "S-1-5-21-1-2-3-1001", ConfigSHA256: strings.Repeat("b", 64), Enabled: true, LogonType: 1, ActionCount: 1}, Challenge: "57800000-0000-4000-8000-000000000003", NotBefore: time.Unix(1700000000, 0).UTC(), Deadline: time.Unix(1700000120, 0).UTC()}
	s.ID = crypto.SHA256Hex([]byte(s.RotationID + "\x00" + s.PlanDigest + "\x00" + s.Direction + "\x00" + s.Action + "\x00" + s.Ref.AgentID + "\x00" + s.Ref.Family + "\x00" + s.Ref.Name))[:32]
	// dependentKey uses the same public host/family/name tuple.
	if s.Validate() != nil {
		t.Fatal("invalid exact inverse fixture")
	}
	at := s.Deadline.Add(time.Hour)
	next, err := servicedependents.NewInverseRecoveryStep(s, "57800000-0000-4000-8000-000000000004", at)
	if err != nil {
		t.Fatal(err)
	}
	report := servicedependents.StepReport{RotationID: s.RotationID, PlanDigest: s.PlanDigest, StepID: s.ID, Direction: s.Direction, Status: "uncertain", Failure: "task_start_uncertain", ObservedAt: s.NotBefore.Add(time.Second)}
	v := ServiceDependentStepRecoveryQueued{Previous: s, Step: next, PreviousStatus: report.Status, PreviousReportDigest: ServiceDependentReportDigest(&report), CurrentVersion: 1, Actor: "owned-recovery-operator", Reason: "Owned exact terminal recovery", At: at}
	v.ReviewDigest, err = ServiceDependentRecoveryReviewDigest(s, v.PreviousStatus, v.PreviousReportDigest, 1)
	if err != nil {
		t.Fatal(err)
	}
	source := events.Event{ID: servicedependents.RecoverySourceID(s.RotationID, s.ID), TenantID: "57800000-0000-4000-8000-000000000005", Type: EventServiceDependentStepRecoveryQueued, SchemaVersion: 1, Time: at, Sequence: 3}
	observedRaw, err := json.Marshal(ServiceDependentStepObserved{Report: report, JobID: 1, Attempt: 1, ReceiptStatement: "owned-signed-statement", ReceiptSignature: "owned-signature", SignerFingerprint: "owned-signer", At: report.ObservedAt})
	if err != nil {
		t.Fatal(err)
	}
	return source, v, events.Event{Sequence: 1}, events.Event{TenantID: source.TenantID, Type: EventServiceDependentStepObserved, SchemaVersion: 1, Data: observedRaw, Sequence: 2}
}
func TestInverseRecoverySourceRejectsChangedEnvelopeAndPriorEvidenceA267(t *testing.T) {
	source, v, previous, observed := recoverySourceFixture(t)
	if err := ValidateServiceDependentStepRecovery(source, v); err != nil {
		t.Fatal(err)
	}
	changed := source
	changed.Time = changed.Time.Add(time.Second)
	if ValidateServiceDependentStepRecovery(changed, v) == nil {
		t.Fatal("recovery source accepted a changed envelope time")
	}
	if err := validateRecoveryPredecessorObservation(previous, source, v, observed, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"missing", "tenant", "late", "schema", "digest", "status"} {
		t.Run(change, func(t *testing.T) {
			proof, value, found := observed, v, true
			switch change {
			case "missing":
				found = false
			case "tenant":
				proof.TenantID = "foreign"
			case "late":
				proof.Sequence = 4
			case "schema":
				proof.SchemaVersion = 2
			case "digest":
				value.PreviousReportDigest = strings.Repeat("0", 64)
			case "status":
				value.PreviousStatus = "failed"
			}
			if validateRecoveryPredecessorObservation(previous, source, value, proof, found) == nil {
				t.Fatal("changed predecessor authorized recovery")
			}
		})
	}
	v.PreviousStatus = "queued"
	v.PreviousReportDigest = ""
	if validateRecoveryPredecessorObservation(previous, source, v, observed, true) == nil {
		t.Fatal("queued review ignored existing failure")
	}
	observed.Sequence = 4
	if err := validateRecoveryPredecessorObservation(previous, source, v, observed, true); err != nil {
		t.Fatal("later audit receipt rewrote first recovery review", err)
	}
}
