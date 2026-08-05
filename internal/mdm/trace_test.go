// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"strings"
	"testing"
	"time"
)

var traceNow = time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)

// The whole point of a trace: a failed enrollment says WHERE it broke.
//
// A status field can only say "failed", and an operator holding that has to
// reconstruct which step failed from three systems' logs.
func TestAFailedEnrollmentNamesTheStepThatBroke(t *testing.T) {
	t.Parallel()
	got := BuildTrace(DeviceTrace{DeviceID: "d1"}, []Observation{
		{Stage: StageRequested, Outcome: OutcomeOK, At: traceNow, Source: "scep"},
		{Stage: StageIssued, Outcome: OutcomeOK, At: traceNow.Add(time.Second), Source: "ca"},
		{Stage: StageInstalled, Outcome: OutcomeFailed, At: traceNow.Add(time.Minute),
			Detail: "Intune reports the SCEP profile failed to install: device storage full.", Source: "intune"},
	})
	if got.BrokeAt != StageInstalled {
		t.Fatalf("broke_at = %q, want installed. Without this an operator gets \"failed\" and has "+
			"to reconstruct which step from three systems' logs", got.BrokeAt)
	}
	if !strings.Contains(got.Summary, "storage full") {
		t.Fatalf("summary = %q; it must lead with WHAT broke. A summary that leads with what "+
			"worked buries the reason somebody opened the page", got.Summary)
	}
}

// The most common real failure: issued but never installed. It must not look
// like a device that never asked.
func TestIssuedButNeverInstalledIsDistinctFromNeverAsked(t *testing.T) {
	t.Parallel()
	issued := BuildTrace(DeviceTrace{DeviceID: "d1"}, []Observation{
		{Stage: StageRequested, Outcome: OutcomeOK, At: traceNow, Source: "scep"},
		{Stage: StageIssued, Outcome: OutcomeOK, At: traceNow.Add(time.Second), Source: "ca"},
	})
	silent := BuildTrace(DeviceTrace{DeviceID: "d2"}, nil)

	if issued.Steps[2].Outcome != OutcomePending {
		t.Fatalf("installed = %q for an issued device, want pending", issued.Steps[2].Outcome)
	}
	if silent.Steps[1].Outcome == OutcomePending {
		t.Fatal("a device that never asked shows its ISSUED step as pending.\n\n" +
			"That makes a device nobody ever enrolled look mid-flight, and it will sit in a queue " +
			"labelled 'in progress' forever while somebody waits for it to finish.")
	}
	if issued.Summary == silent.Summary {
		t.Fatalf("an issued-not-installed device and a never-asked device read identically: %q. "+
			"They need different people to fix them", issued.Summary)
	}
}

// An MDM we could not reach tells us NOTHING. Rendering that as "not installed"
// sends somebody to re-push a profile that is already there.
func TestAnUnreachableMDMIsUnknownNotNotInstalled(t *testing.T) {
	t.Parallel()
	got := BuildTrace(DeviceTrace{DeviceID: "d1"}, []Observation{
		{Stage: StageRequested, Outcome: OutcomeOK, At: traceNow, Source: "scep"},
		{Stage: StageIssued, Outcome: OutcomeOK, At: traceNow.Add(time.Second), Source: "ca"},
		{Stage: StageInstalled, Outcome: OutcomeUnknown, At: traceNow.Add(time.Minute),
			Detail: "Intune could not be reached.", Source: "intune"},
	})
	if got.BrokeAt != "" {
		t.Fatalf("broke_at = %q; an unreachable MDM is not a device failure and must not be "+
			"reported as one", got.BrokeAt)
	}
	if got.Steps[2].Outcome != OutcomeUnknown {
		t.Fatalf("installed = %q, want unknown", got.Steps[2].Outcome)
	}
	if !strings.Contains(got.Summary, "not a failed one") {
		t.Fatalf("summary = %q; it must say an unobserved step is not a failed one, or somebody "+
			"re-pushes a profile that is already installed", got.Summary)
	}
}

// Nothing downstream of a failure was attempted. Calling it "pending" suggests
// it might still happen on its own.
func TestStepsAfterAFailureAreUnknownNotPending(t *testing.T) {
	t.Parallel()
	got := BuildTrace(DeviceTrace{DeviceID: "d1"}, []Observation{
		{Stage: StageRequested, Outcome: OutcomeFailed, At: traceNow,
			Detail: "SCEP challenge rejected.", Source: "scep"},
	})
	for _, s := range got.Steps[1:] {
		if s.Outcome == OutcomePending {
			t.Fatalf("%s is pending after enrollment already broke at requested. Nothing "+
				"downstream was attempted, and pending suggests it still might happen", s.Stage)
		}
	}
	if got.BrokeAt != StageRequested {
		t.Fatalf("broke_at = %q, want requested", got.BrokeAt)
	}
}

// Only the FIRST failure is the one to fix. A cascade reporting the last stage
// would send an operator to the symptom.
func TestOnlyTheFirstFailureIsReportedAsTheBreak(t *testing.T) {
	t.Parallel()
	got := BuildTrace(DeviceTrace{DeviceID: "d1"}, []Observation{
		{Stage: StageRequested, Outcome: OutcomeFailed, At: traceNow, Detail: "challenge expired", Source: "scep"},
		{Stage: StageIssued, Outcome: OutcomeFailed, At: traceNow.Add(time.Second), Detail: "no request", Source: "ca"},
	})
	if got.BrokeAt != StageRequested {
		t.Fatalf("broke_at = %q, want the FIRST failure. Reporting the last one sends an operator "+
			"to the symptom rather than the cause", got.BrokeAt)
	}
}

// A retried device has a newer truth than its first attempt.
func TestALaterObservationOfTheSameStageWins(t *testing.T) {
	t.Parallel()
	got := BuildTrace(DeviceTrace{DeviceID: "d1"}, []Observation{
		{Stage: StageInstalled, Outcome: OutcomeFailed, At: traceNow, Detail: "first try failed", Source: "intune"},
		{Stage: StageInstalled, Outcome: OutcomeOK, At: traceNow.Add(time.Hour), Source: "intune"},
	})
	for _, s := range got.Steps {
		if s.Stage == StageInstalled && s.Outcome != OutcomeOK {
			t.Fatalf("installed = %q; a device that retried successfully is still shown as broken",
				s.Outcome)
		}
	}
	if got.BrokeAt != "" {
		t.Fatalf("broke_at = %q after a successful retry", got.BrokeAt)
	}
}

// The stage list is one list, so the console, the API enum and the builder
// cannot disagree about what the steps are.
func TestEveryStageAppearsInEveryTrace(t *testing.T) {
	t.Parallel()
	got := BuildTrace(DeviceTrace{DeviceID: "d1"}, nil)
	if len(got.Steps) != len(Stages) {
		t.Fatalf("trace has %d steps, want %d — a device view that omits a stage cannot show "+
			"where enrollment stopped", len(got.Steps), len(Stages))
	}
	for i, s := range got.Steps {
		if s.Stage != Stages[i] {
			t.Fatalf("step %d = %q, want %q; the trace must read in lifecycle order", i, s.Stage, Stages[i])
		}
	}
}
