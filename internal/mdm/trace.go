// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Per-device enrollment traces (epic I5).
//
// The acceptance asks for a device's certificate lifecycle end to end —
// requested, issued, installed, renewing — and for a FAILED enrollment to show
// where it broke. The second half is the hard half and the reason this is a
// trace rather than a status field.
//
// A status field can only say "failed". An operator holding "failed" has to go
// and reconstruct which step failed from three systems' logs, and the common
// case — the certificate was issued and never reached the device — looks
// identical to the case where the device never asked. Those need different
// people to fix them, so they must not render the same.

// Stage names one step of a device's enrollment.
type Stage string

const (
	// StageRequested: the device presented a SCEP request we accepted.
	StageRequested Stage = "requested"
	// StageIssued: a certificate was minted for it.
	StageIssued Stage = "issued"
	// StageInstalled: the MDM reports the profile as installed on the device.
	// This is the MDM's word, not ours — see StepEvidence.
	StageInstalled Stage = "installed"
	// StageRenewing: the certificate is inside its renewal window.
	StageRenewing Stage = "renewing"
)

// Stages is the lifecycle in order. One list, so the console, the API enum and
// the trace builder cannot disagree about what the steps are.
var Stages = []Stage{StageRequested, StageIssued, StageInstalled, StageRenewing}

// Outcome is what happened at a step.
type Outcome string

const (
	OutcomeOK Outcome = "ok"
	// OutcomeFailed: the step was attempted and did not succeed.
	OutcomeFailed Outcome = "failed"
	// OutcomePending: the step has not happened yet and nothing is wrong.
	OutcomePending Outcome = "pending"
	// OutcomeUnknown: we cannot see this step. Deliberately distinct from
	// pending and from failed — an MDM we could not reach tells us nothing
	// about the device, and rendering that as "not installed" would send
	// somebody to re-push a profile that is already there.
	OutcomeUnknown Outcome = "unknown"
)

// Step is one stage of one device's enrollment.
type Step struct {
	Stage   Stage     `json:"stage"`
	Outcome Outcome   `json:"outcome"`
	At      time.Time `json:"at,omitempty"`
	// Detail is what an operator reads. For a failure it must say what broke,
	// not that something did.
	Detail string `json:"detail,omitempty"`
	// Source names who told us: "scep", "ca", "intune", "jamf". A step whose
	// source is an MDM is that MDM's claim, and an operator deciding whether to
	// trust it needs to know which system said so.
	Source string `json:"source,omitempty"`
}

// DeviceTrace is one device's certificate lifecycle.
type DeviceTrace struct {
	DeviceID     string `json:"device_id"`
	MDMDeviceID  string `json:"mdm_device_id,omitempty"`
	MDM          string `json:"mdm,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	// TransactionID ties the trace to the SCEP exchange. Without it a device
	// with two enrollments cannot be told apart from two devices.
	TransactionID string `json:"transaction_id,omitempty"`
	Steps         []Step `json:"steps"`
	// BrokeAt names the first stage that failed, empty when nothing did. It is
	// computed rather than stored so it cannot disagree with the steps.
	BrokeAt Stage `json:"broke_at,omitempty"`
	// Summary is the sentence an operator reads first.
	Summary string `json:"summary"`
}

// Observation is one system's report about a device, as the correlator sees it.
type Observation struct {
	Stage   Stage
	Outcome Outcome
	At      time.Time
	Detail  string
	Source  string
}

// BuildTrace assembles a device's trace from what each system reported.
//
// The rules that matter:
//   - A stage nobody reported is PENDING only if an earlier stage succeeded.
//     Before that it is not pending, it is not yet due, and calling every
//     unreported stage "pending" makes a device that never asked look like one
//     that is mid-flight.
//   - Once a stage FAILS, later stages are UNKNOWN rather than pending: nothing
//     downstream was attempted, and "pending" would suggest it still might be.
//   - An MDM we could not reach yields UNKNOWN, never "not installed".
func BuildTrace(device DeviceTrace, observed []Observation) DeviceTrace {
	byStage := map[Stage]Observation{}
	for _, o := range observed {
		// Later observation of the same stage wins; a device that retried has a
		// newer truth than its first attempt.
		if prev, ok := byStage[o.Stage]; ok && o.At.Before(prev.At) {
			continue
		}
		byStage[o.Stage] = o
	}

	out := device
	out.Steps = nil
	out.BrokeAt = ""
	broken := false
	prevOK := true
	for _, stage := range Stages {
		obs, reported := byStage[stage]
		switch {
		case reported:
			step := Step{Stage: stage, Outcome: obs.Outcome, At: obs.At, Detail: obs.Detail, Source: obs.Source}
			out.Steps = append(out.Steps, step)
			if obs.Outcome == OutcomeFailed && !broken {
				broken = true
				out.BrokeAt = stage
			}
			prevOK = obs.Outcome == OutcomeOK
		case broken:
			// Nothing downstream of a failure was attempted. Saying "pending"
			// would suggest it still might happen on its own.
			out.Steps = append(out.Steps, Step{Stage: stage, Outcome: OutcomeUnknown,
				Detail: "Not attempted: enrollment stopped at " + string(out.BrokeAt) + "."})
			prevOK = false
		case prevOK:
			out.Steps = append(out.Steps, Step{Stage: stage, Outcome: OutcomePending})
			prevOK = false
		default:
			out.Steps = append(out.Steps, Step{Stage: stage, Outcome: OutcomeUnknown,
				Detail: "No system has reported this step."})
		}
	}
	out.Summary = summarize(out)
	return out
}

// summarize writes the sentence an operator reads first. It leads with the
// failure when there is one, because a summary that leads with what worked
// buries the reason somebody opened the page.
func summarize(t DeviceTrace) string {
	if t.BrokeAt != "" {
		for _, s := range t.Steps {
			if s.Stage == t.BrokeAt {
				detail := strings.TrimSpace(s.Detail)
				if detail == "" {
					detail = "no detail was reported"
				}
				return fmt.Sprintf("Enrollment broke at %s: %s", t.BrokeAt, detail)
			}
		}
	}
	var unknown []string
	done := 0
	for _, s := range t.Steps {
		switch s.Outcome {
		case OutcomeOK:
			done++
		case OutcomeUnknown:
			unknown = append(unknown, string(s.Stage))
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Sprintf(
			"%d of %d steps confirmed; %s could not be observed. An unobserved step is not a "+
				"failed one — the MDM may simply be unreachable.", done, len(t.Steps), strings.Join(unknown, ", "))
	}
	if done == len(t.Steps) {
		return "Enrolled and current: every step confirmed."
	}
	return fmt.Sprintf("%d of %d steps confirmed, the rest not yet due.", done, len(t.Steps))
}
