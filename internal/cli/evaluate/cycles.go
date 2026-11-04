// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Unattended cycles (A249). --cycles repeats the chosen journeys, --interval
// apart, with nobody watching. When the control plane cannot be reached — it
// restarts, or something in front of it answers 502, 503 or 504 — the cycle
// it cut short is interrupted, not failed: the evaluator waits for /readyz
// and the next cycle has to pass, which is the proof that the deployment
// recovered on its own. Any other failure fails the run.

// PackFormatV3 is a pack with unattended cycles.
const PackFormatV3 = "trstctl.evaluation-pack/v3"

// StatusInterrupted is a cycle the control plane's outage cut short.
const StatusInterrupted Status = "interrupted"

// CycleResult is one unattended cycle.
type CycleResult struct {
	Cycle      int             `json:"cycle"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Verdict    Status          `json:"verdict"`
	Summary    Summary         `json:"summary"`
	Steps      []Step          `json:"steps,omitempty"`
	Journeys   []JourneyResult `json:"journeys,omitempty"`
	// Outage is when the evaluator could not reach the control plane during
	// or just before the cycle, and when /readyz answered again.
	Outage *Outage `json:"outage,omitempty"`
}

// Outage is one stretch the control plane could not be reached.
type Outage struct {
	FirstSeen   time.Time `json:"first_seen"`
	RecoveredAt time.Time `json:"recovered_at,omitzero"`
	Detail      string    `json:"detail"`
}

// noteOutage records the first call this cycle that could not reach the
// control plane.
func (j *journey) noteOutage(err error) {
	if j.outage == nil {
		j.outage = &Outage{FirstSeen: j.opts.Now().UTC(), Detail: sentence(err.Error())}
	}
}

// ready reports whether the control plane answers /readyz.
func (j *journey) ready(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.api.base+"/readyz", nil)
	if err != nil {
		return false
	}
	resp, err := j.api.http.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// awaitRecovery waits up to RecoveryTimeout for /readyz and records when it
// answered.
func (j *journey) awaitRecovery(ctx context.Context) error {
	deadline := j.opts.Now().Add(j.opts.RecoveryTimeout)
	for !j.ready(ctx) {
		if j.opts.Now().After(deadline) {
			return fmt.Errorf("the control plane did not answer /readyz within %s", j.opts.RecoveryTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(j.opts.PollInterval):
		}
	}
	j.outage.RecoveredAt = j.opts.Now().UTC()
	return nil
}

// runCycles runs every cycle into the pack.
func (j *journey) runCycles(ctx context.Context, certificateJourney bool) {
	j.api.unavailable = j.noteOutage
	base := j.keyPrefix
	var cycles []CycleResult
	for cycle := 1; cycle <= j.opts.Cycles; cycle++ {
		if cycle > 1 && j.opts.Interval > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(j.opts.Interval):
			}
		}
		if ctx.Err() != nil {
			break
		}
		j.outage = nil
		// Each cycle starts against a control plane that answers; an outage
		// found here belongs to this cycle.
		var unrecovered error
		if !j.ready(ctx) {
			j.noteOutage(fmt.Errorf("GET /readyz did not answer before cycle %d", cycle))
			unrecovered = j.awaitRecovery(ctx)
		}
		// Every cycle is its own run: its own idempotency keys, certificates
		// and audit window. The endpoint stays enrolled as the identity the
		// first cycle made.
		if j.renewed.Fingerprint != "" {
			j.lastDeployed = j.renewed.Fingerprint
		} else if j.issued.Fingerprint != "" {
			j.lastDeployed = j.issued.Fingerprint
		}
		j.keyPrefix = base + "c" + strconv.Itoa(cycle) + "-"
		j.failed, j.identity, j.issued, j.renewed, j.servedChain = "", "", certificate{}, certificate{}, nil
		j.pack.Steps, j.pack.Journeys, j.pack.AuditExport = []Step{}, nil, nil
		result := CycleResult{Cycle: cycle, StartedAt: j.opts.Now().UTC()}
		if j.opts.CycleStarted != nil {
			j.opts.CycleStarted(cycle)
		}
		if unrecovered == nil {
			j.runCycle(ctx, certificateJourney, result.StartedAt)
		}
		j.finish(certificateJourney)
		result.Steps, result.Journeys, result.Summary, result.Verdict = j.pack.Steps, j.pack.Journeys, j.pack.Summary, j.pack.Verdict
		if unrecovered != nil {
			result.Verdict = StatusFail
		} else if result.Verdict == StatusFail && j.outage != nil {
			if j.outage.RecoveredAt.IsZero() {
				unrecovered = j.awaitRecovery(ctx)
			}
			if unrecovered == nil {
				result.Verdict = StatusInterrupted
			}
		}
		if unrecovered != nil && j.outage != nil {
			j.outage.Detail += " " + sentence(unrecovered.Error())
		}
		result.Outage, result.FinishedAt = j.outage, j.opts.Now().UTC()
		cycles = append(cycles, result)
	}
	p := j.pack
	p.Cycles = cycles
	p.Format = PackFormatV3
	p.Summary = Summary{}
	for _, c := range cycles {
		p.Summary.Passed += c.Summary.Passed
		p.Summary.Failed += c.Summary.Failed
		p.Summary.Skipped += c.Summary.Skipped
	}
	p.Verdict = cyclesVerdict(cycles, j.opts.Cycles)
	p.Limits = append(p.Limits, cyclesLimits(cycles)...)
}

// cyclesVerdict passes a run whose cycles all ran and passed, except a cycle an
// outage interrupted that the very next cycle passed after.
func cyclesVerdict(cycles []CycleResult, want int) Status {
	if len(cycles) != want {
		return StatusFail
	}
	for i, c := range cycles {
		switch c.Verdict {
		case StatusPass:
		case StatusInterrupted:
			if i+1 == len(cycles) || cycles[i+1].Verdict != StatusPass {
				return StatusFail
			}
		default:
			return StatusFail
		}
	}
	return StatusPass
}

func cyclesLimits(cycles []CycleResult) []string {
	interrupted := 0
	for _, c := range cycles {
		if c.Verdict == StatusInterrupted {
			interrupted++
		}
	}
	out := []string{fmt.Sprintf("The journeys ran %d times unattended. The run's steps and audit export are the last cycle's; every cycle is under cycles.", len(cycles))}
	if interrupted > 0 {
		out = append(out, fmt.Sprintf("%d %s cut short when the control plane could not be reached; the run passes only if the next cycle passed after it answered /readyz again.",
			interrupted, plural(interrupted, "cycle was", "cycles were")))
	}
	return out
}
