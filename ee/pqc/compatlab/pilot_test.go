// SPDX-License-Identifier: LicenseRef-trstctl-EE

package compatlab

import (
	"context"
	"testing"
)

// recordingProber returns a canned outcome per client and records every client
// it was ever asked to probe, so a test can prove which waves ran and which did
// not.
type recordingProber struct {
	outcome map[string]Outcome
	probed  []string
}

func (p *recordingProber) Probe(_ context.Context, clients []string) ([]Result, error) {
	var out []Result
	for _, c := range clients {
		p.probed = append(p.probed, c)
		oc, ok := p.outcome[c]
		if !ok {
			continue // absent from evidence: Assess treats it as not-attempted
		}
		out = append(out, Result{ClientID: c, Outcome: oc})
	}
	return out, nil
}

func (p *recordingProber) sawProbed(client string) bool {
	for _, c := range p.probed {
		if c == client {
			return true
		}
	}
	return false
}

// A rejection in the canary wave halts the pilot BEFORE the broader wave runs.
// This is the load-bearing property: the later wave's clients must never be
// probed once the canary has failed.
func TestPilotHaltsTheWaveOnACanaryRejection(t *testing.T) {
	prober := &recordingProber{outcome: map[string]Outcome{
		"canary-1": OutcomeRejected,
		"broad-a":  OutcomeNegotiated,
		"broad-b":  OutcomeNegotiated,
	}}
	plan := PilotPlan{Cohort: "gateways", Waves: []Wave{
		{Name: "canary", Clients: []string{"canary-1"}},
		{Name: "broad", Clients: []string{"broad-a", "broad-b"}},
	}}

	res, err := RunPilot(context.Background(), plan, prober)
	if err != nil {
		t.Fatalf("RunPilot: %v", err)
	}
	if res.HaltedAtWave != "canary" {
		t.Fatalf("HaltedAtWave = %q, want \"canary\"", res.HaltedAtWave)
	}
	if len(res.Waves) != 1 || !res.Waves[0].Halted {
		t.Fatalf("waves = %+v, want exactly the canary wave, halted", res.Waves)
	}
	// The broad wave must NOT have been probed — the whole reason to stage.
	if prober.sawProbed("broad-a") || prober.sawProbed("broad-b") {
		t.Fatalf("the broad wave was probed after the canary halted: probed=%v", prober.probed)
	}
	if !Assess(res.Cohort).Halt {
		t.Fatalf("the accumulated evidence should sign as HALT, got %+v", Assess(res.Cohort))
	}
}

// With every wave negotiating, the pilot runs to completion and the accumulated
// evidence is ready.
func TestPilotCompletesWhenEveryWaveNegotiates(t *testing.T) {
	prober := &recordingProber{outcome: map[string]Outcome{
		"canary-1": OutcomeNegotiated,
		"broad-a":  OutcomeNegotiated,
		"broad-b":  OutcomeNegotiated,
	}}
	plan := PilotPlan{Cohort: "gateways", Waves: []Wave{
		{Name: "canary", Clients: []string{"canary-1"}},
		{Name: "broad", Clients: []string{"broad-a", "broad-b"}},
	}}

	res, err := RunPilot(context.Background(), plan, prober)
	if err != nil {
		t.Fatalf("RunPilot: %v", err)
	}
	if res.HaltedAtWave != "" {
		t.Fatalf("HaltedAtWave = %q, want empty (completed)", res.HaltedAtWave)
	}
	if len(res.Waves) != 2 {
		t.Fatalf("waves run = %d, want 2", len(res.Waves))
	}
	if v := Assess(res.Cohort); !v.Ready || v.Negotiated != 3 {
		t.Fatalf("final verdict = %+v, want ready with 3 negotiated", v)
	}
}

// A rejection in a LATER wave halts there, sparing any wave after it.
func TestPilotHaltsAtALaterWave(t *testing.T) {
	prober := &recordingProber{outcome: map[string]Outcome{
		"canary-1": OutcomeNegotiated,
		"mid-a":    OutcomeRejected,
		"final-z":  OutcomeNegotiated,
	}}
	plan := PilotPlan{Cohort: "gateways", Waves: []Wave{
		{Name: "canary", Clients: []string{"canary-1"}},
		{Name: "mid", Clients: []string{"mid-a"}},
		{Name: "final", Clients: []string{"final-z"}},
	}}

	res, err := RunPilot(context.Background(), plan, prober)
	if err != nil {
		t.Fatalf("RunPilot: %v", err)
	}
	if res.HaltedAtWave != "mid" {
		t.Fatalf("HaltedAtWave = %q, want \"mid\"", res.HaltedAtWave)
	}
	if prober.sawProbed("final-z") {
		t.Fatalf("the final wave ran after the mid wave halted: probed=%v", prober.probed)
	}
}

// A wave that reached fewer clients than it targeted is incomplete, not ready —
// the prober omitting a client leaves it not-attempted.
func TestPilotIncompleteWaveIsNotReady(t *testing.T) {
	prober := &recordingProber{outcome: map[string]Outcome{
		"a": OutcomeNegotiated,
		// "b" is deliberately absent from the prober's evidence.
	}}
	plan := PilotPlan{Cohort: "gateways", Waves: []Wave{
		{Name: "only", Clients: []string{"a", "b"}},
	}}

	res, err := RunPilot(context.Background(), plan, prober)
	if err != nil {
		t.Fatalf("RunPilot: %v", err)
	}
	if res.HaltedAtWave != "" {
		t.Fatalf("an incomplete wave should not HALT (no rejection); HaltedAtWave = %q", res.HaltedAtWave)
	}
	if v := Assess(res.Cohort); v.Ready || v.NotAttempted != 1 {
		t.Fatalf("verdict = %+v, want not-ready with one not-attempted", v)
	}
}

func TestRunPilotRejectsAnEmptyPlan(t *testing.T) {
	if _, err := RunPilot(context.Background(), PilotPlan{Cohort: "x"}, &recordingProber{}); err == nil {
		t.Fatal("a pilot with no waves was accepted")
	}
	if _, err := RunPilot(context.Background(), PilotPlan{Cohort: "", Waves: []Wave{{Name: "w", Clients: []string{"a"}}}}, &recordingProber{}); err == nil {
		t.Fatal("a pilot with no cohort name was accepted")
	}
}
