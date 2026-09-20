// SPDX-License-Identifier: BUSL-1.1

package compatlab

import (
	"context"
	"fmt"
	"strings"
)

// Pilot-wave execution with canary halt (epic M1, H2).
//
// Assess already DECIDES whether evidence halts a wave; this DRIVES the wave.
// A pilot rolls a PQ/hybrid leaf out in ordered stages — a small canary first,
// then progressively broader waves — and the whole point of staging is that a
// failure in an early wave must stop the later ones BEFORE they run. A pilot that
// gathered every wave's evidence and only then noticed the canary had failed
// would have already broken the connections staging exists to protect.
//
// So RunPilot probes each wave in order, assesses the evidence accumulated so
// far after each, and STOPS the instant a wave halts — the remaining waves are
// never probed. The accumulated evidence (including the failing wave) is what
// leaves as the signed readiness report, so the report says HALT over the exact
// evidence that caused it.

// Prober runs the real handshakes for a wave's clients and returns their
// evidence. The relay satisfies this in production; a test satisfies it with
// recorded results. A client the prober omits from its return is simply absent
// from the evidence, which Assess treats as not-attempted — silence is not
// compatibility.
type Prober interface {
	Probe(ctx context.Context, clients []string) ([]Result, error)
}

// Wave is one ordered stage of a pilot. The first wave is the canary.
type Wave struct {
	Name    string
	Clients []string
}

// PilotPlan is the ordered staging of a rollout.
type PilotPlan struct {
	Cohort string
	Waves  []Wave
}

// WaveOutcome is what one wave produced and the verdict on the evidence
// accumulated THROUGH that wave (not that wave alone) — a rejection in the
// canary must color the verdict every later wave is judged against.
type WaveOutcome struct {
	Wave    string
	Probed  []string
	Results []Result
	Verdict Verdict
	Halted  bool
}

// PilotResult is the whole run: the accumulated cohort (the evidence to sign),
// each wave's outcome, and which wave halted the pilot (empty if it completed).
type PilotResult struct {
	Cohort       Cohort
	Waves        []WaveOutcome
	HaltedAtWave string
}

// RunPilot drives the plan's waves in order, halting the instant the evidence
// so far says to. It returns the accumulated evidence whether the pilot
// completed or halted — a halted pilot's evidence is the most important to keep.
//
// A probe that ERRORS ends the run with an error rather than a verdict: a wave
// that could not be exercised is not evidence of anything, and must not be
// scored as if it were.
func RunPilot(ctx context.Context, plan PilotPlan, prober Prober) (PilotResult, error) {
	if strings.TrimSpace(plan.Cohort) == "" {
		return PilotResult{}, fmt.Errorf("compatlab: a pilot needs a cohort name")
	}
	if len(plan.Waves) == 0 {
		return PilotResult{}, fmt.Errorf("compatlab: a pilot needs at least one wave")
	}
	if prober == nil {
		return PilotResult{}, fmt.Errorf("compatlab: a pilot needs a prober")
	}

	var targeted []string
	var results []Result
	var outcomes []WaveOutcome

	for _, w := range plan.Waves {
		name := strings.TrimSpace(w.Name)
		clients := normalizeTargets(w.Clients)
		if len(clients) == 0 {
			return PilotResult{}, fmt.Errorf("compatlab: wave %q targets no clients", name)
		}
		if err := ctx.Err(); err != nil {
			return PilotResult{}, err
		}
		waveResults, err := prober.Probe(ctx, clients)
		if err != nil {
			return PilotResult{}, fmt.Errorf("compatlab: wave %q probe: %w", name, err)
		}
		targeted = append(targeted, clients...)
		results = append(results, waveResults...)

		accumulated := Cohort{Name: plan.Cohort, Targeted: targeted, Results: results}
		verdict := Assess(accumulated)
		outcomes = append(outcomes, WaveOutcome{
			Wave: name, Probed: clients, Results: waveResults, Verdict: verdict, Halted: verdict.Halt,
		})

		if verdict.Halt {
			// Stop here. The later waves are NOT probed — that is the whole point
			// of a canary, and a pilot that kept going would break the very
			// connections staging exists to protect.
			return PilotResult{Cohort: accumulated, Waves: outcomes, HaltedAtWave: name}, nil
		}
	}

	final := Cohort{Name: plan.Cohort, Targeted: targeted, Results: results}
	return PilotResult{Cohort: final, Waves: outcomes, HaltedAtWave: ""}, nil
}
