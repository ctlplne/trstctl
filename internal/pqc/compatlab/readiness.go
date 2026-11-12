// SPDX-License-Identifier: BUSL-1.1

// Package compatlab decides whether PQC handshake evidence supports a
// readiness claim (epic M1).
//
// A compatibility lab's entire output is a statement about what will work in
// production. The dangerous failure is not a handshake that fails — that is the
// lab doing its job. It is a cohort that was never really exercised reporting
// zero failures, and somebody reading that as "PQ is safe to roll out".
//
// So this file is about what the evidence does NOT support. Every refusal here
// exists because the alternative is a signed readiness report that is confidently
// wrong about a migration nobody can easily reverse.
package compatlab

import (
	"fmt"
	"sort"
	"strings"
)

// Outcome is what one client's handshake attempt did.
type Outcome string

const (
	// OutcomeNegotiated: the handshake completed with the PQ/hybrid leaf.
	OutcomeNegotiated Outcome = "negotiated"
	// OutcomeRejected: the client refused it. This is EVIDENCE, and a good
	// outcome for a lab — it is the thing the pilot exists to discover.
	OutcomeRejected Outcome = "rejected"
	// OutcomeUnreachable: the client could not be contacted at all. NOT a
	// rejection and NOT a success: it says nothing about PQ compatibility, and
	// counting it either way corrupts the verdict.
	OutcomeUnreachable Outcome = "unreachable"
	// OutcomeNotAttempted: no handshake was tried against this client. The
	// most dangerous state to render as anything but itself.
	OutcomeNotAttempted Outcome = "not_attempted"
)

// Observed-traffic marks (X3-L5). A pilot that requires observed traffic
// holds a wave until an observer agent has seen real clients connect at
// every negotiated target after its probe: the probe is trstctl's own
// client, and the readiness claim is about everyone else's.
const (
	// TrafficObserved: real clients were observed connecting at the target
	// after the probe.
	TrafficObserved = "observed"
	// TrafficUnobserved: the observed-traffic window ended with no new
	// connection seen there.
	TrafficUnobserved = "unobserved"
)

// Result is one client's handshake evidence.
type Result struct {
	ClientID string
	Outcome  Outcome
	// HandshakeBytes and LatencyMS are the cost half of the question. A
	// combination that negotiates but triples handshake size is a different
	// answer from one that negotiates cheaply, and a readiness report that
	// omitted cost would be recommending an outage.
	HandshakeBytes int
	LatencyMS      int
	Detail         string
	// Traffic is the observed-traffic mark (TrafficObserved or
	// TrafficUnobserved) when the cohort requires observed traffic; empty
	// while the gate is still waiting, and always empty otherwise.
	Traffic string `json:",omitempty"`
}

// Cohort is the set of clients a pilot wave targeted.
type Cohort struct {
	Name string
	// Targeted is who the wave was SUPPOSED to reach. Kept separate from the
	// results so a wave that silently reached fewer clients than intended
	// cannot pass as complete.
	Targeted []string
	Results  []Result
	// RequireObservedTraffic makes a negotiated client count toward
	// readiness only once real clients were observed at its endpoint
	// (X3-L5).
	RequireObservedTraffic bool
}

// Verdict is what the evidence supports.
type Verdict struct {
	// Ready is true only when the evidence actually supports rolling forward.
	Ready bool
	// Halt is true when a canary result should stop the wave (H2).
	Halt bool
	// Summary is the sentence a human reads first. For a refusal it names what
	// is missing, because "not ready" alone gets argued with rather than acted
	// on.
	Summary                                         string
	Negotiated, Rejected, Unreachable, NotAttempted int
	// AwaitingTraffic counts negotiated clients whose observed-traffic mark
	// is still pending; Unobserved those whose window ended with none
	// (X3-L5). Both are zero, and absent from a report, when the cohort does
	// not require observed traffic.
	AwaitingTraffic int `json:",omitempty"`
	Unobserved      int `json:",omitempty"`
}

// Assess turns a cohort's handshake evidence into a verdict.
//
// The rules, and why each exists:
//   - a client with NO RESULT AT ALL makes the cohort incomplete. Silence is
//     not compatibility, and a wave that reached nine of ten clients must not
//     report on ten.
//   - UNREACHABLE is neither success nor rejection. It says nothing about PQ,
//     so it cannot be netted out of either column.
//   - ANY REJECTION halts. A PQ rollout breaks connections that used to work,
//     and one client refusing the new leaf is exactly the signal the canary
//     exists to surface — a percentage tolerance would let a lab certify a
//     migration that is already failing.
//   - a cohort where NOTHING negotiated is not ready even with no rejections,
//     because it has demonstrated nothing.
//   - when the cohort REQUIRES OBSERVED TRAFFIC, a negotiated client counts
//     only once an observer saw real clients connect at its endpoint after
//     the probe: still waiting is not ready, and a window that ended with no
//     connection is not ready either — the probe is one client, ours.
func Assess(c Cohort) Verdict {
	byClient := map[string]Result{}
	for _, r := range c.Results {
		byClient[strings.TrimSpace(r.ClientID)] = r
	}
	var v Verdict
	var missing []string
	for _, id := range c.Targeted {
		id = strings.TrimSpace(id)
		r, ok := byClient[id]
		if !ok {
			v.NotAttempted++
			missing = append(missing, id)
			continue
		}
		switch r.Outcome {
		case OutcomeNegotiated:
			v.Negotiated++
		case OutcomeRejected:
			v.Rejected++
		case OutcomeUnreachable:
			v.Unreachable++
		default:
			v.NotAttempted++
			missing = append(missing, id)
		}
	}

	if v.Rejected > 0 {
		v.Halt = true
		v.Summary = fmt.Sprintf(
			"HALT: %d of %d targeted clients REFUSED the PQ leaf. A rollout would break "+
				"connections that work today, and one refusal is the signal this canary exists to "+
				"surface — not a fraction to tolerate.", v.Rejected, len(c.Targeted))
		return v
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		v.Summary = fmt.Sprintf(
			"NOT READY: %d of %d targeted clients were never handshaked (%s). Silence is not "+
				"compatibility — a wave that reached fewer clients than it targeted must not "+
				"report on the ones it missed.",
			len(missing), len(c.Targeted), strings.Join(missing, ", "))
		return v
	}
	if v.Unreachable > 0 {
		v.Summary = fmt.Sprintf(
			"NOT READY: %d of %d clients were unreachable. That is not a rejection and not a "+
				"success — it says nothing about PQ compatibility, so it cannot be netted out of "+
				"either column.", v.Unreachable, len(c.Targeted))
		return v
	}
	if v.Negotiated == 0 {
		v.Summary = "NOT READY: nothing negotiated. A cohort that demonstrated nothing is not " +
			"evidence of readiness, however few failures it recorded."
		return v
	}
	if c.RequireObservedTraffic {
		return assessObservedTraffic(c, byClient, v)
	}
	v.Ready = true
	v.Summary = fmt.Sprintf(
		"Ready: all %d targeted clients negotiated the PQ leaf.", v.Negotiated)
	return v
}

// assessObservedTraffic finishes a verdict whose every targeted client
// negotiated, for a cohort that requires observed traffic.
func assessObservedTraffic(c Cohort, byClient map[string]Result, v Verdict) Verdict {
	var awaiting, unobserved []string
	for _, id := range c.Targeted {
		id = strings.TrimSpace(id)
		switch byClient[id].Traffic {
		case TrafficObserved:
		case TrafficUnobserved:
			unobserved = append(unobserved, id)
		default:
			awaiting = append(awaiting, id)
		}
	}
	v.AwaitingTraffic, v.Unobserved = len(awaiting), len(unobserved)
	if len(unobserved) > 0 {
		sort.Strings(unobserved)
		v.Summary = fmt.Sprintf(
			"NOT READY: %d of %d targeted clients negotiated the PQ leaf, but no real client was "+
				"observed connecting at %s within the observed-traffic window. The probe is one "+
				"client; silence from everyone else is not compatibility.",
			v.Negotiated, len(c.Targeted), strings.Join(unobserved, ", "))
		return v
	}
	if len(awaiting) > 0 {
		sort.Strings(awaiting)
		v.Summary = fmt.Sprintf(
			"AWAITING TRAFFIC: %d of %d targeted clients negotiated the PQ leaf; waiting for an "+
				"observer to see real clients connect at %s.",
			v.Negotiated, len(c.Targeted), strings.Join(awaiting, ", "))
		return v
	}
	v.Ready = true
	v.Summary = fmt.Sprintf(
		"Ready: all %d targeted clients negotiated the PQ leaf, and real clients were observed "+
			"connecting at each.", v.Negotiated)
	return v
}
