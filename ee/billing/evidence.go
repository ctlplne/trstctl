// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"fmt"
	"time"
)

// When a metering period may be signed as invoice evidence (epic L2).
//
// Metering is in-memory today. That does not merely lose data on restart — it
// loses it SILENTLY. A provider pulls a number, invoices from it, and never
// learns the number was short; the customer is under-billed and the provider's
// revenue quietly disappears into a process restart nobody correlated.
//
// So the question this file answers is not "what did we count" but "may we sign
// what we counted". Signing is a claim that the figure is complete, and a
// signature over an incomplete figure is worse than no evidence at all: it
// converts a gap somebody might have noticed into an attestation somebody will
// rely on.

// EvidencePeriod is a metering window a provider would invoice against.
type EvidencePeriod struct {
	CustomerID string
	Start      time.Time
	End        time.Time
}

// Coverage is what the metering store can actually vouch for over a period.
type Coverage struct {
	// ObservedFrom and ObservedTo bound what the store actually holds. If they
	// do not span the whole period, the figure is short by an unknown amount.
	ObservedFrom time.Time
	ObservedTo   time.Time
	// RestartsWithin counts process restarts inside the period. With in-memory
	// metering each one is an unknown quantity of lost usage; with a durable
	// store it is merely a fact.
	RestartsWithin int
	// Durable reports whether the counts came from a durable store. An
	// in-memory store cannot vouch for anything across a restart, and saying so
	// is the difference between evidence and a guess.
	Durable bool
}

// EvidenceDecision is whether a period may be signed, and why not.
type EvidenceDecision struct {
	Signable bool
	// Reason is what a finance team reads. For a refusal it must say what is
	// missing, because "cannot sign" alone gets escalated as a bug rather than
	// acted on as a gap.
	Reason string
}

// MaySign decides whether a period's usage may be signed as invoice evidence.
//
// Every refusal path here exists because the alternative is a signed number
// that is quietly wrong:
//   - a NON-DURABLE store cannot vouch across a restart, and a provider cannot
//     tell from the figure alone whether one happened.
//   - PARTIAL COVERAGE means the store's own window does not span the period it
//     is being asked to attest.
//   - a RESTART inside the period on a non-durable store means usage was lost;
//     the figure is short by an amount nobody can reconstruct.
//   - a period that has NOT CLOSED is still accruing, and signing it invites an
//     invoice built from a partial month.
func MaySign(p EvidencePeriod, c Coverage, now time.Time) EvidenceDecision {
	if p.CustomerID == "" || !p.End.After(p.Start) {
		return EvidenceDecision{Reason: "The period is not a real window; there is nothing to attest."}
	}
	if now.Before(p.End) {
		return EvidenceDecision{Reason: fmt.Sprintf(
			"The period has not closed yet (ends %s). Usage is still accruing, and signing now "+
				"produces evidence for a partial month that reads like a final figure.",
			p.End.UTC().Format(time.RFC3339))}
	}
	if !c.Durable {
		return EvidenceDecision{Reason: "Usage is metered IN MEMORY, so it cannot be vouched for " +
			"across a process restart. Signing it would attest a figure that may be silently short " +
			"— which is worse than no evidence, because a signature turns a gap somebody might " +
			"have questioned into a number they will rely on."}
	}
	if c.ObservedFrom.After(p.Start) || c.ObservedTo.Before(p.End) {
		return EvidenceDecision{Reason: fmt.Sprintf(
			"The metering store only covers %s to %s, which does not span the period. The figure "+
				"is short by an unknown amount.",
			c.ObservedFrom.UTC().Format(time.RFC3339), c.ObservedTo.UTC().Format(time.RFC3339))}
	}
	if c.RestartsWithin > 0 && !c.Durable {
		return EvidenceDecision{Reason: fmt.Sprintf(
			"%d process restart(s) fell inside the period and metering was not durable across "+
				"them.", c.RestartsWithin)}
	}
	return EvidenceDecision{Signable: true,
		Reason: "The period is closed and durably covered end to end; the figure can be attested."}
}
