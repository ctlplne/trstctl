// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/usage"
)

// Reconciliation of metered totals against the event history (epic L2).
//
// The meters are written by a recorder the serving process runs; the event log
// is written by the orchestrator under AN-2. They are two independent records
// of the same activity, and an invoice should only be signed when they AGREE —
// a counter that drifted from the log is exactly the "quietly wrong number"
// the signable gate exists to keep off invoices.
//
// Not every meter has an independent source. certificates_issued does: every
// mint appends a lifecycle transition to `issued`, and the identity_transitions
// projection is that history made queryable (rebuilt from the log on demand,
// which is what makes it usable as a check rather than a copy). A gauge
// sampled from live state has no event to recount, and the honest document
// says so per line instead of implying every number was cross-checked.

// EvidenceReconciler recounts what the event history says happened in a
// period. ok=false means this deployment has no reconciliation source (an
// in-memory install), which the caller treats as unsignable rather than as
// agreement.
type EvidenceReconciler interface {
	IssuedInPeriod(ctx context.Context, tenantID string, from, to time.Time) (count int64, ok bool, err error)
}

// ReconciliationLine is one meter's cross-check, on the document.
type ReconciliationLine struct {
	Meter string `json:"meter"`
	// Metered is the durable counter's total for the period.
	Metered int64 `json:"metered"`
	// EventHistory is the independent recount, meaningful only when Checked.
	EventHistory int64 `json:"event_history"`
	// Checked says an independent source existed and was consulted. A line
	// with Checked=false and Matches=false is "nothing to check against",
	// which is a different fact from "checked and diverged".
	Checked bool `json:"checked"`
	Matches bool `json:"matches"`
	// Source names what the recount came from, so an auditor can repeat it.
	Source string `json:"source,omitempty"`
	Note   string `json:"note,omitempty"`
}

const transitionsSource = "identity_transitions projection of the event log (to_state=issued, occurred_at within the period)"

// ReconcileEvidence cross-checks the period's metered lines.
//
// Only certificates_issued has an independent recount today; other meters get
// a line saying no independent source exists. The empty-both case still emits
// a checked line: "the meter says zero and the log says zero" is a real
// finding for a period being invoiced at zero.
func ReconcileEvidence(ctx context.Context, rec EvidenceReconciler, p EvidencePeriod, lines []EvidenceLine) ([]ReconciliationLine, error) {
	if rec == nil {
		return nil, nil
	}
	var metered int64
	for _, l := range lines {
		if l.Meter == usage.MeterCertificatesIssued {
			metered = l.Value
		}
	}
	events, ok, err := rec.IssuedInPeriod(ctx, p.CustomerID, p.Start, p.End)
	if err != nil {
		return nil, fmt.Errorf("billing: recount issued certificates: %w", err)
	}
	out := []ReconciliationLine{{
		Meter:        usage.MeterCertificatesIssued,
		Metered:      metered,
		EventHistory: events,
		Checked:      ok,
		Matches:      ok && metered == events,
		Source:       transitionsSource,
	}}
	if !ok {
		out[0].Source = ""
		out[0].Note = "no event-history source is attached on this deployment; the metered value stands alone"
	}
	for _, l := range lines {
		if l.Meter == usage.MeterCertificatesIssued {
			continue
		}
		out = append(out, ReconciliationLine{
			Meter: l.Meter, Metered: l.Value,
			Checked: false, Matches: false,
			Note: "no independent event source for this meter; the metered value stands alone",
		})
	}
	return out, nil
}

// reconciliationBlocksSigning returns the refusal reason when a checked line
// diverged, or when the period was signable-by-coverage but nothing could be
// checked at all. Divergence and unverifiability both keep a signature off the
// document — the signature is precisely the claim that the number was stood
// behind, and "we could not check" must not be signed as "we checked".
func reconciliationBlocksSigning(recon []ReconciliationLine) (string, bool) {
	if len(recon) == 0 {
		return "The period's usage was never reconciled against the event history: no reconciliation " +
			"source is attached. A signature is the claim that this figure was checked, so an " +
			"unchecked figure cannot carry one.", true
	}
	for _, r := range recon {
		if r.Checked && !r.Matches {
			return fmt.Sprintf(
				"The %s meter reads %d but the event history records %d for this period. A counter "+
					"that disagrees with the log must not be invoiced from; one of the two records is "+
					"wrong and a signature would pick a side silently.",
				r.Meter, r.Metered, r.EventHistory), true
		}
	}
	if !recon[0].Checked {
		return "The period's primary meter could not be reconciled: " + recon[0].Note + ". A signature " +
			"is the claim that the figure was checked against an independent record.", true
	}
	return "", false
}
