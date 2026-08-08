// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// The invoice-evidence document (epic L2).
//
// This is what a provider hands their finance team, and what that team hands an
// auditor. So the document's job is not to look authoritative — it is to be
// checkable, and to refuse to exist when the underlying usage cannot support
// the claim.
//
// Two properties carry that. First, the document states its own COVERAGE and
// whether it is signable, so a reader never has to infer completeness from the
// absence of a warning. Second, the canonical form is deterministic, because a
// signature over a document whose bytes depend on map iteration order verifies
// on the machine that made it and nowhere else.

// EvidenceDocument is a period's usage, with the honesty fields a reader needs
// before trusting the numbers.
type EvidenceDocument struct {
	CustomerID  string         `json:"customer_id"`
	Period      EvidencePeriod `json:"-"`
	PeriodStart string         `json:"period_start"`
	PeriodEnd   string         `json:"period_end"`
	Lines       []EvidenceLine `json:"lines"`
	// Signable and Reason come straight from MaySign. They are ON THE DOCUMENT
	// rather than decided by the caller, so an unsignable period cannot be
	// rendered as a normal invoice by a client that forgot to check.
	Signable bool   `json:"signable"`
	Reason   string `json:"reason"`
	// ObservedFrom/To is what the metering store could actually vouch for. A
	// reader comparing these to the period sees the gap directly rather than
	// inferring it.
	ObservedFrom string `json:"observed_from,omitempty"`
	ObservedTo   string `json:"observed_to,omitempty"`
	// Reconciliation is the cross-check of metered totals against the event
	// history, per line. It is INSIDE the digest: the check's outcome is part
	// of what the signature attests, so the same numbers cannot circulate
	// both as reconciled and unreconciled under one digest.
	Reconciliation []ReconciliationLine `json:"reconciliation,omitempty"`
	// Digest is over the canonical form. Present even when unsignable, because
	// an auditor may still want to prove WHICH unsignable document they were
	// shown.
	Digest string `json:"digest"`
	// Signature is the detached JWS over the canonical bytes, present ONLY
	// when the document is signable and a signing key is attached. An
	// unsignable document never carries one — the absence is the point.
	Signature *EvidenceSignature `json:"signature,omitempty"`
	Guidance  string             `json:"guidance"`
}

// EvidenceLine is one meter's total for the period.
type EvidenceLine struct {
	Meter string `json:"meter"`
	Kind  string `json:"kind"`
	Value int64  `json:"value"`
}

const evidenceGuidance = "This document states its own completeness. Read `signable` before the " +
	"numbers: a period the metering store could not cover end to end is reported with signable " +
	"false and a reason, and the totals below are then a partial view rather than an invoice. The " +
	"digest covers the canonical form and is present either way, so an unsignable document can " +
	"still be identified later."

// BuildEvidence assembles a period's document from durable usage.
//
// Lines are SORTED by meter. Map iteration order in Go is randomised, so an
// unsorted document would hash differently on every build and a signature over
// it would verify only on the machine that produced it.
//
// Reconciliation and signing are applied by BuildSignedEvidence; this
// assembles the numbers and the coverage verdict.
func BuildEvidence(p EvidencePeriod, c Coverage, records []UsageRecord, now time.Time) EvidenceDocument {
	totals := map[string]*EvidenceLine{}
	for _, r := range records {
		if r.TenantID != p.CustomerID {
			continue
		}
		if r.PeriodStart.Before(p.Start) || !r.PeriodStart.Before(p.End) {
			continue
		}
		line, ok := totals[r.Meter]
		if !ok {
			line = &EvidenceLine{Meter: r.Meter, Kind: r.Kind}
			totals[r.Meter] = line
		}
		// Counters sum; a gauge is a level and takes the latest value rather
		// than accumulating, or the total would be meaningless.
		if r.Kind == "gauge" {
			line.Value = r.Value
			continue
		}
		line.Value += r.Value
	}
	doc := EvidenceDocument{
		CustomerID:  p.CustomerID,
		Period:      p,
		PeriodStart: p.Start.UTC().Format(time.RFC3339),
		PeriodEnd:   p.End.UTC().Format(time.RFC3339),
		Lines:       make([]EvidenceLine, 0, len(totals)),
		Guidance:    evidenceGuidance,
	}
	for _, l := range totals {
		doc.Lines = append(doc.Lines, *l)
	}
	sort.Slice(doc.Lines, func(i, j int) bool { return doc.Lines[i].Meter < doc.Lines[j].Meter })

	decision := MaySign(p, c, now)
	doc.Signable, doc.Reason = decision.Signable, decision.Reason
	if !c.ObservedFrom.IsZero() {
		doc.ObservedFrom = c.ObservedFrom.UTC().Format(time.RFC3339)
	}
	if !c.ObservedTo.IsZero() {
		doc.ObservedTo = c.ObservedTo.UTC().Format(time.RFC3339)
	}
	doc.Digest = doc.canonicalDigest()
	return doc
}

// BuildSignedEvidence is the full document: numbers, coverage verdict,
// event-history reconciliation, and — only when everything holds — the
// detached signature.
//
// The order is the design: coverage can refuse, reconciliation can refuse,
// and the signature is applied last over the canonical bytes that INCLUDE
// both verdicts. A reconciliation failure flips signable even for a period
// coverage was happy with, because a counter that disagrees with the log is
// exactly the quietly-wrong number the gate exists to stop.
func BuildSignedEvidence(ctx context.Context, p EvidencePeriod, c Coverage, records []UsageRecord,
	rec EvidenceReconciler, signer EvidenceSigner, now time.Time) (EvidenceDocument, error) {
	doc := BuildEvidence(p, c, records, now)
	recon, err := ReconcileEvidence(ctx, rec, p, doc.Lines)
	if err != nil {
		return EvidenceDocument{}, err
	}
	doc.Reconciliation = recon
	if doc.Signable {
		if reason, blocked := reconciliationBlocksSigning(recon); blocked {
			doc.Signable, doc.Reason = false, reason
		}
	}
	doc.Digest = doc.canonicalDigest()
	if doc.Signable {
		if signer == nil {
			// Signable data with nothing to sign it is served as UNSIGNABLE:
			// the route's contract is a signed document, and "the numbers are
			// fine but unattested" invites exactly the take-it-anyway reading
			// the signature exists to prevent.
			doc.Signable = false
			doc.Reason = "The figures are complete and reconciled, but no evidence-signing key is " +
				"attached on this deployment, so the document cannot carry the attestation an " +
				"invoice needs. Attach the audit signing key (audit.signing_key_file)."
			doc.Digest = doc.canonicalDigest()
			return doc, nil
		}
		sig, err := signer.SignEvidence(doc.canonicalBytes())
		if err != nil {
			return EvidenceDocument{}, err
		}
		doc.Signature = sig
	}
	return doc, nil
}

// canonicalBytes is the deterministic rendering the digest hashes and the
// signature signs — one input, two attestations.
//
// The signable flag and the reason are INSIDE it. If they were outside, the
// same numbers could be presented as signable or not without changing the
// hash — which would let somebody strip the warning off a partial period and
// keep a valid-looking digest. Reconciliation lines are inside it for the
// same reason: "checked and matched" must not be strippable.
func (d EvidenceDocument) canonicalBytes() []byte {
	var b strings.Builder
	b.WriteString(d.CustomerID)
	b.WriteByte('\n')
	b.WriteString(d.PeriodStart)
	b.WriteByte('\n')
	b.WriteString(d.PeriodEnd)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatBool(d.Signable))
	b.WriteByte('\n')
	b.WriteString(d.Reason)
	b.WriteByte('\n')
	b.WriteString(d.ObservedFrom)
	b.WriteByte('\n')
	b.WriteString(d.ObservedTo)
	b.WriteByte('\n')
	for _, l := range d.Lines {
		fmt.Fprintf(&b, "%s|%s|%d\n", l.Meter, l.Kind, l.Value)
	}
	for _, r := range d.Reconciliation {
		fmt.Fprintf(&b, "reconcile:%s|%d|%d|%t|%t\n", r.Meter, r.Metered, r.EventHistory, r.Checked, r.Matches)
	}
	return []byte(b.String())
}

// canonicalDigest hashes the canonical rendering.
func (d EvidenceDocument) canonicalDigest() string {
	// Through internal/crypto, not crypto/sha256 directly: AN-3 keeps every
	// hash in one place so an algorithm change is a single-package change, and
	// the linter enforces it. It caught this import.
	return crypto.SHA256Hex(d.canonicalBytes())
}
