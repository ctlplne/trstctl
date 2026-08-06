// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"strings"
	"testing"
	"time"
)

func docRecords() []UsageRecord {
	return []UsageRecord{
		{TenantID: "bank-a", Meter: "certs.issued", Kind: "counter", PeriodStart: pStart.Add(time.Hour), Value: 10},
		{TenantID: "bank-a", Meter: "certs.issued", Kind: "counter", PeriodStart: pStart.Add(2 * time.Hour), Value: 7},
		// TWO gauge readings on purpose. With one, "latest wins" and "sum" give
		// the same answer, and the test cannot tell them apart — a mutation that
		// accumulated gauges passed against a single reading.
		{TenantID: "bank-a", Meter: "agents.active", Kind: "gauge", PeriodStart: pStart.Add(time.Hour), Value: 4},
		{TenantID: "bank-a", Meter: "agents.active", Kind: "gauge", PeriodStart: pStart.Add(2 * time.Hour), Value: 6},
		// Another customer's usage, and one outside the window. Neither belongs.
		{TenantID: "bank-b", Meter: "certs.issued", Kind: "counter", PeriodStart: pStart.Add(time.Hour), Value: 999},
		{TenantID: "bank-a", Meter: "certs.issued", Kind: "counter", PeriodStart: pEnd.Add(time.Hour), Value: 500},
	}
}

// Counters sum; a gauge is a LEVEL and must not accumulate, or the total is
// meaningless.
func TestCountersSumAndGaugesDoNot(t *testing.T) {
	t.Parallel()
	doc := BuildEvidence(period(), fullDurable(), docRecords(), after)
	byMeter := map[string]int64{}
	for _, l := range doc.Lines {
		byMeter[l.Meter] = l.Value
	}
	if byMeter["certs.issued"] != 17 {
		t.Fatalf("counter total = %d, want 17 (10+7, excluding the other customer and the "+
			"out-of-window row)", byMeter["certs.issued"])
	}
	if byMeter["agents.active"] != 6 {
		t.Fatalf("gauge = %d, want 6 (the latest reading, not 4+6=10). Accumulating a level would "+
			"invoice a customer for the sum of every reading rather than what they actually had",
			byMeter["agents.active"])
	}
}

// Another customer's usage must never appear on this document.
func TestAnotherCustomersUsageIsNeverBilledHere(t *testing.T) {
	t.Parallel()
	doc := BuildEvidence(period(), fullDurable(), docRecords(), after)
	for _, l := range doc.Lines {
		if l.Value >= 999 {
			t.Fatalf("a line carries another customer's usage: %+v.\n\n"+
				"Billing one customer for another's activity is the single worst arithmetic error "+
				"this document can make.", l)
		}
	}
}

// The canonical form must be deterministic. Go randomises map iteration, so an
// unsorted document would hash differently on every build and a signature over
// it would verify only on the machine that produced it.
func TestTheDigestIsStableAcrossBuilds(t *testing.T) {
	t.Parallel()
	first := BuildEvidence(period(), fullDurable(), docRecords(), after)
	for i := 0; i < 20; i++ {
		again := BuildEvidence(period(), fullDurable(), docRecords(), after)
		if again.Digest != first.Digest {
			t.Fatalf("digest changed between builds (%s vs %s).\n\n"+
				"Map iteration order is randomised in Go, so a signature over an unstable "+
				"rendering verifies on the machine that made it and nowhere else.",
				first.Digest, again.Digest)
		}
	}
}

// The signable flag and its reason are INSIDE the digest, so a warning cannot
// be stripped off a partial period while keeping a valid-looking hash.
func TestStrippingTheWarningChangesTheDigest(t *testing.T) {
	t.Parallel()
	// The two coverages differ ONLY in Durable, so ObservedFrom/To are identical
	// on both documents. An earlier version of this test used a SHORT coverage
	// window, which also changed ObservedTo — so the digest differed for the
	// wrong reason and the test passed even with the signable flag removed from
	// the hash. It proved the timestamps were hashed, not the warning.
	nonDurable := fullDurable()
	nonDurable.Durable = false
	unsignable := BuildEvidence(period(), nonDurable, docRecords(), after)
	signable := BuildEvidence(period(), fullDurable(), docRecords(), after)

	if unsignable.Signable {
		t.Fatal("in-memory usage was marked signable")
	}
	if unsignable.ObservedFrom != signable.ObservedFrom || unsignable.ObservedTo != signable.ObservedTo {
		t.Fatalf("precondition: the two documents must differ only in signability, but coverage "+
			"differs (%s..%s vs %s..%s)", unsignable.ObservedFrom, unsignable.ObservedTo,
			signable.ObservedFrom, signable.ObservedTo)
	}
	if unsignable.Digest == signable.Digest {
		t.Fatal("the same numbers hash identically whether or not the period is signable.\n\n" +
			"That would let somebody strip the warning off a partial period and keep a " +
			"valid-looking digest — the document would then claim completeness it never had.")
	}
}

// An unsignable document still carries a digest: an auditor may need to prove
// WHICH unsignable document they were shown.
func TestAnUnsignableDocumentStillHasADigest(t *testing.T) {
	t.Parallel()
	nonDurable := fullDurable()
	nonDurable.Durable = false
	doc := BuildEvidence(period(), nonDurable, docRecords(), after)
	if doc.Signable {
		t.Fatal("in-memory usage was marked signable")
	}
	if doc.Digest == "" {
		t.Fatal("an unsignable document has no digest, so it cannot be identified later")
	}
	if !strings.Contains(doc.Reason, "silently short") {
		t.Errorf("the document does not carry the reason it cannot be signed: %q", doc.Reason)
	}
}

// Coverage is stated on the document, so a reader sees the gap directly rather
// than inferring it from the absence of a warning.
func TestTheDocumentStatesItsOwnCoverage(t *testing.T) {
	t.Parallel()
	doc := BuildEvidence(period(), fullDurable(), docRecords(), after)
	if doc.ObservedFrom == "" || doc.ObservedTo == "" {
		t.Fatal("the document does not state what the metering store actually observed; a reader " +
			"would have to infer completeness from the absence of a warning")
	}
}
