// SPDX-License-Identifier: MPL-2.0

package ownership

import (
	"strings"
	"testing"
	"time"
)

// What a bulk ownership import must refuse to do (epic I2).
//
// The acceptance asks for conflict resolution, and the resolution that matters
// is not "apply the source". An external system's view of who owns a
// certificate is a claim, sometimes a stale one, and the record it would
// overwrite may be the only thing a human ever confirmed.
//
// Last-writer-wins is what makes CMDB integrations distrusted: one import
// replaces a verified owner with a disbanded team's alias, the expiry notice
// goes nowhere, and nobody learns why until the certificate expires.

var observed = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func TestAnImportNeverOverwritesOwnershipAHumanAttested(t *testing.T) {
	t.Parallel()
	plan := Reconcile(
		Record{OwnerName: "payments", ApplicationID: "APP-999", SourceRef: "ci-4711"},
		Existing{OwnerID: "o1", ApplicationID: "APP-123", Source: SourceManual, Attested: true},
		SourceCSVImport, observed,
	)

	if len(plan.Apply) != 0 {
		t.Fatalf("import applied %d change(s) over attested ownership: %+v\n\n"+
			"Attestation is the scarcest fact in the system. A spreadsheet overwriting it is how "+
			"an expiry notice ends up going to a team that no longer exists.", len(plan.Apply), plan.Apply)
	}
	if len(plan.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want exactly one recorded disagreement", len(plan.Conflicts))
	}
	c := plan.Conflicts[0]
	if c.CurrentValue != "APP-123" || c.IncomingValue != "APP-999" {
		t.Errorf("conflict does not carry both sides: %+v", c)
	}
	if c.IncomingRef != "ci-4711" {
		t.Errorf("conflict does not name the source row that caused it: %q. A conflict nobody can "+
			"trace back is a conflict nobody can resolve", c.IncomingRef)
	}
	if !c.CurrentAttested {
		t.Error("conflict does not record that the stored side was attested — the reason it was refused")
	}
	if !strings.Contains(c.Why, "Not applied") {
		t.Errorf("conflict reason does not say the change was refused: %q. A conflict list whose "+
			"entries read like completed work is worse than no list", c.Why)
	}
}

// Filling in what nobody knew is the main thing an import is for, and must
// always work.
func TestAnImportFillsInUnknownFields(t *testing.T) {
	t.Parallel()
	plan := Reconcile(
		Record{OwnerName: "payments", ApplicationID: "APP-123", Service: "checkout", SourceRef: "ci-1"},
		Existing{OwnerID: "o1", Attested: true}, // attested, but nothing recorded to overwrite
		SourceCSVImport, observed,
	)
	if len(plan.Apply) != 2 {
		t.Fatalf("applied %d, want both unknown fields filled: %+v", len(plan.Apply), plan.Apply)
	}
	if len(plan.Conflicts) != 0 {
		t.Fatalf("filling an unknown field raised a conflict: %+v. Attestation protects what a "+
			"human SAID, not fields they left blank", plan.Conflicts)
	}
	for _, u := range plan.Apply {
		if u.Source != SourceCSVImport || u.Ref != "ci-1" {
			t.Errorf("update carries no provenance: %+v", u)
		}
	}
}

// A blank cell is silence, not a deletion.
//
// Treating an empty column as "set this to empty" is how a bulk import erases
// data nobody meant to touch — and the erasure looks like a successful import.
func TestABlankCellIsSilenceNotADeletion(t *testing.T) {
	t.Parallel()
	plan := Reconcile(
		Record{OwnerName: "payments", ApplicationID: "", Service: "checkout"},
		Existing{OwnerID: "o1", ApplicationID: "APP-123", Service: "", Attested: false},
		SourceCSVImport, observed,
	)
	for _, u := range plan.Apply {
		if u.Field == "application_id" {
			t.Fatalf("a blank cell deleted a stored value: %+v\n\nSaying nothing about a field is "+
				"not saying it is empty, and an import that treats it as one erases data while "+
				"reporting success", u)
		}
	}
	if len(plan.Apply) != 1 || plan.Apply[0].Field != "service" {
		t.Fatalf("apply = %+v, want only the field the source actually spoke about", plan.Apply)
	}
}

// An unattested change is applied AND recorded.
//
// Nobody vouched for the old value, so taking the newer one is defensible. It
// still changed, and a change nobody was told about is how ownership data
// quietly stops matching reality.
func TestAnUnattestedChangeIsAppliedAndStillRecorded(t *testing.T) {
	t.Parallel()
	plan := Reconcile(
		Record{OwnerName: "payments", ApplicationID: "APP-999", SourceRef: "ci-7"},
		Existing{OwnerID: "o1", ApplicationID: "APP-123", Source: SourceCSVImport, Attested: false},
		SourceCMDB, observed,
	)
	if len(plan.Apply) != 1 {
		t.Fatalf("apply = %+v, want the change applied — nobody attested the old value", plan.Apply)
	}
	if len(plan.Conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want the change recorded even though it was applied", plan.Conflicts)
	}
	if plan.Conflicts[0].CurrentAttested {
		t.Error("recorded the unattested change as attested")
	}
	if !strings.Contains(plan.Conflicts[0].Why, "Applied") {
		t.Errorf("reason does not say the change WAS applied: %q — an operator reading this list "+
			"must be able to tell what changed from what did not", plan.Conflicts[0].Why)
	}
}

// Matching values are neither applied nor flagged, and are counted so a re-run
// reads as "already in sync" rather than "did nothing".
func TestMatchingValuesAreCountedNotApplied(t *testing.T) {
	t.Parallel()
	plan := Reconcile(
		Record{OwnerName: "payments", ApplicationID: "APP-123", Service: "checkout"},
		Existing{OwnerID: "o1", ApplicationID: "APP-123", Service: "checkout", Attested: true},
		SourceCSVImport, observed,
	)
	if len(plan.Apply) != 0 || len(plan.Conflicts) != 0 {
		t.Fatalf("identical values produced work: apply=%+v conflicts=%+v", plan.Apply, plan.Conflicts)
	}
	if plan.Unchanged != 2 {
		t.Fatalf("unchanged = %d, want 2. Without this a re-run reports zero applied, which reads "+
			"as a failed import rather than an estate already in sync", plan.Unchanged)
	}
}

// A CSV export from last quarter is not a live reconciliation.
//
// Keeping the two sources distinct stops stale data inheriting a live source's
// credibility when somebody later asks where a value came from.
func TestCSVImportAndCMDBAreDistinctSources(t *testing.T) {
	t.Parallel()
	if SourceCSVImport == SourceCMDB {
		t.Fatal("a file somebody exported is recorded identically to a live reconciliation")
	}
	if SourceUnknown == SourceManual {
		t.Fatal("an unrecorded origin is recorded identically to a human's answer; absence of " +
			"provenance is not evidence of a human")
	}
	if SourceUnknown != "" {
		t.Fatalf("SourceUnknown = %q, want the empty string so a pre-provenance row reads as unknown",
			SourceUnknown)
	}
}

func TestCSVParsingRefusesRowsItCannotAttribute(t *testing.T) {
	t.Parallel()
	if _, err := ParseCSV(strings.NewReader("owner,application_id\npayments,APP-1\n,APP-2\n")); err == nil {
		t.Fatal("a row naming no owner was accepted; it cannot be attributed to anything, and " +
			"skipping it silently makes the import's count disagree with the file")
	}
	if _, err := ParseCSV(strings.NewReader("application_id\nAPP-1\n")); err == nil {
		t.Fatal("a csv with no owner column was accepted")
	}
	recs, err := ParseCSV(strings.NewReader("owner,application_id,service\npayments,APP-1,checkout\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ApplicationID != "APP-1" || recs[0].Service != "checkout" {
		t.Fatalf("parsed = %+v", recs)
	}
	// A row with no explicit reference still gets a traceable one.
	if recs[0].SourceRef != "line:2" {
		t.Errorf("source ref = %q, want a line reference so the row can be traced", recs[0].SourceRef)
	}
}

// Column order and extra columns must not matter: a real CMDB export has
// dozens of columns in whatever order the tool emitted.
func TestParsingFollowsTheHeaderNotTheColumnOrder(t *testing.T) {
	t.Parallel()
	recs, err := ParseCSV(strings.NewReader(
		"sys_id,service,unrelated,owner,application_id\nci-9,checkout,junk,payments,APP-1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].OwnerName != "payments" || recs[0].ApplicationID != "APP-1" || recs[0].Service != "checkout" {
		t.Fatalf("parsed = %+v; the header names the columns, so extra ones in a different order "+
			"must still import", recs)
	}
}
