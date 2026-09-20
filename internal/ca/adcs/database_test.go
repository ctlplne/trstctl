// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"testing"
)

// A pending request is not a failure. Rendering it as one makes an operator
// re-submit rather than go and approve — and the CA team gets duplicate
// requests instead of an approval.
func TestPendingIsNotFailed(t *testing.T) {
	t.Parallel()
	if MapDisposition(9) != DispositionPending {
		t.Fatalf("disposition 9 = %q, want pending", MapDisposition(9))
	}
	if DispositionPending == DispositionFailed {
		t.Fatal("pending and failed are the same value; an operator would re-submit a request " +
			"that is sitting waiting for their CA manager to approve it")
	}
	if DispositionDenied == DispositionFailed {
		t.Fatal("denied and failed are the same value. A human decided one of them, and " +
			"re-submitting a denied request is how people annoy their CA team")
	}
}

// Microsoft adds disposition codes. Guessing "failure" reports healthy
// certificates as broken.
func TestAnUnknownDispositionCodeIsUnknownNotFailed(t *testing.T) {
	t.Parallel()
	if got := MapDisposition(9999); got != DispositionUnknown {
		t.Fatalf("unrecognised code mapped to %q. A build that guesses \"failure\" reports "+
			"healthy certificates as broken the first time it meets a code Microsoft added", got)
	}
}

// A row with no request id cannot be reconciled and must not enter inventory.
func TestARowWithNoRequestIDIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := ParseDBRow(map[string]string{"CommonName": "web.corp"}); err == nil {
		t.Fatal("a row with no request id was accepted. It cannot be reconciled against " +
			"anything, and an unreconcilable row inflates coverage")
	}
}

// certutil output varies by version and locale. A parser that demanded one
// exact shape would work in a lab and nowhere else.
func TestParsingToleratesColumnNamingVariants(t *testing.T) {
	t.Parallel()
	for _, fields := range []map[string]string{
		{"RequestID": "42", "SerialNumber": "1A 2B 3C", "CommonName": "web.corp",
			"CertificateTemplate": "WebServer", "Request.Disposition": "20", "NotAfter": "2027-01-01T00:00:00Z"},
		{"Request ID": "42", "Serial Number": "1a2b3c", "Common Name": "web.corp",
			"Certificate Template": "WebServer", "Disposition": "20", "NotAfter": "2027-01-01 00:00:00"},
	} {
		row, err := ParseDBRow(fields)
		if err != nil {
			t.Fatalf("%v: %v", fields, err)
		}
		if row.RequestID != 42 || row.Subject != "web.corp" || row.Template != "WebServer" {
			t.Fatalf("parsed = %+v", row)
		}
		if row.Serial != "1a2b3c" {
			t.Fatalf("serial = %q; it must normalise so the same certificate from two exports "+
				"does not become two inventory rows", row.Serial)
		}
		if row.Disposition != DispositionIssued {
			t.Fatalf("disposition = %q, want issued", row.Disposition)
		}
	}
}

// An unparseable expiry is a VISIBILITY gap, not a certificate that expired in
// year zero. The obvious use of this field is an expiry sweep.
func TestAnUnparseableExpiryIsCountedAsAGapNotAnExpiry(t *testing.T) {
	t.Parallel()
	row, err := ParseDBRow(map[string]string{
		"RequestID": "7", "Request.Disposition": "20", "NotAfter": "sometime next Tuesday",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !row.NotAfter.IsZero() {
		t.Fatalf("NotAfter = %v, want zero for an unparseable value", row.NotAfter)
	}
	s := Summarize([]DBRow{row})
	if s.Unparsed != 1 {
		t.Fatalf("unparsed = %d, want 1.\n\n"+
			"An issued certificate whose expiry we could not read is a gap in visibility. If it "+
			"is not counted, the ingestion claims complete coverage it does not have — and a "+
			"zero NotAfter in an expiry sweep reads as expired in year zero.", s.Unparsed)
	}
}

// Every disposition is counted separately: one "certificates found" number
// hides that half are waiting on somebody's approval.
func TestSummaryCountsEachDispositionSeparately(t *testing.T) {
	t.Parallel()
	rows := []DBRow{
		{RequestID: 1, Disposition: DispositionIssued, NotAfter: parseDBTime("2027-01-01T00:00:00Z")},
		{RequestID: 2, Disposition: DispositionPending},
		{RequestID: 3, Disposition: DispositionRevoked},
		{RequestID: 4, Disposition: DispositionDenied},
		{RequestID: 5, Disposition: DispositionUnknown},
	}
	s := Summarize(rows)
	if s.Issued != 1 || s.Pending != 1 || s.Revoked != 1 || s.Denied != 1 || s.Unknown != 1 {
		t.Fatalf("summary = %+v; each disposition needs its own count, because a single total "+
			"hides that a request is waiting for a CA manager", s)
	}
	if s.Total != 5 {
		t.Fatalf("total = %d, want 5", s.Total)
	}
}
