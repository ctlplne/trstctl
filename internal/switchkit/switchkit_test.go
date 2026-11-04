// SPDX-License-Identifier: BUSL-1.1

package switchkit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func fingerprintOf(i int) string { return crypto.SHA256Hex([]byte(fmt.Sprintf("a265-cert-%d", i))) }

// seedExport is several thousand rows across nested folders, owners and
// application groups, with the defects a real export carries.
func seedExport(n int) string {
	var b strings.Builder
	b.WriteString("Thumbprint,Subject CN,Valid To,Policy Folder,App Group,Owner,Renewal Days,Installed At\n")
	for i := 1; i <= n; i++ {
		fp := fingerprintOf(i)
		notAfter := now.AddDate(0, 0, 30+i%300).Format("2006-01-02")
		endpoint := fmt.Sprintf("svc-%d.example.test:443", i)
		switch {
		case i%997 == 0:
			fp = fingerprintOf(i - 1) // a duplicate of the row before
		case i%499 == 0:
			fp = "not-a-fingerprint"
		case i%251 == 0:
			notAfter = now.AddDate(0, 0, -3).Format("2006-01-02")
		case i%7 == 0:
			endpoint = ""
		}
		folder := fmt.Sprintf("Root\\Region %d\\Team %d", i%4, i%9)
		fmt.Fprintf(&b, "%s,svc-%d.example.test,%s,%s,app-%d,owner-%d@example.test,%d,%s\n",
			fp, i, notAfter, folder, i%12, i%25, 30, endpoint)
	}
	return b.String()
}

var columnMap = map[string]string{
	"Thumbprint": "fingerprint_sha256", "Subject CN": "common_name", "Valid To": "not_after",
	"Policy Folder": "folder", "App Group": "application", "Owner": "owner_email",
	"Renewal Days": "renewal_window_days", "Installed At": "endpoints",
}

// A265: several thousand rows, nested folders, owners and application groups
// map with a report that accounts for every row.
func TestMapAccountsForEveryRowOfAThousandsRowExport(t *testing.T) {
	const n = 3500
	rows, err := Parse([]byte(seedExport(n)), columnMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != n {
		t.Fatalf("parsed %d rows, want %d", len(rows), n)
	}
	owner3 := ExistingOwners{OwnerKey("Owner-3@example.test", "app-3"): "00000000-0000-4000-8000-000000000003"}
	report := Map(rows, owner3, now)
	total := 0
	for _, c := range report.Counts {
		total += c
	}
	if total != n || len(report.Items) != n || report.Rows != n {
		t.Fatalf("outcomes cover %d rows, items %d, want %d: %v", total, len(report.Items), n, report.Counts)
	}
	for _, m := range report.Items {
		if m.Outcome == "" {
			t.Fatalf("row %d has no outcome", m.Row)
		}
		if (m.Outcome == OutcomeUnparseable || m.Outcome == OutcomeExpired || m.Outcome == OutcomeDuplicate) && m.Reason == "" {
			t.Fatalf("row %d is %s with no reason", m.Row, m.Outcome)
		}
	}
	if report.Counts[OutcomeDuplicate] == 0 || report.Counts[OutcomeUnparseable] == 0 || report.Counts[OutcomeExpired] == 0 ||
		report.GapCounts["no endpoint"] == 0 {
		t.Fatalf("seeded defects not reported: %v %v", report.Counts, report.GapCounts)
	}
	if len(report.Folders) != 36 || !strings.HasPrefix(report.Folders[0].Profile, "switched-root-region-") {
		t.Fatalf("folders = %d, first %+v", len(report.Folders), report.Folders[0])
	}
	// One owner per email in each application group: 25 emails across 12
	// groups make 300 pairs, and only owner-3 in app-3 already exists.
	if len(report.Owners) != 300 || len(report.Applications) != 12 {
		t.Fatalf("owners %d applications %d", len(report.Owners), len(report.Applications))
	}
	for _, o := range report.Owners {
		if (o.Email == "owner-3@example.test" && o.Application == "app-3") != (o.OwnerID != "" && !o.Create) {
			t.Fatalf("owner match = %+v", o)
		}
	}
	// The digest binds the rows: the same export digests the same; one changed
	// row changes it.
	again := Map(rows, owner3, now)
	rows[10].Fields["application"] = "moved"
	moved := Map(rows, owner3, now)
	if again.Digest != report.Digest || moved.Digest == report.Digest {
		t.Fatalf("digest not stable or not binding: %s %s %s", report.Digest, again.Digest, moved.Digest)
	}
}

func TestJSONExportWithACertificateAndBadRows(t *testing.T) {
	served, err := tlsprobe.NewServingTestServer("api.a265.example.test")
	if err != nil {
		t.Fatal(err)
	}
	served.Close()
	info, err := certinfo.Inspect(served.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(served.LeafPEM)
	export, _ := json.Marshal(map[string]any{"certificates": []map[string]any{
		{"certificate_pem": certPEM, "folder": "Web/Public", "application": "storefront", "owner_email": "web@example.test",
			"endpoints": []string{"api.a265.example.test:443"}},
		{"certificate_pem": "-----BEGIN NOTHING-----"},
		{"common_name": "no-fingerprint.example.test"},
		{"fingerprint_sha256": strings.ToUpper(fingerprintOf(9)), "not_after": "next tuesday"},
		{"fingerprint_sha256": fingerprintOf(10), "endpoints": "bad-endpoint"},
	}})
	rows, err := Parse(export, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The listener's certificate is valid from now; map it as of a moment
	// inside its validity.
	report := Map(rows, nil, info.NotBefore.Add(time.Minute))
	want := []string{OutcomeMapped, OutcomeUnparseable, OutcomeUnparseable, OutcomeUnparseable, OutcomeMappedWithGaps}
	for i, m := range report.Items {
		if m.Outcome != want[i] {
			t.Errorf("row %d = %s (%s), want %s", m.Row, m.Outcome, m.Reason, want[i])
		}
	}
	first := report.Items[0]
	if !first.HasPEM || first.Fingerprint != info.SHA256Fingerprint || first.CommonName != "api.a265.example.test" ||
		first.Folder != "Web/Public" || first.Endpoints[0] != "api.a265.example.test:443" {
		t.Fatalf("certificate row = %+v", first)
	}
	if !strings.Contains(strings.Join(report.Items[4].Gaps, ";"), "not host:port") {
		t.Fatalf("bad endpoint not reported: %+v", report.Items[4])
	}
	if _, err := Parse([]byte("a,b\n1,2\n"), map[string]string{"a": "nonsense"}); err == nil {
		t.Fatal("a column map to an unknown field was accepted")
	}
}

// A mapped row already in the inventory is marked, counted and bound into the
// digest; an unusable row is never marked.
func TestMarkKnownBindsTheInventoryIntoTheDigest(t *testing.T) {
	rows, err := Parse([]byte(seedExport(600)), columnMap)
	if err != nil {
		t.Fatal(err)
	}
	report := Map(rows, nil, now)
	before := report.Digest
	report.MarkKnown(map[string]string{fingerprintOf(1): "00000000-0000-4000-8000-0000000000a1",
		"not-a-fingerprint": "00000000-0000-4000-8000-0000000000a2"})
	if report.Known != 1 || report.Items[0].KnownCertificateID == "" || report.Digest == before {
		t.Fatalf("known = %d, row 1 = %+v, digest moved = %v", report.Known, report.Items[0], report.Digest != before)
	}
	for _, m := range report.Items {
		if m.Outcome == OutcomeUnparseable && m.KnownCertificateID != "" {
			t.Fatalf("unparseable row %d marked known", m.Row)
		}
	}
	report.MarkKnown(nil)
	if report.Known != 0 || report.Digest != before {
		t.Fatalf("clearing known did not restore the digest: %d %s %s", report.Known, report.Digest, before)
	}
}

// A CSV row is numbered by the line it starts on, past a quoted line break,
// so the report points at the row in the file.
func TestCSVRowsAreNumberedByTheirLine(t *testing.T) {
	data := "fingerprint_sha256,common_name,folder\n" + fingerprintOf(1) + ",\"two\nlines\",a\n" + fingerprintOf(2) + ",b,a\n"
	rows, err := Parse([]byte(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Number != 2 || rows[1].Number != 4 {
		t.Fatalf("rows = %+v", rows)
	}
}
