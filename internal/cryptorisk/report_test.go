// SPDX-License-Identifier: BUSL-1.1

package cryptorisk

import (
	"bytes"
	"encoding/csv"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/graph"
)

func readinessFixture() cryptoreadiness.Dataset {
	return cryptoreadiness.Dataset{Items: []cryptoreadiness.Item{
		{
			CryptoReadinessRow: graph.CryptoReadinessRow{
				Asset: graph.Node{ID: "crypto:a-rsa2048"},
				Dependents: []graph.CryptoDependent{
					{Node: graph.Node{ID: "wl:payments", Kind: graph.KindWorkload, Name: "payments"}},
					{Node: graph.Node{ID: "wl:billing", Kind: graph.KindWorkload, Name: "billing"}},
				},
				Owners: []string{"payments-team"}, QuantumVulnerable: true,
			},
			Actions: []cryptoreadiness.Action{{CampaignID: "c-1", Name: "RSA wave 1", Status: "in_progress", Wave: "1",
				Deadline: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)}},
		},
		{CryptoReadinessRow: graph.CryptoReadinessRow{Asset: graph.Node{ID: "crypto:a-p256"}, QuantumVulnerable: true}, Actions: []cryptoreadiness.Action{}},
	}}
}

func inputsFixture(now time.Time) Inputs {
	return Inputs{
		TenantID: "t1", Now: now, Readiness: readinessFixture(),
		Assets: []Asset{
			{ID: "a-rsa2048", Kind: "tls", Location: "pay:443", Algorithm: "RSA", KeyBits: 2048, Strength: "acceptable", QuantumVulnerable: true},
			{ID: "a-p256", Kind: "tls", Location: "api:443", Algorithm: "ECDSA", KeyBits: 256, Strength: "acceptable", QuantumVulnerable: true},
			{ID: "a-mlkem", Kind: "tls", Location: "pq:443", Algorithm: "ML-KEM-768", Strength: "strong"},
			{ID: "a-leaf", Kind: "tls", Location: "legacy:443", Algorithm: "RSA", KeyBits: 1024, Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true, CertificateFingerprint: "AB12"},
		},
		Certificates: []Certificate{
			{ID: "c-distrusted", Subject: "CN=old.example", Algorithm: "ECDSA", KeyBits: 384, Fingerprint: "cd34",
				Distrust:   &Distrust{Entry: "emSign ECC Root CA - G3", How: "issuer_key_id"},
				Dependents: Dependents{Count: 1, ByKind: map[string]int{"resource": 1}, Names: []string{"old:443"}}},
			{ID: "c-weak", Subject: "CN=legacy.example", Algorithm: "RSA", KeyBits: 1024, Fingerprint: "ab12",
				WeakReasons: []string{"RSA-1024 is below the 2048-bit minimum"}},
			{ID: "c-pq", Subject: "CN=pq.example", Algorithm: "ML-DSA-65"},
		},
	}
}

// Every weak, distrusted or quantum-vulnerable key is listed with its
// dependents, its deadline and its plan, in the order to act on; a post-quantum
// key is not listed; a certificate's own key asset joins its certificate.
func TestReportListsEachRiskyKeyWithDependentsDeadlineAndPlan(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	r := Build(inputsFixture(now))
	keys := []string{}
	for _, it := range r.Items {
		keys = append(keys, it.Key)
	}
	want := []string{"certificate:c-distrusted", "certificate:c-weak", "crypto:a-rsa2048", "crypto:a-p256"}
	if !slices.Equal(keys, want) {
		t.Fatalf("items = %v, want %v", keys, want)
	}
	byKey := map[string]Item{}
	for _, it := range r.Items {
		byKey[it.Key] = it
		if it.Priority == 0 || it.Deadline.Rule == "" || it.EvidenceIDs == nil || it.Plan.Actions == nil {
			t.Fatalf("incomplete item %+v", it)
		}
	}
	rsa := byKey["crypto:a-rsa2048"]
	if rsa.Dependents.Count != 2 || rsa.Dependents.ByKind["workload"] != 2 || rsa.Deadline.DeprecatedAfter != 2030 ||
		len(rsa.Plan.Actions) != 1 || rsa.Plan.Actions[0].CampaignID != "c-1" || rsa.Plan.Recommended != "" || rsa.Owners[0] != "payments-team" {
		t.Fatalf("RSA-2048 asset = %+v", rsa)
	}
	if p256 := byKey["crypto:a-p256"]; p256.Plan.Recommended == "" || p256.Deadline.DisallowedAfter != 2035 || p256.Deadline.DeprecatedAfter != 0 {
		t.Fatalf("P-256 asset = %+v", p256)
	}
	weak := byKey["certificate:c-weak"]
	if !slices.Contains(weak.EvidenceIDs, "crypto_asset:a-leaf") || !slices.Contains(weak.Exposures, ExposureOutOfPolicy) || weak.Deadline.Status != DeadlineReplaceNow ||
		weak.Plan.Recommended != certificatePlan {
		t.Fatalf("the weak certificate must carry its own key asset: %+v", weak)
	}
	if d := byKey["certificate:c-distrusted"]; d.Deadline.Status != DeadlineReplaceNow || d.Distrust == nil || d.Priority != 1 ||
		d.PriorityReason != "distrusted: browsers and clients refuse it" || d.Deadline.Rule != "distrusted: replace now" {
		t.Fatalf("distrusted = %+v", d)
	}
	if r.Summary.Items != 4 || r.Summary.Distrusted != 1 || r.Summary.Weak != 1 || r.Summary.WithPlan != 1 || r.Summary.WithoutPlan != 3 {
		t.Fatalf("summary = %+v", r.Summary)
	}
	if r.Changes.Comparable || r.Changes.Note == "" || r.CNSA20 == "" || r.Sources[0] != IR8547Source {
		t.Fatalf("a first report has nothing to compare: %+v", r.Changes)
	}
}

// The next period's report says what was added, resolved and changed.
func TestReportShowsPeriodOverPeriodChange(t *testing.T) {
	first := Build(inputsFixture(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)))
	in := inputsFixture(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	in.Certificates = in.Certificates[1:] // the distrusted certificate was replaced
	in.Readiness.Items[1].Actions = []cryptoreadiness.Action{{CampaignID: "c-2", Name: "P-256 wave", Status: "planned"}}
	in.Assets = append(in.Assets, Asset{ID: "a-dh", Kind: "tls", Location: "vpn:500", Algorithm: "DH", KeyBits: 2048, Strength: "acceptable", QuantumVulnerable: true})
	in.Previous = &first
	r := Build(in)
	c := r.Changes
	if !c.Comparable || c.PreviousGeneratedAt == nil || !c.PreviousGeneratedAt.Equal(first.GeneratedAt) {
		t.Fatalf("changes = %+v", c)
	}
	if !slices.Equal(c.Added, []string{"crypto:a-dh"}) || !slices.Equal(c.Resolved, []string{"certificate:c-distrusted"}) {
		t.Fatalf("added %v resolved %v", c.Added, c.Resolved)
	}
	if len(c.PlanChanged) != 1 || c.PlanChanged[0].Key != "crypto:a-p256" || c.PlanChanged[0].From != "no plan" || c.PlanChanged[0].To != "c-2=planned" {
		t.Fatalf("plan changes = %+v", c.PlanChanged)
	}
}

// A limited report still compares every qualifying key and says it was cut.
func TestReportLimitTruncatesButComparesEveryKey(t *testing.T) {
	in := inputsFixture(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC))
	in.Limit = 2
	r := Build(in)
	if !r.Truncated || len(r.Items) != 2 || r.Summary.Items != 4 {
		t.Fatalf("limited report = %d items, truncated %v, summary %+v", len(r.Items), r.Truncated, r.Summary)
	}
}

// The CSV lists one row per key in report order, and a subject a spreadsheet
// would read as a formula is neutralized.
func TestReportCSVIsOneRowPerKeyAndFormulaSafe(t *testing.T) {
	in := inputsFixture(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC))
	in.Certificates[0].Subject = "=HYPERLINK(\"https://example.test\")"
	var buf bytes.Buffer
	if err := WriteCSV(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 5 || !slices.Equal(rows[0], csvHeader) {
		t.Fatalf("csv rows = %v (%v)", rows, err)
	}
	if rows[1][2] != "certificate:c-distrusted" || rows[1][4] != "'=HYPERLINK(\"https://example.test\")" || rows[1][0] != "1" {
		t.Fatalf("first row = %v", rows[1])
	}
	if rows[3][16] != "c-1 in_progress by 2027-03-01" {
		t.Fatalf("plan cell = %q", rows[3][16])
	}
}
