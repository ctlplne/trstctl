// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"encoding/json"
	"html"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// A one-pixel PNG.
const testLogo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

func customerTestFacts(base time.Time) store.CustomerAssuranceFacts {
	soon := base.Add(5 * 24 * time.Hour)
	return store.CustomerAssuranceFacts{
		ActiveCertificates: 8, OwnedCertificates: 6, ExpiredActive: 1, Expiring: 2,
		ExpiringSoonest: []store.AssuranceCertificate{{ID: "c1", Subject: "CN=api.customer.example", NotAfter: &soon, Owner: "payments"}},
		UnownedSoonest:  []store.AssuranceCertificate{{ID: "c2", Subject: "CN=<script>alert(1)</script>"}},
		AddedInPeriod:   3, RenewedInPeriod: 2, RevokedInPeriod: 1,
		FailedRenewals:     1,
		Failures:           []store.AssuranceFailure{{Kind: "renewal", ID: "r1", Subject: "edge-tls", Status: "failed", Reason: "ACME order rejected", At: base}},
		VerifiedDeliveries: 2, EndpointObservations: 4, EndpointsMatching: 3, EndpointsMismatched: 1, EndpointsCheckedInPeriod: 4,
		IncidentsInPeriod: 1, IncidentsOpenedInPeriod: 1,
		Incidents: []store.AssuranceIncident{{Kind: "credential_compromise", ID: "i1", Status: "executed", Phase: "completed",
			OpenedAt: base, UpdatedAt: base, EvidenceFormat: "jws", Evidence: "header.payload.signature"}},
	}
}

// A187: the report says what happened in plain sentences, in the tenant's
// white-label brand and never under the product's own name, and compares
// every figure with the previous period's report.
func TestCustomerReportSaysItPlainlyInTheTenantBrandAndComparesPeriods(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	brand := branding.Brand{ProductName: "AcmeTrust", LogoDataURI: testLogo, EmailFooter: "AcmeTrust managed PKI",
		TokenOverrides: map[string]string{"accent": "#AA3300"}}
	previous, err := BuildCustomerReport(CustomerInputs{TenantID: "t1", TenantName: "Customer One", Brand: brand,
		GeneratedAt: base.Add(-30 * 24 * time.Hour), From: base.Add(-60 * 24 * time.Hour), Through: base.Add(-30 * 24 * time.Hour),
		Facts: store.CustomerAssuranceFacts{ActiveCertificates: 6, OwnedCertificates: 3, Expiring: 4}})
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{
		{IndependentlyObserved: []string{StageDiscovery, StageVerification}},
		{RecordedOnly: []string{StageVerification}},
		{Absent: []string{StageVerification}},
	}
	r, err := BuildCustomerReport(CustomerInputs{TenantID: "t1", TenantName: "Customer One", Brand: brand,
		GeneratedAt: base, From: base.Add(-30 * 24 * time.Hour), Through: base,
		Facts: customerTestFacts(base), Records: records, Previous: &previous})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Customer One holds 8 active certificates; 6 of them (75%) have a named owner.",
		"2 certificates expire in the next 30 days; the soonest is CN=api.customer.example on 2026-10-06.",
		"1 certificate has already expired and is still active.",
		"In this period 2 certificates were renewed, 3 were added to the inventory and 1 was revoked.",
		"1 renewal and 0 deliveries failed; each is listed below.",
		"Of 4 endpoint checks, 3 served the expected certificate, 1 served a different one and 0 could not be reached.",
		"Of 3 credentials that changed in this period, 1 was seen served from outside AcmeTrust's own record.",
		"1 incident was opened in this period and 0 are open; each is listed with its evidence.",
		"Since the previous report: Active certificates rose from 6 to 8; Ownership coverage (%) rose from 50 to 75; Certificates expiring within 30 days fell from 4 to 2; Expired certificates still active rose from 0 to 1.",
	} {
		if !slices.Contains(r.Summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, strings.Join(r.Summary, "\n"))
		}
	}
	if r.Verification.IndependentlyVerified != 1 || r.Verification.RecordedOnly != 1 || r.Verification.NotVerified != 1 {
		t.Fatalf("verification = %+v", r.Verification)
	}
	if !r.Changes.Comparable || r.Changes.PreviousPeriodThrough == nil || !r.Changes.PreviousPeriodThrough.Equal(previous.PeriodThrough) {
		t.Fatalf("changes = %+v", r.Changes)
	}
	metrics := map[string]MetricChange{}
	for _, m := range r.Changes.Metrics {
		metrics[m.Key] = m
	}
	if m := metrics["ownership_coverage_percent"]; m.Previous != 50 || m.Current != 75 || m.Delta != 25 {
		t.Fatalf("ownership change = %+v", m)
	}
	if m := metrics["expiring"]; m.Delta != -2 || m.Sentence != "Certificates expiring within 30 days fell from 4 to 2." {
		t.Fatalf("expiry change = %+v", m)
	}
	if r.Brand.ProductName != "AcmeTrust" || r.Brand.LogoDataURI != testLogo || r.Brand.Accent != "#aa3300" || !r.Brand.Custom {
		t.Fatalf("brand = %+v", r.Brand)
	}
	// html/template writes the logo's "+" as an entity; a browser reads it back.
	if !strings.Contains(html.UnescapeString(r.HTML), `src="`+testLogo+`"`) {
		t.Error("HTML lacks the embedded logo")
	}
	for _, want := range []string{"AcmeTrust assurance report", "--accent: #aa3300", "AcmeTrust managed PKI",
		"CN=&lt;script&gt;alert(1)&lt;/script&gt;", "ACME order rejected", "jws <code>sha256:"} {
		if !strings.Contains(r.HTML, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if strings.Contains(r.HTML, "<script>") || strings.Contains(strings.ToLower(r.HTML), "trstctl") {
		t.Fatal("the white-label rendering carries script or the product's own name")
	}
	if r.Incidents.Items[0].Evidence != "header.payload.signature" ||
		r.Incidents.Items[0].EvidenceSHA256 != crypto.SHA256Hex([]byte("header.payload.signature")) {
		t.Fatalf("incident evidence = %+v", r.Incidents.Items[0])
	}
	payload, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if checked, err := CheckCustomerReport(payload); err != nil || checked.HTMLSHA256 != r.HTMLSHA256 {
		t.Fatalf("check = %v", err)
	}
	r.HTML = strings.Replace(r.HTML, "AcmeTrust managed PKI", "Someone else's PKI", 1)
	tampered, _ := json.Marshal(r)
	if _, err := CheckCustomerReport(tampered); err == nil {
		t.Fatal("a rendering that differs from its digest was accepted")
	}
}

// A brand that cannot be embedded safely is left out and says so; large
// incident evidence is named by digest; a first report says there is nothing
// to compare.
func TestCustomerReportRefusesUnsafeBrandingAndBoundsEvidence(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	big := strings.Repeat("e", MaxEvidenceBytes+1)
	r, err := BuildCustomerReport(CustomerInputs{TenantID: "t1", TenantName: "Customer One",
		Brand: branding.Brand{ProductName: "AcmeTrust", LogoDataURI: "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
			TokenOverrides: map[string]string{"accent": "red;}body{display:none"}},
		GeneratedAt: base, From: base.Add(-24 * time.Hour), Through: base,
		Facts: store.CustomerAssuranceFacts{IncidentsInPeriod: 1, IncidentsOpen: 1, Incidents: []store.AssuranceIncident{
			{Kind: "issuer_compromise", ID: "i2", Status: "running", Phase: "revoking", OpenedAt: base, UpdatedAt: base, EvidenceFormat: "jws", Evidence: big}}},
		RecordsNote: "no records"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Brand.LogoDataURI != "" || strings.Contains(r.HTML, "<img") || r.Brand.Accent != defaultAccent {
		t.Fatalf("unsafe brand was embedded: %+v", r.Brand)
	}
	item := r.Incidents.Items[0]
	if item.Evidence != "" || item.EvidenceSHA256 != crypto.SHA256Hex([]byte(big)) {
		t.Fatalf("large evidence = %d bytes, digest %q", len(item.Evidence), item.EvidenceSHA256)
	}
	limits := strings.Join(r.Limits, "\n")
	if !strings.Contains(limits, "logo is not a PNG, JPEG, GIF or WebP data URI") || !strings.Contains(limits, "Incident i2's evidence is larger than 64 KiB") {
		t.Fatalf("limits = %s", limits)
	}
	if r.Inventory.OwnershipCoveragePercent != nil || !slices.Contains(r.Summary, "There are no active certificates in the inventory.") ||
		r.Changes.Comparable || !slices.Contains(r.Summary, "There is no earlier report to compare with.") ||
		r.Verification.Note != "no records" {
		t.Fatalf("first report = %+v", r.Summary)
	}
	def, err := BuildCustomerReport(CustomerInputs{TenantID: "t1", GeneratedAt: base, From: base.Add(-time.Hour), Through: base})
	if err != nil || def.Brand.Custom || def.Brand.ProductName != branding.Default().ProductName || def.TenantName != "t1" {
		t.Fatalf("default brand = %+v, %v", def.Brand, err)
	}
}
