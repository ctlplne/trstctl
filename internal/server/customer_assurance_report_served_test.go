// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A one-pixel PNG.
const a187Logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

// tenantBrandSource serves one tenant's white-label brand, as the Provider
// edition's resolver does, and the built-in brand to everyone else.
type tenantBrandSource struct {
	tenant string
	brand  branding.Brand
}

func (s tenantBrandSource) Resolve(_ context.Context, _, tenantID string) branding.Brand {
	if tenantID == s.tenant {
		return s.brand
	}
	return branding.Default()
}

func (tenantBrandSource) TenantForHost(context.Context, string) string { return "" }

// TestServedCustomerAssuranceReportA187 drives the customer assurance report
// end to end: a schedule signs and archives a report in the tenant's brand, the
// next run says what changed since the first, a verifier holding only the
// published signing key checks the saved run offline, and the Provider-facing
// reads list and return the exact signed runs.
func TestServedCustomerAssuranceReportA187(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := &reportWorkerSigner{key: key}
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
	})
	branding.SetSource(tenantBrandSource{tenant: h.tenant, brand: branding.Brand{
		ProductName: "AcmeTrust", LogoDataURI: a187Logo, EmailFooter: "AcmeTrust managed PKI",
		TokenOverrides: map[string]string{"accent": "#aa3300"},
	}})
	t.Cleanup(func() { branding.SetSource(nil) })
	ctx := t.Context()
	projector := projections.New(h.store)
	const (
		ownerID    = "18700000-0000-4000-8000-000000000001"
		scheduleID = "18700000-0000-4000-8000-000000000002"
	)
	ownerData, err := json.Marshal(projections.OwnerCreated{ID: ownerID, Kind: "service", Name: "payments-team"})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, events.Event{ID: "18700000-0000-4000-8000-000000000101", Type: projections.EventOwnerCreated,
		TenantID: h.tenant, Sequence: 1, Time: time.Now().UTC().Add(-4 * time.Hour), Data: ownerData}); err != nil {
		t.Fatal(err)
	}
	owner := ownerID
	record := func(name string, owned bool, notAfter time.Time) store.Certificate {
		t.Helper()
		in := store.Certificate{Subject: "CN=" + name, Serial: name, Issuer: "CN=Acme Issuing CA", KeyAlgorithm: "ECDSA-P256",
			Fingerprint: crypto.SHA256Hex([]byte("a187-" + name)), Source: "discovered", NotAfter: &notAfter}
		if owned {
			in.OwnerID = &owner
		}
		cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, in)
		if err != nil {
			t.Fatalf("record %s: %v", name, err)
		}
		return cert
	}
	now := time.Now().UTC()
	soon := record("soon.customer.example.test", true, now.Add(5*24*time.Hour))
	record("unowned.customer.example.test", false, now.Add(200*24*time.Hour))
	record("owned.customer.example.test", true, now.Add(200*24*time.Hour))

	// An hourly customer_assurance schedule whose first due edge was two hours
	// ago: the first period is [-3h, -2h), the second [-2h, -1h).
	due := now.Add(-2 * time.Hour).Truncate(time.Second)
	scheduleEvent, err := h.log.Append(ctx, events.Event{
		TenantID: h.tenant, Type: projections.EventComplianceReportScheduleUpserted, Time: due.Add(-time.Hour), SchemaVersion: 1,
		Data: []byte(`{"id":"` + scheduleID + `","framework":"soc2","name":"monthly customer assurance","report_type":"customer_assurance","interval_seconds":3600,"enabled":true,"delivery":"audit_export"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, scheduleEvent); err != nil {
		t.Fatal(err)
	}
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "customer-reporter", "audit:read")
	status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/report-signing-key", reader, "", nil)
	var signingKey api.ReportSigningKey
	if status != http.StatusOK || json.Unmarshal(body, &signingKey) != nil || signingKey.SHA256 != crypto.SHA256Hex(key.Public().DER) {
		t.Fatalf("report signing key = %d %s", status, body)
	}
	pinned, err := compliance.ParsePublicKey([]byte(signingKey.PublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	runReport := func(label string) (store.ComplianceReportRun, []byte, assurance.CustomerReport) {
		t.Helper()
		schedule, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
		if err != nil {
			t.Fatal(err)
		}
		if processed, err := h.srv.runComplianceReportDue(ctx, schedule, time.Now().UTC().Add(2*time.Hour)); err != nil || !processed {
			t.Fatalf("%s: due edge processed %v, %v", label, processed, err)
		}
		run, err := h.store.GetComplianceReportRunByDue(ctx, h.tenant, scheduleID, schedule.NextRunAt)
		if err != nil || run.Status != "completed" {
			t.Fatalf("%s: run = %+v, %v", label, run, err)
		}
		artifact, err := h.srv.reportArchive.Read(ctx, run.ArtifactRef, h.tenant, run.ID, run.ArtifactDigest)
		if err != nil {
			t.Fatal(err)
		}
		// Offline: only the pinned key, never the server's verifier.
		verified, err := compliance.VerifyScheduledReport(artifact, pinned)
		if err != nil || verified.ReportType != "customer_assurance" || verified.RunID != run.ID {
			t.Fatalf("%s: offline verification = %+v, %v", label, verified, err)
		}
		report, err := assurance.CheckCustomerReport(verified.Payload)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		return run, artifact, report
	}

	firstRun, _, first := runReport("first period")
	if first.Brand.ProductName != "AcmeTrust" || first.Brand.LogoDataURI != a187Logo || !first.Brand.Custom ||
		!strings.Contains(first.HTML, "AcmeTrust assurance report") || !strings.Contains(html.UnescapeString(first.HTML), `src="`+a187Logo+`"`) ||
		strings.Contains(strings.ToLower(first.HTML), "trstctl") {
		t.Fatalf("the first report is not in the tenant's brand: %+v", first.Brand)
	}
	if first.Inventory.ActiveCertificates != 3 || first.Inventory.OwnedCertificates != 2 || first.Credentials.Expiring != 1 ||
		len(first.Credentials.ExpiringSoonest) != 1 || first.Credentials.ExpiringSoonest[0].Owner != "payments-team" ||
		first.Changes.Comparable || first.Changes.Note == "" {
		t.Fatalf("first report = inventory %+v credentials %+v changes %+v", first.Inventory, first.Credentials, first.Changes)
	}
	if !first.PeriodThrough.Equal(due) || !first.PeriodFrom.Equal(due.Add(-time.Hour)) {
		t.Fatalf("first period = %s to %s, want the hour before %s", first.PeriodFrom, first.PeriodThrough, due)
	}

	// The next due edge is an interval after the first run completed, so the
	// second period starts at that completion; the soon-expiring certificate is
	// revoked just inside it.
	next, err := h.store.GetComplianceReportSchedule(ctx, h.tenant, scheduleID)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := next.NextRunAt.Add(-time.Hour).Add(time.Millisecond)
	if err := h.srv.orch.RevokeCertificate(ctx, h.tenant, soon.Fingerprint, soon.Serial, "superseded", revokedAt); err != nil {
		t.Fatal(err)
	}
	secondRun, secondArtifact, second := runReport("second period")
	metrics := map[string]assurance.MetricChange{}
	for _, m := range second.Changes.Metrics {
		metrics[m.Key] = m
	}
	if !second.PeriodFrom.Equal(next.NextRunAt.Add(-time.Hour)) || !second.Changes.Comparable ||
		second.Changes.PreviousGeneratedAt == nil || !second.Changes.PreviousGeneratedAt.Equal(first.GeneratedAt) ||
		metrics["active_certificates"].Delta != -1 || metrics["revoked"].Previous != 0 || metrics["revoked"].Current != 1 ||
		metrics["expiring"].Current != 0 || metrics["ownership_coverage_percent"].Previous != 66 || metrics["ownership_coverage_percent"].Current != 50 {
		t.Fatalf("period-over-period change = %+v", second.Changes)
	}
	if !strings.Contains(second.HTML, "Compared with the previous period") || !strings.Contains(strings.Join(second.Summary, " "), "Since the previous report:") {
		t.Fatalf("the second report does not show the change: %v", second.Summary)
	}

	// The Provider-facing reads: newest first, exact signed bytes.
	runs, err := h.srv.api.CustomerAssuranceRuns(ctx, h.tenant)
	if err != nil || len(runs) != 2 || runs[0].RunID != secondRun.ID || runs[1].RunID != firstRun.ID || runs[0].ArtifactSHA256 != secondRun.ArtifactDigest {
		t.Fatalf("runs = %+v, %v", runs, err)
	}
	if artifact, err := h.srv.api.CustomerAssuranceArtifact(ctx, h.tenant, secondRun.ID); err != nil || string(artifact) != string(secondArtifact) {
		t.Fatalf("artifact = %v", err)
	}
	if _, err := h.srv.api.CustomerAssuranceArtifact(ctx, store.ZeroUUID, secondRun.ID); !errors.Is(err, api.ErrReportRunNotFound) {
		t.Fatalf("another tenant read the run: %v", err)
	}

	// On demand: the last week, compared with the newest archived report.
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/reports/assurance?days=7", reader, "", nil)
	var onDemand assurance.CustomerReport
	if status != http.StatusOK || json.Unmarshal(body, &onDemand) != nil || !onDemand.Changes.Comparable ||
		onDemand.Changes.PreviousGeneratedAt == nil || !onDemand.Changes.PreviousGeneratedAt.Equal(second.GeneratedAt) ||
		onDemand.Credentials.Revoked != 1 {
		t.Fatalf("on-demand report = %d %s", status, body)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/reports/assurance?days=0", reader, "", nil); status != http.StatusBadRequest {
		t.Fatalf("days=0 = %d %s", status, body)
	}
}
