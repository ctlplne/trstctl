// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/whitelabel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
	corestore "trstctl.com/trstctl/internal/store"
)

// A one-pixel PNG.
const reportTestLogo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

// reportTestSigner stands in for the licensed governance signer.
type reportTestSigner struct{ key *crypto.LockedSigner }

func (reportTestSigner) ExportEvidencePack(context.Context, string, api.ComplianceFramework) (api.ComplianceEvidencePack, error) {
	return api.ComplianceEvidencePack{}, errors.New("unexpected evidence-pack export")
}

func (s reportTestSigner) SignScheduledManifest(_ context.Context, manifest json.RawMessage) (json.RawMessage, error) {
	signature, err := crypto.SignMessage(s.key, manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Manifest     json.RawMessage `json:"manifest"`
		Signature    []byte          `json:"signature"`
		PublicKeyDER []byte          `json:"public_key_der"`
	}{manifest, signature, s.key.Public().DER})
}

func (s reportTestSigner) ScheduledVerificationKeyDER() []byte { return s.key.Public().DER }

// reportBrandStore is the Provider's view of the durable white-label store,
// as the attach seam adapts it.
type reportBrandStore struct {
	pg       *whitelabel.PGStore
	resolver *whitelabel.Resolver
}

func (b reportBrandStore) TenantBrand(ctx context.Context, tenantID string) (*TenantBrand, error) {
	record, err := b.pg.TenantBrand(ctx, tenantID)
	if err != nil || record == nil {
		return nil, err
	}
	return &TenantBrand{TenantID: tenantID, ProductName: record.ProductName, LogoDataURI: record.LogoDataURI,
		EmailFooter: record.EmailFooter, TokenOverrides: record.TokenOverrides, Revision: record.Revision}, nil
}

func (b reportBrandStore) Invalidate() { b.resolver.Invalidate() }

// TestProviderSharesASignedBrandedAssuranceReport is A187's done condition: a
// Provider schedules a customer's assurance report through a tenant template
// (announced on the customer's own channel), brands the customer, and each run
// renders in that brand; the next run shows the change since the first; and
// the Provider downloads the exact signed run and verifies it offline with the
// key the plane lists. An undelegated customer's reports stay closed.
func TestProviderSharesASignedBrandedAssuranceReport(t *testing.T) {
	ctx := t.Context()
	st, log, sink := isolatedTemplateFixture(t)
	customer := CustomerID("assurance-customer")
	other := CustomerID("assurance-other")
	delegations := StaticDelegations{
		{OperatorID: "op-1", CustomerID: customer, Operations: []Operation{OpRead, OpProvision}},
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	archive := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	brands := whitelabel.NewPGStore(st)
	resolver := whitelabel.NewResolver(brands, time.Minute)
	branding.SetSource(resolver)
	t.Cleanup(func() { branding.SetSource(nil) })
	var orch *orchestrator.Orchestrator
	srv, err := server.Build(ctx, server.Deps{Store: st, Log: log, EnablePolicyGate: true, AuditArchiveDir: archive,
		APIOptions: []api.Option{api.WithComplianceEvidence(reportTestSigner{key: key})},
		ProviderHandlerFactory: func(o *orchestrator.Orchestrator, services api.ProviderTenantServices) (http.Handler, error) {
			orch = o
			return NewHandler(Config{
				License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: sink, Activity: NewEventLogActivitySource(log),
				Authenticator: stubAuth{accept: templateOperatorCredential}, Delegations: delegations,
				Brands:    reportBrandStore{pg: brands, resolver: resolver},
				Templates: TemplateDeps{Store: NewPGStore(st), Baselines: services, RegisterTenant: o.RegisterTenant},
				Reports:   services,
			}), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	h := srv.Handler()

	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/tenants", "provision-assurance",
		ProvisionRequest{Slug: "assurance-customer", Name: "Assurance Customer"}); rec.Code != http.StatusCreated {
		t.Fatalf("provision = %d %s", rec.Code, rec.Body.String())
	}
	// The template announces each monthly report on the customer's webhook.
	baseline := api.TenantBaseline{
		NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", Label: "Customer reports", EndpointURL: "https://hooks.example.com/reports"}},
		ReportSchedules: []api.BaselineReportSchedule{{Key: "assurance", Name: "Monthly assurance", Framework: "soc2",
			ReportType: "customer_assurance", IntervalSeconds: 30 * 24 * 3600,
			Dispatch: &corestore.ComplianceReportDispatch{Channels: []string{"webhook"}}}},
	}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-assurance",
		TemplateRequest{ID: "assured", Name: "Assured customer", Baseline: baseline}); rec.Code != http.StatusOK {
		t.Fatalf("record template = %d %s", rec.Code, rec.Body.String())
	}
	rec := templateRequest(t, h, http.MethodPost, "/provider/v1/tenants/"+customer+"/template", "onboard-assurance",
		TemplateApplyRequest{TemplateID: "assured"})
	var onboarded TemplateApplication
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &onboarded) != nil || !onboarded.Complete {
		t.Fatalf("onboard = %d %s", rec.Code, rec.Body.String())
	}
	schedules, err := st.ListComplianceReportSchedulesPage(ctx, customer, corestore.ZeroUUID, 10)
	if err != nil || len(schedules) != 1 || schedules[0].ReportType != "customer_assurance" ||
		schedules[0].Dispatch == nil || len(schedules[0].Dispatch.Channels) != 1 {
		t.Fatalf("templated schedules = %+v, %v", schedules, err)
	}
	scheduleID := schedules[0].ID

	// The Provider brands the customer.
	brandReq := httptest.NewRequest(http.MethodPut, "/provider/v1/tenants/"+customer+"/brand", bytes.NewReader([]byte(
		`{"product_name":"AcmeTrust","logo_data_uri":"`+reportTestLogo+`","email_footer":"AcmeTrust managed PKI","token_overrides":{"accent":"#aa3300"}}`)))
	brandReq.Header.Set("Authorization", templateOperatorCredential)
	brandReq.Header.Set("Idempotency-Key", "brand-assurance")
	brandReq.Header.Set("If-Match", `"0"`)
	brandRec := httptest.NewRecorder()
	h.ServeHTTP(brandRec, brandReq)
	if brandRec.Code != http.StatusNoContent {
		t.Fatalf("brand = %d %s", brandRec.Code, brandRec.Body.String())
	}

	record := func(name string) {
		t.Helper()
		notAfter := time.Now().UTC().Add(200 * 24 * time.Hour)
		if _, err := orch.RecordCertificate(ctx, customer, corestore.Certificate{Subject: "CN=" + name, Serial: name,
			Issuer: "CN=Customer CA", Fingerprint: crypto.SHA256Hex([]byte("a187-provider-" + name)), Source: "discovered",
			NotAfter: &notAfter}); err != nil {
			t.Fatal(err)
		}
	}
	record("www.customer.example.test")
	// The test cannot wait a month: each run moves the due edge into the past.
	runDue := func(due time.Time) {
		t.Helper()
		if err := st.WithTenant(ctx, customer, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE compliance_report_schedules SET next_run_at = $3 WHERE tenant_id = $1 AND id = $2`, customer, scheduleID, due)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if n, err := srv.RunComplianceReportsOnce(ctx); err != nil || n != 1 {
			t.Fatalf("report sweep = %d, %v", n, err)
		}
	}
	listReports := func(operator string, customerID string) (*httptest.ResponseRecorder, AssuranceReports) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/"+customerID+"/assurance-reports", nil)
		req.Header.Set("Authorization", operator)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out AssuranceReports
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	download := func(runID string) []byte {
		t.Helper()
		rec := templateRequest(t, h, http.MethodGet, "/provider/v1/tenants/"+customer+"/assurance-reports/"+runID, "", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "assurance-report-"+runID) {
			t.Fatalf("download = %d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.Bytes()
	}

	now := time.Now().UTC().Truncate(time.Second)
	runDue(now.Add(-2 * time.Hour))
	rec, listed := listReports(templateOperatorCredential, customer)
	if rec.Code != http.StatusOK || len(listed.Runs) != 1 || listed.SigningKey.SHA256 != crypto.SHA256Hex(key.Public().DER) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	// Offline: only the key the plane listed, which the Provider hands the
	// customer over a channel of its own.
	pinned, err := compliance.ParsePublicKey([]byte(listed.SigningKey.PublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	verify := func(artifact []byte) assurance.CustomerReport {
		t.Helper()
		verified, err := compliance.VerifyScheduledReport(artifact, pinned)
		if err != nil || verified.TenantID != customer || verified.ScheduleID != scheduleID {
			t.Fatalf("offline verification = %+v, %v", verified, err)
		}
		report, err := assurance.CheckCustomerReport(verified.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	first := verify(download(listed.Runs[0].RunID))
	if first.Brand.ProductName != "AcmeTrust" || first.Brand.Accent != "#aa3300" || !strings.Contains(first.HTML, "AcmeTrust assurance report") ||
		!strings.Contains(html.UnescapeString(first.HTML), `src="`+reportTestLogo+`"`) || !strings.Contains(first.HTML, "AcmeTrust managed PKI") ||
		strings.Contains(strings.ToLower(first.HTML), "trstctl") || first.TenantName != "Assurance Customer" {
		t.Fatalf("the report is not in the customer's brand: %+v", first.Brand)
	}
	if first.Inventory.ActiveCertificates != 1 || first.Changes.Comparable {
		t.Fatalf("first report = %+v %+v", first.Inventory, first.Changes)
	}
	// The run was announced on the customer's own channel (A103), never with
	// the report body.
	var notices int
	if err := st.WithTenant(ctx, customer, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`, customer, notify.DestinationComplianceReport).Scan(&notices)
	}); err != nil || notices != 1 {
		t.Fatalf("report notices = %d, %v", notices, err)
	}

	record("api.customer.example.test")
	runDue(now.Add(-time.Hour))
	_, listed = listReports(templateOperatorCredential, customer)
	if len(listed.Runs) != 2 {
		t.Fatalf("runs = %+v", listed.Runs)
	}
	second := verify(download(listed.Runs[0].RunID))
	changed := map[string]assurance.MetricChange{}
	for _, m := range second.Changes.Metrics {
		changed[m.Key] = m
	}
	if !second.Changes.Comparable || changed["active_certificates"].Previous != 1 || changed["active_certificates"].Current != 2 ||
		!strings.Contains(strings.Join(second.Summary, " "), "Since the previous report: Active certificates rose from 1 to 2") {
		t.Fatalf("period-over-period change = %+v", second.Changes)
	}

	// A customer this operator holds no grant on stays closed.
	if rec, _ := listReports(templateOperatorCredential, other); rec.Code != http.StatusForbidden {
		t.Fatalf("undelegated list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := templateRequest(t, h, http.MethodGet, "/provider/v1/tenants/"+other+"/assurance-reports/"+listed.Runs[0].RunID, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("undelegated download = %d %s", rec.Code, rec.Body.String())
	}
	if rec := templateRequest(t, h, http.MethodGet, "/provider/v1/tenants/"+customer+"/assurance-reports/00000000-0000-4000-8000-000000000000", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d %s", rec.Code, rec.Body.String())
	}
}
