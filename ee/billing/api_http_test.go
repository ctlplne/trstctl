// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
)

var billingRole = authz.Role{Name: "billing-operator", Permissions: []authz.Permission{authz.AuditRead}}

const (
	billTenantA = "tenant-a"
	billTenantB = "tenant-b"
)

// stubReader stands in for the durable meter store and RECORDS which tenant it
// was asked about, so a test can prove the handler never reached for another.
type stubReader struct {
	records  []billing.UsageRecord
	coverage billing.Coverage
	askedFor []string
}

func (s *stubReader) Query(_ context.Context, from, to time.Time, tenantID string) ([]billing.UsageRecord, error) {
	s.askedFor = append(s.askedFor, tenantID)
	var out []billing.UsageRecord
	for _, r := range s.records {
		if r.TenantID == tenantID && !r.PeriodStart.Before(from) && r.PeriodStart.Before(to) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *stubReader) CoverageFor(_ context.Context, tenantID string) (billing.Coverage, error) {
	s.askedFor = append(s.askedFor, tenantID)
	return s.coverage, nil
}

// serveEvidenceRequest drives the real licensed route through a real *api.API,
// so the test exercises what an operator's HTTP call reaches — not the document
// builder underneath it.
func serveEvidenceRequest(t *testing.T, reader billing.EvidenceReader, callerTenant, query string) *httptest.ResponseRecorder {
	t.Helper()
	routes := billing.Routes(reader)
	if len(routes) != 1 {
		t.Fatalf("expected exactly one evidence route, got %d", len(routes))
	}
	// Through the real router with the real authz middleware, not by calling
	// the handler closure directly: a route is only as scoped as what a request
	// actually traverses to reach it.
	principal := authz.Principal{TenantID: callerTenant, Subject: "operator",
		Grants: []authz.Grant{{Role: billingRole, Scope: authz.Scope{TenantID: callerTenant}}}}
	a := api.New(nil, nil, nil,
		api.WithLicensedRoutes(routes...),
		api.WithRoles(billingRole),
		api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
	)
	req := httptest.NewRequest(http.MethodGet, routes[0].Path+"?"+query, nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

func periodQuery(customer string) string {
	q := "period_start=2026-07-01T00:00:00Z&period_end=2026-08-01T00:00:00Z"
	if customer != "" {
		q += "&customer_id=" + customer
	}
	return q
}

// The cross-tenant refusal. This is the one that matters.
//
// The document is a complete record of one tenant's activity. If customer_id
// could name somebody else, a tenant admin holding a read permission IN THEIR
// OWN TENANCY would read another customer's usage — AN-1 defeated by a query
// parameter, on a route whose whole purpose is to be pulled by whoever does the
// billing.
func TestEvidenceRouteRefusesACustomerIDNamingAnotherTenant(t *testing.T) {
	t.Parallel()
	reader := &stubReader{coverage: billing.Coverage{Durable: true}, records: []billing.UsageRecord{
		{TenantID: billTenantB, Meter: "certs.issued", Kind: billing.KindCounter, Value: 9999,
			PeriodStart: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
	}}
	rec := serveEvidenceRequest(t, reader, billTenantA, periodQuery(billTenantB))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("naming another tenant in customer_id returned %d, want 403.\n\n"+
			"Tenant %s asked for tenant %s's invoice evidence and the route answered. That is a "+
			"cross-tenant read of a complete activity record, reachable by anyone who can spell "+
			"another customer's tenant id.\nbody: %s", rec.Code, billTenantA, billTenantB, rec.Body.String())
	}
	for _, asked := range reader.askedFor {
		if asked == billTenantB {
			t.Fatalf("the handler queried tenant %s on behalf of tenant %s; the refusal must happen "+
				"BEFORE the store is touched, or a timing difference still discloses whether "+
				"another customer has usage", billTenantB, billTenantA)
		}
	}
}

// The caller's own tenancy answers normally, and the store is only ever asked
// about that tenant.
func TestEvidenceRouteServesTheCallersOwnTenancy(t *testing.T) {
	t.Parallel()
	reader := &stubReader{
		coverage: billing.Coverage{Durable: true,
			ObservedFrom: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			ObservedTo:   time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)},
		records: []billing.UsageRecord{
			{TenantID: billTenantA, Meter: "certs.issued", Kind: billing.KindCounter, Value: 7,
				PeriodStart: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
			{TenantID: billTenantB, Meter: "certs.issued", Kind: billing.KindCounter, Value: 9999,
				PeriodStart: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
		},
	}
	rec := serveEvidenceRequest(t, reader, billTenantA, periodQuery(""))
	if rec.Code != http.StatusOK {
		t.Fatalf("own-tenancy evidence returned %d: %s", rec.Code, rec.Body.String())
	}
	var doc billing.EvidenceDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if doc.CustomerID != billTenantA {
		t.Fatalf("document is for customer %q, want the caller's tenant %q", doc.CustomerID, billTenantA)
	}
	for _, l := range doc.Lines {
		if l.Value == 9999 {
			t.Fatal("the other tenant's usage appeared in this tenant's evidence document")
		}
	}
	for _, asked := range reader.askedFor {
		if asked != billTenantA {
			t.Fatalf("the store was asked about %q while serving %q", asked, billTenantA)
		}
	}
}

// An incomplete period still returns the document, carrying its own refusal.
//
// Returning an error would tell a finance team "the system is broken" when the
// truth is "your usage is incomplete, here is exactly how" — and only the
// second is actionable. But the numbers must never arrive without the warning
// attached, so signable=false and a reason are asserted on the wire.
func TestUnsignableEvidenceIsServedWithItsRefusalNotHiddenBehindAnError(t *testing.T) {
	t.Parallel()
	reader := &stubReader{coverage: billing.Coverage{Durable: false}, records: []billing.UsageRecord{
		{TenantID: billTenantA, Meter: "certs.issued", Kind: billing.KindCounter, Value: 3,
			PeriodStart: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)},
	}}
	rec := serveEvidenceRequest(t, reader, billTenantA, periodQuery(""))
	if rec.Code != http.StatusOK {
		t.Fatalf("an unsignable period returned %d; the document is the answer, not an error", rec.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	signable, present := raw["signable"]
	if !present {
		t.Fatal("the served document omits `signable`; a reader would take the numbers as billable")
	}
	if signable != false {
		t.Fatalf("in-memory metering produced signable=%v. Usage counted by a process that loses "+
			"its state on restart must never be presentable as an invoice", signable)
	}
	if reason, _ := raw["reason"].(string); strings.TrimSpace(reason) == "" {
		t.Fatal("signable=false with no reason: a finance team is told the number is unusable and " +
			"not told what to fix")
	}
}

// No metering attached is not zero usage. Answering 200 with an empty document
// would invoice a customer for nothing because the recorder was never installed.
func TestNoMeteringRefusesRatherThanReportingZeroUsage(t *testing.T) {
	t.Parallel()
	rec := serveEvidenceRequest(t, nil, billTenantA, periodQuery(""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("with no metering store the route returned %d, want 503.\n"+
			"A zero-usage document and an absent recorder are different facts, and conflating them "+
			"bills a busy customer nothing.\nbody: %s", rec.Code, rec.Body.String())
	}
}

// An in-memory installation SERVES the route and reports the period unsignable.
//
// The tempting alternative — mount the route only when the store is durable —
// answers 404 on a deployment that is genuinely metering, which reads as "this
// product has no such feature" rather than "your metering cannot be billed
// from". The operator needs the second, and only a served document says it.
func TestInMemoryMeteringServesAnUnsignableDocumentRatherThan404(t *testing.T) {
	t.Parallel()
	mem := billing.NewMemStore()
	var reader billing.EvidenceReader = mem // compile-time: MemStore is a reader
	rec := serveEvidenceRequest(t, reader, billTenantA, periodQuery(""))
	if rec.Code != http.StatusOK {
		t.Fatalf("in-memory metering returned %d, want 200 with an unsignable document.\n"+
			"404 would tell an operator the feature does not exist, when the truth is that it "+
			"exists and cannot be billed from.\nbody: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw["signable"] != false {
		t.Fatalf("in-memory metering reported signable=%v; usage that does not survive a restart "+
			"must never be presentable as an invoice", raw["signable"])
	}
}
