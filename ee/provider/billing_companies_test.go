// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

type billingOperatorAuth struct{}

func (billingOperatorAuth) AuthenticateOperator(r *http.Request) (Operator, bool) {
	switch r.Header.Get("Authorization") {
	case "Bearer billing-admin":
		return providerOperator("op-billing"), true
	case "Bearer break-glass-operator":
		// The built-in operator role holds the break-glass trio only.
		return Operator{ID: "op-billing", Email: "bg@provider.example.test", Role: OperatorOperator, MFA: true}, true
	}
	return Operator{}, false
}

// MSP-2 Done-when (part 1): a Provider operator maps each delegated customer
// to its company in a configured billing target through the served plane,
// recorded as an authority event and projected; one company in one target
// belongs to one customer (another customer's mapping of it is refused 409
// before any event is appended); an unknown target is 404; an operator
// without billing:write is refused; a retried mutation replays; clearing a
// mapping frees the company; and a rebuild from the event history alone
// reproduces every mapping exactly.
func TestProviderBillingCompanyMappingsMSP2(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	var ticks atomic.Int64
	clock := func() time.Time {
		return time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC).Add(time.Duration(ticks.Add(1)) * time.Second)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	customerA, customerB := CustomerID("billing-a-"+suffix), CustomerID("billing-b-"+suffix)
	h := NewHandler(Config{
		License:          providerLicense(t, 10),
		Store:            NewPGStore(st),
		Mutations:        runtime.Mutations,
		Idempotency:      orchestrator.NewIdempotency(st),
		Authenticator:    billingOperatorAuth{},
		Delegations:      fullyDelegated("op-billing", customerA, customerB),
		BillingTargets:   []BillingTarget{{ID: "psa", Name: "PSA", Type: "json", Cadence: "monthly"}},
		BillingCompanies: NewPGBillingCompanyStore(st),
		Clock:            clock,
	})
	request := func(method, path, auth, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", auth)
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	companies := func(customer string) TenantBillingCompanies {
		t.Helper()
		rec := request(http.MethodGet, "/provider/v1/tenants/"+customer+"/billing-companies", "Bearer billing-admin", "", "")
		var out TenantBillingCompanies
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("list %s = %d %s", customer, rec.Code, rec.Body.String())
		}
		return out
	}
	set := func(customer, auth, key, company string) *httptest.ResponseRecorder {
		return request(http.MethodPut, "/provider/v1/tenants/"+customer+"/billing-companies/psa", auth, key, `{"external_company_id":"`+company+`"}`)
	}

	if rec := set(customerA, "Bearer billing-admin", "", "COMPANY-A"); rec.Code != http.StatusBadRequest {
		t.Fatalf("a mapping without an Idempotency-Key = %d", rec.Code)
	}
	if rec := set(customerA, "Bearer billing-admin", "map-a-"+suffix, "COMPANY-A"); rec.Code != http.StatusNoContent {
		t.Fatalf("map A = %d %s", rec.Code, rec.Body.String())
	}
	if rec := set(customerA, "Bearer billing-admin", "map-a-"+suffix, "COMPANY-A"); rec.Code != http.StatusNoContent {
		t.Fatalf("replay of map A = %d %s", rec.Code, rec.Body.String())
	}
	got := companies(customerA)
	if len(got.Targets) != 1 || got.Targets[0].ID != "psa" || got.Targets[0].Cadence != "monthly" || len(got.Companies) != 1 ||
		got.Companies[0].ExternalCompanyID != "COMPANY-A" || got.Companies[0].MappedBy != "op-billing@provider.example.test" {
		t.Fatalf("A's mappings = %+v", got)
	}

	// Customer B may not take A's company: B's counts would reach A's company.
	rec := set(customerB, "Bearer billing-admin", "map-b-conflict-"+suffix, "COMPANY-A")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "billing_company_conflict") {
		t.Fatalf("B mapping A's company = %d %s", rec.Code, rec.Body.String())
	}
	var appended int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM provider_billing_companies WHERE tenant_id = $1`, customerB).Scan(&appended); err != nil || appended != 0 {
		t.Fatalf("B's refused mapping left %d rows (%v)", appended, err)
	}
	if rec := request(http.MethodPut, "/provider/v1/tenants/"+customerB+"/billing-companies/unknown-target", "Bearer billing-admin",
		"map-b-unknown-"+suffix, `{"external_company_id":"COMPANY-B"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown target = %d %s", rec.Code, rec.Body.String())
	}
	if rec := set(customerB, "Bearer break-glass-operator", "map-b-noperm-"+suffix, "COMPANY-B"); rec.Code != http.StatusForbidden {
		t.Fatalf("an operator without billing:write = %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", 129), "line\nbreak"} {
		body, _ := json.Marshal(map[string]string{"external_company_id": bad})
		if rec := request(http.MethodPut, "/provider/v1/tenants/"+customerB+"/billing-companies/psa", "Bearer billing-admin",
			"map-b-bad-"+uuid.NewString(), string(body)); rec.Code != http.StatusBadRequest {
			t.Fatalf("company %q = %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	if rec := set(customerB, "Bearer billing-admin", "map-b-"+suffix, "COMPANY-B"); rec.Code != http.StatusNoContent {
		t.Fatalf("map B = %d %s", rec.Code, rec.Body.String())
	}

	// Clearing A frees COMPANY-A; B may then move to it.
	if rec := request(http.MethodDelete, "/provider/v1/tenants/"+customerA+"/billing-companies/psa", "Bearer billing-admin", "clear-a-"+suffix, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("clear A = %d %s", rec.Code, rec.Body.String())
	}
	if got := companies(customerA); len(got.Companies) != 0 {
		t.Fatalf("A after clearing = %+v", got.Companies)
	}
	if rec := set(customerB, "Bearer billing-admin", "map-b-move-"+suffix, "COMPANY-A"); rec.Code != http.StatusNoContent {
		t.Fatalf("B moving to the freed company = %d %s", rec.Code, rec.Body.String())
	}
	want := companies(customerB)
	if len(want.Companies) != 1 || want.Companies[0].ExternalCompanyID != "COMPANY-A" {
		t.Fatalf("B's mappings = %+v", want.Companies)
	}

	// The authority history alone rebuilds the mappings.
	truncateProviderAuthority(t, st)
	if got := companies(customerB); len(got.Companies) != 0 {
		t.Fatalf("erase left %+v", got.Companies)
	}
	if err := projections.New(st, projections.WithEventProjection(NewAuthorityProjection(st))).Project(ctx, log); err != nil {
		t.Fatalf("Project(event history): %v", err)
	}
	if got := companies(customerB); len(got.Companies) != 1 || got.Companies[0] != want.Companies[0] {
		t.Fatalf("rebuilt B = %+v, want %+v", got.Companies, want.Companies)
	}
	if got := companies(customerA); len(got.Companies) != 0 {
		t.Fatalf("rebuilt A = %+v, want none", got.Companies)
	}
}

// MSP-2 (part 2): a delegated customer's recorded usage pushes are read
// through the plane, newest period first, with each held period's reason; an
// operator without the customer's delegation is refused.
func TestProviderBillingSyncPushHistoryMSP2(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	customer, other := CustomerID("history-a-"+suffix), CustomerID("history-b-"+suffix)
	for _, row := range []struct {
		start, status, reason string
	}{
		{"2026-09-01T00:00:00Z", "delivered", ""},
		{"2026-10-01T00:00:00Z", "held", "metering coverage has a gap"},
	} {
		start, _ := time.Parse(time.RFC3339, row.start)
		if _, err := st.SystemPool().Exec(ctx, `INSERT INTO provider_billing_sync_pushes
			(tenant_id, target_id, period_start, period_end, status, external_company_id, reason, event_sequence, updated_at)
			VALUES ($1, 'psa', $2, $3, $4, 'COMPANY-A', $5, 1, now())`, customer, start, start.AddDate(0, 1, 0), row.status, row.reason); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(Config{
		License:           providerLicense(t, 10),
		Store:             NewPGStore(st),
		Authenticator:     billingOperatorAuth{},
		Delegations:       fullyDelegated("op-billing", customer),
		BillingSyncPushes: st,
	})
	get := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/"+id+"/billing-sync", nil)
		req.Header.Set("Authorization", "Bearer billing-admin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := get(customer)
	var out struct {
		Pushes []BillingSyncPush `json:"pushes"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Pushes) != 2 ||
		out.Pushes[0].Status != "held" || out.Pushes[0].Reason != "metering coverage has a gap" || out.Pushes[1].Status != "delivered" {
		t.Fatalf("history = %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(other); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("an undelegated customer's history = %d %s", rec.Code, rec.Body.String())
	}
}
