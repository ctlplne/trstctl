// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// MSP-3: a delegated customer's PSA tickets read most recently changed
// first, with the alert kind and subject split out, the PSA's ticket ID and
// the note count; an undelegated customer's tickets are refused.
func TestProviderPSATicketHistoryMSP3(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	customer, other := CustomerID("tickets-a-"+suffix), CustomerID("tickets-b-"+suffix)
	for _, row := range []struct {
		key, status, ticket, reason string
		notes                       int
		age                         time.Duration
	}{
		{"identity.renewal_failed:orders-api", "closed", "501", "a renewal succeeded", 1, 2 * time.Hour},
		{"certificate.expiry:c-1", "open", "502", "", 0, time.Minute},
	} {
		if _, err := st.SystemPool().Exec(ctx, `INSERT INTO provider_psa_tickets (tenant_id, target_id, alert_key, generation, kind, status,
			external_company_id, external_ticket_id, summary, notes, reason, event_sequence, updated_at)
			VALUES ($1, 'cw', $2, 1, split_part($2, ':', 1), $3, 'ALPHA', $4, 'summary', $5, $6, 1, now() - $7::interval)`,
			customer, row.key, row.status, row.ticket, row.notes, row.reason, row.age.String()); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         NewPGStore(st),
		Authenticator: billingOperatorAuth{},
		Delegations:   fullyDelegated("op-billing", customer),
		PSATickets:    st,
	})
	get := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/"+id+"/psa-tickets", nil)
		req.Header.Set("Authorization", "Bearer billing-admin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := get(customer)
	var out struct {
		Tickets []PSATicket `json:"tickets"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Tickets) != 2 ||
		out.Tickets[0].AlertKind != "certificate.expiry" || out.Tickets[0].Subject != "c-1" || out.Tickets[0].ExternalTicketID != "502" ||
		out.Tickets[1].Status != "closed" || out.Tickets[1].Notes != 1 || out.Tickets[1].Reason != "a renewal succeeded" {
		t.Fatalf("tickets = %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(other); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("an undelegated customer's tickets = %d %s", rec.Code, rec.Body.String())
	}
}

// MSP-9: a delegated customer's RMM devices read with their agent mapping,
// health and last action; an undelegated customer's are refused.
func TestProviderRMMDevicesMSP9(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	customer, other := CustomerID("rmm-a-"+suffix), CustomerID("rmm-b-"+suffix)
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO provider_rmm_devices (tenant_id, target_id, device_id, device_name, org_id, present,
		agent_id, agent_match, health, action, action_status, event_sequence, updated_at)
		VALUES ($1, 'ninja', '1001', 'ALPHA-DC01', '11', true, 'agent-1', 'hostname', 'trstctl agent healthy (version 1.4.2)', 'upgrade', 'done', 1, now())`,
		customer); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         NewPGStore(st),
		Authenticator: billingOperatorAuth{},
		Delegations:   fullyDelegated("op-billing", customer),
		RMMDevices:    st,
	})
	get := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/"+id+"/rmm-devices", nil)
		req.Header.Set("Authorization", "Bearer billing-admin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := get(customer)
	var out struct {
		Devices []RMMDevice `json:"devices"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Devices) != 1 || out.Devices[0].AgentMatch != "hostname" ||
		out.Devices[0].Health != "trstctl agent healthy (version 1.4.2)" || out.Devices[0].ActionStatus != "done" || !out.Devices[0].Present {
		t.Fatalf("devices = %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(other); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("an undelegated customer's devices = %d %s", rec.Code, rec.Body.String())
	}
}

type fakeRMMActions struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeRMMActions) QueueRMMAction(_ context.Context, tenantID, targetID, deviceID, action, by, requestKey string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.calls = append(f.calls, strings.Join([]string{tenantID, targetID, deviceID, action, by, requestKey}, "|"))
	return "request-" + deviceID + "-" + action, nil
}

// MSP-9 (agent actions): an operator with rmm:write asks core to install,
// upgrade or remove the agent on a delegated customer's device through an
// RMM target, with the request's idempotency key so a retry queues nothing
// more; an operator without the permission, an undelegated customer, a
// target that is not an RMM, an unknown action and a missing key are
// refused before core is asked; core's refusals (no such device, an action
// in flight) answer 404 and 409; and the console authority offers the
// actions only where the operator may take them.
func TestProviderRMMActionsMSP9(t *testing.T) {
	st := openProviderStore(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	customer, other := CustomerID("rmm-act-a-"+suffix), CustomerID("rmm-act-b-"+suffix)
	queue := &fakeRMMActions{}
	h := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         NewPGStore(st),
		Idempotency:   orchestrator.NewIdempotency(st),
		Authenticator: billingOperatorAuth{},
		Delegations:   fullyDelegated("op-billing", customer),
		BillingTargets: []BillingTarget{{ID: "ninja", Type: "ninjaone", Cadence: "monthly", RMM: true},
			{ID: "psa", Type: "json", Cadence: "monthly"}},
		RMMActions: queue,
	})
	post := func(customerID, target, device, auth, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+customerID+"/rmm-devices/"+target+"/"+device+"/actions", bytes.NewBufferString(body))
		req.Header.Set("Authorization", auth)
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	install := `{"action":"install"}`
	if rec := post(customer, "ninja", "1003", "Bearer billing-admin", "", install); rec.Code != http.StatusBadRequest {
		t.Fatalf("an action without an Idempotency-Key = %d %s", rec.Code, rec.Body.String())
	}
	rec := post(customer, "ninja", "1003", "Bearer billing-admin", "act-"+suffix, install)
	var out struct {
		RequestEventID string `json:"request_event_id"`
		Action         string `json:"action"`
		Status         string `json:"status"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.RequestEventID != "request-1003-install" ||
		out.Action != "install" || out.Status != "requested" {
		t.Fatalf("install = %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(customer, "ninja", "1003", "Bearer billing-admin", "act-"+suffix, install); rec.Code != http.StatusAccepted {
		t.Fatalf("a replayed install = %d %s", rec.Code, rec.Body.String())
	}
	if want := customer + "|ninja|1003|install|op-billing@provider.example.test|act-" + suffix; len(queue.calls) != 1 || queue.calls[0] != want {
		t.Fatalf("core was asked %q, want once %q", queue.calls, want)
	}
	for _, tc := range []struct {
		name, customer, target, auth, body string
		code                               int
		problem                            string
	}{
		{"an operator without rmm:write", customer, "ninja", "Bearer break-glass-operator", install, http.StatusForbidden, "forbidden"},
		{"an undelegated customer", other, "ninja", "Bearer billing-admin", install, http.StatusForbidden, ""},
		{"a target that is not an RMM", customer, "psa", "Bearer billing-admin", install, http.StatusNotFound, "billing_target_unknown"},
		{"an unknown target", customer, "nowhere", "Bearer billing-admin", install, http.StatusNotFound, "billing_target_unknown"},
		{"an unknown action", customer, "ninja", "Bearer billing-admin", `{"action":"reboot"}`, http.StatusBadRequest, "rmm_action_invalid"},
		{"an extra field", customer, "ninja", "Bearer billing-admin", `{"action":"install","script":"x"}`, http.StatusBadRequest, ""},
	} {
		rec := post(tc.customer, tc.target, "1003", tc.auth, "act-"+uuid.NewString(), tc.body)
		codeOK := rec.Code == tc.code || (tc.code == http.StatusForbidden && rec.Code == http.StatusNotFound)
		if !codeOK || !strings.Contains(rec.Body.String(), tc.problem) {
			t.Fatalf("%s = %d %s", tc.name, rec.Code, rec.Body.String())
		}
	}
	if len(queue.calls) != 1 {
		t.Fatalf("a refused request reached core: %q", queue.calls)
	}
	queue.err = orchestrator.ErrRMMDeviceUnknown
	if rec := post(customer, "ninja", "2001", "Bearer billing-admin", "act-unknown-"+suffix, install); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "rmm_device_unknown") {
		t.Fatalf("a device the customer's inventory lacks = %d %s", rec.Code, rec.Body.String())
	}
	queue.err = orchestrator.ErrRMMActionInFlight
	if rec := post(customer, "ninja", "1003", "Bearer billing-admin", "act-busy-"+suffix, `{"action":"upgrade"}`); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "rmm_action_in_flight") {
		t.Fatalf("an action in flight = %d %s", rec.Code, rec.Body.String())
	}

	session := func(handler http.Handler, auth string) ConsoleCustomerAuthority {
		req := httptest.NewRequest(http.MethodGet, "/provider/v1/auth/session", nil)
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var body struct {
			Authority ConsoleAuthority `json:"authority"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("session = %d %s", rec.Code, rec.Body.String())
		}
		return body.Authority.Customers[customer]
	}
	if !session(h, "Bearer billing-admin").WriteRMM || session(h, "Bearer break-glass-operator").WriteRMM {
		t.Fatal("the console offers RMM actions to the wrong operators")
	}
	without := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Authenticator: billingOperatorAuth{},
		Delegations: fullyDelegated("op-billing", customer), BillingTargets: []BillingTarget{{ID: "ninja", Type: "ninjaone", Cadence: "monthly", RMM: true}}})
	if session(without, "Bearer billing-admin").WriteRMM {
		t.Fatal("the console offers RMM actions without the command spine")
	}
}
