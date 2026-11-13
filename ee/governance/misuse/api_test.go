// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/governance/misuse"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

const otherMisuseTenant = "33333333-3333-3333-3333-333333333333"

// M2-L1: GET /api/v1/misuse/findings lists the caller's own tenant's
// findings from the read model, newest first and a page at a time, through
// the real router and its permission check; another tenant's findings never
// appear, whatever the query says.
func TestMisuseFindingsRouteListsTheCallersOwnFindingsM2L1(t *testing.T) {
	ctx := context.Background()
	st := newMisuseTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	proj := projections.New(st)
	for _, tenant := range []string{misuseTenant, otherMisuseTenant} {
		reg, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"misuse tenant"}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := proj.Apply(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}
	findings := misuse.NewProjection(st)
	window := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	record := func(tenant string, f misuse.FindingDetected) {
		t.Helper()
		payload, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := log.Append(ctx, events.Event{Type: misuse.EventFindingDetected, TenantID: tenant, Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		if err := findings.Apply(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	record(misuseTenant, misuse.FindingDetected{Rule: misuse.RuleNewSourceLease, CredentialID: "deployer", Principal: "svc-deployer",
		Source: "10.20.30.0/24", WindowStart: window, ObservedCount: 1, NormalSources: []string{"127.0.0.0/24"}, Alerted: true})
	record(otherMisuseTenant, misuse.FindingDetected{Rule: misuse.RuleSecretReadBurst, CredentialID: "other-reader", Principal: "svc-other",
		Source: "192.0.2.0/24", WindowStart: window, ObservedCount: 512, Baseline: 8, Alerted: true})
	record(misuseTenant, misuse.FindingDetected{Rule: misuse.RuleSecretReadBurst, CredentialID: "reader", Principal: "svc-reader",
		Source: "127.0.0.0/24", WindowStart: window.Add(time.Hour), ObservedCount: 64, Baseline: 2, Alerted: false})

	auditor := authz.Role{Name: "auditor", Permissions: []authz.Permission{authz.AuditRead}}
	bystander := authz.Role{Name: "bystander", Permissions: []authz.Permission{authz.CertsRead}}
	get := func(role authz.Role, query string) (int, misuse.FindingList, string) {
		t.Helper()
		principal := authz.Principal{TenantID: misuseTenant, Subject: "operator",
			Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: misuseTenant}}}}
		a := api.New(nil, nil, nil,
			api.WithLicensedRoutes(misuse.Routes(misuse.StoreFindings{Store: st})...),
			api.WithRoles(auditor, bystander),
			api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
		)
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/misuse/findings"+query, nil))
		var list misuse.FindingList
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
				t.Fatalf("decode %s: %v", rec.Body.String(), err)
			}
		}
		return rec.Code, list, rec.Body.String()
	}

	code, list, body := get(auditor, "")
	if code != http.StatusOK || len(list.Items) != 2 || list.NextCursor != "" {
		t.Fatalf("listing = %d %s, want this tenant's two findings on one page", code, body)
	}
	newest, older := list.Items[0], list.Items[1]
	if newest.Rule != misuse.RuleSecretReadBurst || newest.CredentialID != "reader" || newest.ObservedCount != 64 || newest.Baseline != 2 || newest.Alerted ||
		!newest.WindowStart.Equal(window.Add(time.Hour)) || newest.ID == "" || newest.DetectedAt.IsZero() {
		t.Fatalf("newest finding = %+v, want the uncapped-alert secret read burst", newest)
	}
	if older.Rule != misuse.RuleNewSourceLease || older.CredentialID != "deployer" || older.Source != "10.20.30.0/24" || !older.Alerted {
		t.Fatalf("older finding = %+v, want the new-network lease", older)
	}
	for _, f := range list.Items {
		if f.CredentialID == "other-reader" {
			t.Fatal("another tenant's finding was listed")
		}
	}

	code, first, body := get(auditor, "?limit=1")
	if code != http.StatusOK || len(first.Items) != 1 || first.Items[0].CredentialID != "reader" || first.NextCursor == "" {
		t.Fatalf("first page = %d %s", code, body)
	}
	code, second, body := get(auditor, "?limit=1&cursor="+first.NextCursor)
	if code != http.StatusOK || len(second.Items) != 1 || second.Items[0].CredentialID != "deployer" || second.NextCursor != "" {
		t.Fatalf("second page = %d %s", code, body)
	}
	if code, filtered, body := get(auditor, "?rule=new_source_lease"); code != http.StatusOK || len(filtered.Items) != 1 || filtered.Items[0].CredentialID != "deployer" {
		t.Fatalf("rule filter = %d %s", code, body)
	}
	if code, filtered, body := get(auditor, "?credential_id=other-reader"); code != http.StatusOK || len(filtered.Items) != 0 {
		t.Fatalf("naming another tenant's token = %d %s, want an empty page", code, body)
	}
	for _, bad := range []string{"?rule=everything", "?limit=0", "?limit=201", "?cursor=abc"} {
		if code, _, body := get(auditor, bad); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", bad, code, body)
		}
	}
	if code, _, body := get(bystander, ""); code != http.StatusForbidden {
		t.Fatalf("a caller without audit:read = %d %s, want 403", code, body)
	}
}

// M2-L2: GET /api/v1/misuse/policy answers the thresholds detection uses (the
// defaults until the tenant sets its own), and PUT sets them for a caller who
// may write policy, through the real router, its permission check and its
// idempotency replay; a threshold out of range is a 400 and changes nothing.
func TestMisusePolicyRoutesReadAndSetTheTenantsThresholdsM2L2(t *testing.T) {
	ctx := context.Background()
	st := newMisuseTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	reg, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: misuseTenant, Data: []byte(`{"name":"misuse tenant"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, reg); err != nil {
		t.Fatal(err)
	}
	reader := authz.Role{Name: "policy-reader", Permissions: []authz.Permission{authz.PolicyRead}}
	writer := authz.Role{Name: "policy-writer", Permissions: []authz.Permission{authz.PolicyRead, authz.PolicyWrite}}
	policies := misuse.PolicyStore{Store: st, Log: log, Defaults: misuse.DefaultPolicy(0)}
	call := func(role authz.Role, method, body, key string) (int, misuse.PolicyView, string) {
		t.Helper()
		principal := authz.Principal{TenantID: misuseTenant, Subject: "sec-admin",
			Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: misuseTenant}}}}
		a := api.New(st, orchestrator.NewIdempotency(st), nil,
			api.WithLicensedRoutes(misuse.PolicyRoutes(policies)...),
			api.WithRoles(reader, writer),
			api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
		)
		req := httptest.NewRequest(method, "/api/v1/misuse/policy", strings.NewReader(body))
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		var view misuse.PolicyView
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
				t.Fatalf("decode %s: %v", rec.Body.String(), err)
			}
		}
		return rec.Code, view, rec.Body.String()
	}
	if code, view, body := call(reader, http.MethodGet, "", ""); code != http.StatusOK || view.Custom || view.Policy != misuse.DefaultPolicy(0) {
		t.Fatalf("defaults = %d %s", code, body)
	}
	set := `{"normal_days":5,"burst_floor":128,"burst_factor":6,"burst_lookback_days":30,"hourly_alert_cap":40}`
	if code, _, body := call(reader, http.MethodPut, set, "m2l2-reader"); code != http.StatusForbidden {
		t.Fatalf("a caller without policy:write = %d %s, want 403", code, body)
	}
	if code, _, body := call(writer, http.MethodPut, `{"normal_days":5,"burst_floor":128,"burst_factor":1,"burst_lookback_days":30,"hourly_alert_cap":40}`, "m2l2-bad"); code != http.StatusBadRequest || !strings.Contains(body, "burst_factor") {
		t.Fatalf("a factor of 1 = %d %s, want 400 naming it", code, body)
	}
	want := misuse.Policy{NormalDays: 5, BurstFloor: 128, BurstFactor: 6, BurstLookbackDays: 30, HourlyAlertCap: 40}
	code, view, body := call(writer, http.MethodPut, set, "m2l2-set")
	if code != http.StatusOK || !view.Custom || view.Policy != want || view.SetBy != "sec-admin" {
		t.Fatalf("set = %d %s", code, body)
	}
	if code, again, body := call(writer, http.MethodPut, set, "m2l2-set"); code != http.StatusOK || again.Policy != want {
		t.Fatalf("an idempotent replay = %d %s", code, body)
	}
	var recorded int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM misuse_policies WHERE tenant_id = $1`, misuseTenant).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("policy rows = %d, %v", recorded, err)
	}
	if code, view, body := call(reader, http.MethodGet, "", ""); code != http.StatusOK || view.Policy != want || !view.Custom {
		t.Fatalf("read back = %d %s", code, body)
	}
}

// M2-L3: GET /api/v1/misuse/incidents lists the tenant's misuse incidents
// (incidents:read) and POST /api/v1/misuse/incidents/{id}/close closes one
// with a resolution (incidents:write) through the real router: a caller
// without the permission is refused, a bad resolution is a 400, a missing
// incident a 404, a second close a 409.
func TestMisuseIncidentRoutesListAndCloseM2L3(t *testing.T) {
	ctx := context.Background()
	st := newMisuseTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	proj := projections.New(st)
	reg, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: misuseTenant, Data: []byte(`{"name":"misuse tenant"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := proj.Apply(ctx, reg); err != nil {
		t.Fatal(err)
	}
	findings := misuse.NewProjection(st)
	opened, err := log.Append(ctx, events.Event{Type: misuse.EventIncidentOpened, TenantID: misuseTenant,
		Data: []byte(`{"incident_id":"inc-1","credential_id":"reader","principal":"svc-reader","finding_id":"inc-1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := findings.Apply(ctx, opened); err != nil {
		t.Fatal(err)
	}
	reader := authz.Role{Name: "incident-reader", Permissions: []authz.Permission{authz.IncidentsRead}}
	writer := authz.Role{Name: "incident-writer", Permissions: []authz.Permission{authz.IncidentsRead, authz.IncidentsWrite}}
	incidents := misuse.IncidentStore{Store: st, Log: log}
	call := func(role authz.Role, method, path, body string) (int, string) {
		t.Helper()
		principal := authz.Principal{TenantID: misuseTenant, Subject: "responder",
			Grants: []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: misuseTenant}}}}
		a := api.New(st, orchestrator.NewIdempotency(st), nil,
			api.WithLicensedRoutes(misuse.IncidentRoutes(incidents)...),
			api.WithRoles(reader, writer),
			api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
		)
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if method != http.MethodGet {
			req.Header.Set("Idempotency-Key", "m2l3-"+strconv.Itoa(len(body))+"-"+role.Name+"-"+path)
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := call(reader, http.MethodGet, "/api/v1/misuse/incidents?status=open", ""); code != http.StatusOK ||
		!strings.Contains(body, `"id":"inc-1"`) || !strings.Contains(body, `"status":"open"`) {
		t.Fatalf("open incidents = %d %s", code, body)
	}
	if code, body := call(reader, http.MethodGet, "/api/v1/misuse/incidents?status=everything", ""); code != http.StatusBadRequest {
		t.Fatalf("a bad status = %d %s", code, body)
	}
	if code, body := call(reader, http.MethodPost, "/api/v1/misuse/incidents/inc-1/close", `{"resolution":"expected_use"}`); code != http.StatusForbidden {
		t.Fatalf("closing without incidents:write = %d %s", code, body)
	}
	if code, body := call(writer, http.MethodPost, "/api/v1/misuse/incidents/inc-1/close", `{"resolution":"shrug"}`); code != http.StatusBadRequest {
		t.Fatalf("a bad resolution = %d %s", code, body)
	}
	if code, body := call(writer, http.MethodPost, "/api/v1/misuse/incidents/inc-9/close", `{"resolution":"other"}`); code != http.StatusNotFound {
		t.Fatalf("a missing incident = %d %s", code, body)
	}
	if code, body := call(writer, http.MethodPost, "/api/v1/misuse/incidents/inc-1/close", `{"resolution":"expected_use","note":"nightly batch"}`); code != http.StatusOK ||
		!strings.Contains(body, `"status":"closed"`) || !strings.Contains(body, `"closed_by":"responder"`) {
		t.Fatalf("close = %d %s", code, body)
	}
	if code, body := call(writer, http.MethodPost, "/api/v1/misuse/incidents/inc-1/close", `{"resolution":"other"}`); code != http.StatusConflict {
		t.Fatalf("a second close = %d %s", code, body)
	}
}
