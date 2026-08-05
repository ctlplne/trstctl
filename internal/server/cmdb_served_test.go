// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// I2 through the running binary, not the library.
//
// The recurring defect in this codebase is a capability that is complete,
// tested, and documented, and that no request ever reaches. Unit tests cannot
// catch it because they stand in for the missing caller. So this drives the
// whole loop over HTTP against the assembled server: configure a schedule,
// have the scheduler read a real (fake) ServiceNow instance, and read the
// results back off the served surfaces.

type cmdbSink struct {
	mu       sync.Mutex
	methods  []string
	paths    []string
	queries  []string
	auth     []string
	response string
	srv      *httptest.Server
}

func newCMDBSink(t *testing.T, response string) *cmdbSink {
	t.Helper()
	s := &cmdbSink{response: response}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.methods = append(s.methods, r.Method)
		s.paths = append(s.paths, r.URL.Path)
		s.queries = append(s.queries, r.URL.RawQuery)
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.response))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *cmdbSink) seen() (methods, paths, queries, auth []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.methods...), append([]string(nil), s.paths...),
		append([]string(nil), s.queries...), append([]string(nil), s.auth...)
}

// The full loop: an owner whose application nobody recorded gets filled in from
// the CMDB, and an owner a human attested is left alone and raised as a
// conflict — both reachable over HTTP.
func TestServedCMDBReconcileFillsUnknownAndRefusesAttested(t *testing.T) {
	body := `{"result":[
		{"sys_id":"ci-1","name":"api","owned_by":{"display_value":"payments"},
		 "u_application":{"display_value":"APP-CMDB"},"used_for":"production"},
		{"sys_id":"ci-2","name":"web","owned_by":{"display_value":"platform"},
		 "u_application":{"display_value":"APP-CMDB-2"}}
	]}`
	sink := newCMDBSink(t, body)
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-test-token")
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			InstanceURL:          sink.srv.URL,
			TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
			AllowPrivateEndpoint: true,
			PrivateEgressCIDRs:   []string{serviceNowSinkCIDR(t, sink.srv.URL)},
		}}
	})

	// "payments" has no application recorded — the CMDB may fill it in.
	// "platform" was attested by a human and disagrees — it must not change.
	unknown, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "payments"})
	if err != nil {
		t.Fatal(err)
	}
	attested, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "platform", ApplicationID: "APP-HUMAN"})
	if err != nil {
		t.Fatal(err)
	}
	attested.TenantID = h.tenant
	now := time.Now().UTC()
	attested.OwnershipVerifiedAt = &now
	if err := h.store.UpdateOwner(t.Context(), attested); err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read", string(authz.PrivateEgress))
	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "cmdb-schedule-1", map[string]any{
		"instance_url":           sink.srv.URL,
		"token_ref":              "env:TRSTCTL_SERVICENOW_TOKEN",
		"interval_seconds":       3600,
		"enabled":                true,
		"allow_private_endpoint": true,
	})
	if status != http.StatusOK {
		t.Fatalf("configure schedule: status %d body %s", status, out)
	}

	sched, found, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !found {
		t.Fatalf("schedule not persisted: found=%v err=%v", found, err)
	}
	if _, err := h.srv.RunCMDBReconcileOnce(t.Context(), h.tenant, sched); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	methods, paths, queries, auth := sink.seen()
	if len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("methods = %v, want one GET. Any other verb is a write into a customer's system "+
			"of record", methods)
	}
	if !strings.HasSuffix(paths[0], "/api/now/table/cmdb_ci") {
		t.Fatalf("path = %v, want the fixed cmdb_ci table", paths)
	}
	if !strings.Contains(queries[0], "sysparm_display_value=all") {
		t.Fatalf("query = %q, want display values; a sys_id in an owner column is unusable", queries[0])
	}
	if auth[0] != "Bearer servicenow-test-token" {
		t.Fatalf("Authorization = %q; the token_ref was not resolved", auth[0])
	}

	owners, err := h.store.ListOwnersPage(t.Context(), h.tenant, store.ZeroUUID, 50)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]store.Owner{}
	for _, o := range owners {
		byID[o.ID] = o
	}
	if got := byID[unknown.ID].ApplicationID; got != "APP-CMDB" {
		t.Fatalf("unattested owner's application = %q, want APP-CMDB. Filling in what nobody "+
			"recorded is the main thing this integration is for", got)
	}
	if got := byID[unknown.ID].OwnershipSource; got != "cmdb" {
		t.Fatalf("ownership_source = %q, want cmdb. A value whose origin nobody recorded is the "+
			"exact state this epic exists to end, and an unstamped change recreates it", got)
	}
	if byID[unknown.ID].OwnershipSourceObservedAt == nil {
		t.Fatal("ownership_source_observed_at is nil after a sync that changed the row")
	}
	if got := byID[attested.ID].ApplicationID; got != "APP-HUMAN" {
		t.Fatalf("attested owner's application = %q, want APP-HUMAN unchanged.\n\n"+
			"A spreadsheet overwriting an attestation is how an expiry notice ends up going to a "+
			"team that no longer exists", got)
	}

	status, out = secretsReq(t, h, http.MethodGet, "/api/v1/owners/ownership-conflicts", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list conflicts: status %d body %s", status, out)
	}
	var conflicts struct {
		Items []struct {
			ID              string `json:"id"`
			OwnerID         string `json:"owner_id"`
			Field           string `json:"field"`
			CurrentValue    string `json:"current_value"`
			IncomingValue   string `json:"incoming_value"`
			IncomingRef     string `json:"incoming_ref"`
			CurrentAttested bool   `json:"current_attested"`
		} `json:"items"`
		Refused int `json:"refused"`
	}
	if err := json.Unmarshal(out, &conflicts); err != nil {
		t.Fatal(err)
	}
	if conflicts.Refused != 1 || len(conflicts.Items) != 1 {
		t.Fatalf("conflicts = %+v, want exactly one refused disagreement served", conflicts)
	}
	c := conflicts.Items[0]
	if c.OwnerID != attested.ID || c.CurrentValue != "APP-HUMAN" || c.IncomingValue != "APP-CMDB-2" {
		t.Fatalf("conflict does not carry both sides: %+v", c)
	}
	if c.IncomingRef != "ci-2" {
		t.Fatalf("incoming_ref = %q, want the CI that caused it. A conflict nobody can trace back "+
			"is a conflict nobody can resolve", c.IncomingRef)
	}
	if !c.CurrentAttested {
		t.Error("the served conflict does not record that the stored side was attested — the reason " +
			"the change was refused")
	}
	if c.ID == "" {
		t.Error("the served conflict has no id; an operator has nothing to resolve against")
	}
}

// A tenant must not be able to aim the control plane's egress at any host it
// likes by calling it a CMDB.
func TestServedCMDBScheduleRefusesAnUnapprovedInstance(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "cmdb-schedule-unapproved", map[string]any{
		"instance_url":     "https://attacker.example.com",
		"token_ref":        "env:TRSTCTL_SERVICENOW_TOKEN",
		"interval_seconds": 3600,
		"enabled":          true,
	})
	if status == http.StatusOK {
		t.Fatalf("an unapproved instance was accepted (status %d, body %s).\n\n"+
			"That is a tenant pointing the control plane's ServiceNow credential at a host of its "+
			"choosing", status, body)
	}
}

// A poll tighter than the floor buys rate limiting, not freshness.
func TestServedCMDBScheduleRefusesAHotPoll(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write")
	status, _ := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "cmdb-schedule-hot", map[string]any{
		"instance_url":     "https://example.service-now.com",
		"token_ref":        "env:TRSTCTL_SERVICENOW_TOKEN",
		"interval_seconds": 5,
		"enabled":          true,
	})
	if status == http.StatusOK {
		t.Fatal("a 5-second CMDB poll was accepted; a CMDB's ownership columns change on the order " +
			"of days")
	}
}

// "Never configured" and "configured and paused" must stay distinguishable on
// the served surface: an operator debugging a sync that produced nothing needs
// to know which one they are looking at.
func TestServedCMDBScheduleSeparatesUnconfiguredFromPaused(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/owners/cmdb-schedule", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d body %s", status, body)
	}
	var out struct {
		Configured bool `json:"configured"`
		Enabled    bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Configured {
		t.Fatal("a tenant that never configured a schedule reports configured=true; " +
			"\"never set up\" and \"set up and paused\" are different operator states and one flag " +
			"merges them")
	}
}

// An unauthenticated read must be refused, not answered emptily.
//
// a.tenant does not write a response of its own, so a handler that returns
// silently sends an empty 200 — a read that looks like it succeeded and found
// no schedule. That is the worst possible shape for this endpoint: an operator
// checking whether their CMDB sync is configured would be told "no" by a server
// that never authenticated them.
func TestServedCMDBScheduleRefusesAnUnauthenticatedRead(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	// No token at all.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/owners/cmdb-schedule", "", nil)
	if status == http.StatusOK {
		t.Fatalf("an unauthenticated read returned 200 (%s). An empty 200 reads as \"no schedule "+
			"is configured\", so an operator would be told their CMDB sync is off by a server that "+
			"never authenticated them", body)
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}
