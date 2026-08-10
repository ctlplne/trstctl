// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/ownership"
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

// servedCMDBTokenRef is the legacy env: reference rejected by relay-only APIs.
const servedCMDBTokenRef = "env:TRSTCTL_SERVICENOW_TOKEN" // #nosec G101 -- credential reference (env: pointer), no credential value present (CWE-798)

// servedCMDBSecretRef is the secret-store REFERENCE relay-mode schedules carry;
// the relay redeems the value per attempt. No credential value present.
const servedCMDBSecretRef = "secret://itsm/servicenow-token" // #nosec G101 -- credential reference (secret store pointer), no credential value present (CWE-798)

// The full loop: an owner whose application nobody recorded gets filled in from
// the CMDB, and an owner a human attested is left alone and raised as a
// conflict — both reachable over HTTP.
func TestServedCMDBReconcileFillsUnknownAndRefusesAttested(t *testing.T) {
	const instanceURL = "https://cmdb.internal.example"
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
			InstanceURL: instanceURL,
			TokenRef:    servedCMDBSecretRef,
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

	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read")
	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "cmdb-schedule-1", map[string]any{
		"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
		"interval_seconds": 3600, "enabled": true, "execution": "relay",
	})
	if status != http.StatusOK {
		t.Fatalf("configure schedule: status %d body %s", status, out)
	}

	sched, found, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !found {
		t.Fatalf("schedule not persisted: found=%v err=%v", found, err)
	}
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", "cmdb-schedule-1", []byte(mustJSON(t, cmdbSyncIntent(sched))), mustJSON(t, CMDBSyncReport{
		ObservedAt: time.Now().UTC(), Records: []ownership.Record{
			{SourceRef: "ci-1", OwnerName: "payments", ApplicationID: "APP-CMDB", Environment: "production"},
			{SourceRef: "ci-2", OwnerName: "platform", ApplicationID: "APP-CMDB-2"},
		},
	})); err != nil {
		t.Fatalf("ingest relay observation: %v", err)
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
		"token_ref":        servedCMDBTokenRef,
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
		"token_ref":        servedCMDBTokenRef,
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

// I2's relay half at the served layer: a relay-mode schedule DISPATCHES a
// targeted job instead of fetching, keeps exactly one in flight, and the
// relay's reported records run through the SAME reconcile core — attestation
// rule included.
func TestRelayModeCMDBScheduleDispatchesAndIngestsTheReport(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{
			InstanceURL: "https://cmdb.internal.example",
			TokenRef:    servedCMDBSecretRef,
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read")

	// An env: ref cannot ride relay execution: the variable lives in the
	// control plane's environment, which the relay is not.
	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-relay-bad", map[string]any{
			"instance_url":     "https://cmdb.internal.example",
			"token_ref":        servedCMDBTokenRef,
			"interval_seconds": 3600,
			"enabled":          true,
			"execution":        "relay",
		})
	if status != http.StatusBadRequest || !strings.Contains(string(out), "secret://") {
		t.Fatalf("relay execution with an env: ref = %d %s; accepting it configures a sync that "+
			"fails on its first claim, three hops from the mistake", status, out)
	}

	status, out = secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-relay-ok", map[string]any{
			"instance_url":     "https://cmdb.internal.example",
			"token_ref":        servedCMDBSecretRef,
			"interval_seconds": 3600,
			"enabled":          true,
			"execution":        "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure relay schedule: %d %s", status, out)
	}
	sched, found, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !found || sched.Execution != "relay" {
		t.Fatalf("schedule not persisted with relay execution: found=%v exec=%q err=%v", found, sched.Execution, err)
	}

	// Dispatch: one targeted job appears, stamped for the network vantage.
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)
	var jobs int
	var role string
	var payload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT count(*), max(required_agent_role), max(convert_from(payload, 'utf8'))
			   FROM outbox WHERE tenant_id = $1 AND destination = 'cmdb.sync'`,
			h.tenant).Scan(&jobs, &role, &payload)
	}); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || role != "network" {
		t.Fatalf("dispatch produced %d jobs with role %q, want exactly one network-stamped job", jobs, role)
	}
	var intent struct {
		TokenRef string `json:"token_ref"`
	}
	if err := json.Unmarshal(payload, &intent); err != nil || intent.TokenRef != servedCMDBSecretRef {
		t.Fatalf("job intent = %s (%v); the relay redeems exactly this reference", payload, err)
	}

	// A second due tick must NOT stack a second identical read behind the
	// unclaimed first — it stamps the schedule with the waiting state instead.
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'cmdb.sync'`,
			h.tenant).Scan(&jobs)
	}); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("second tick stacked a job: %d in queue.\n\n"+
			"The eventual relay would replay a backlog of identical reads against the instance.", jobs)
	}
	sched2, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !strings.Contains(sched2.LastError, "waiting") {
		t.Fatalf("the waiting state is not on the schedule (last_error=%q); an operator cannot "+
			"tell 'no relay enrolled' from 'healthy'", sched2.LastError)
	}

	// The report lands: the reconcile core runs on the relay's records, fills
	// the unattested owner, refuses the attested one.
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
	report, err := json.Marshal(CMDBSyncReport{ObservedAt: time.Now().UTC(), Records: []ownership.Record{
		{OwnerName: "payments", ApplicationID: "APP-RELAY", SourceRef: "ci-1"},
		{OwnerName: "platform", ApplicationID: "APP-RELAY-2", SourceRef: "ci-2"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", "idem-1", []byte(mustJSON(t, cmdbSyncIntent(sched))), string(report)); err != nil {
		t.Fatal(err)
	}

	owners, err := h.store.ListOwnersPage(t.Context(), h.tenant, store.ZeroUUID, 50)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]store.Owner{}
	for _, o := range owners {
		byID[o.ID] = o
	}
	if got := byID[unknown.ID].ApplicationID; got != "APP-RELAY" {
		t.Fatalf("unattested owner's application = %q, want APP-RELAY from the relay's report", got)
	}
	if got := byID[attested.ID].ApplicationID; got != "APP-HUMAN" {
		t.Fatalf("attested owner's application = %q, want APP-HUMAN untouched.\n\n"+
			"The reconcile core is SHARED between vantages precisely so the relay path cannot "+
			"grow a version that overwrites what a human attested", got)
	}
	sched3, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || sched3.LastError != "" {
		t.Fatalf("after a successful relay report the schedule still carries error %q", sched3.LastError)
	}
}
