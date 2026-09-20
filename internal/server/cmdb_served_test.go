// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
	sched, _, err = h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	intent := cmdbSyncIntent(sched)
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", "cmdb-schedule-1", []byte(mustJSON(t, intent)), mustJSON(t, CMDBSyncReport{
		SweepID: intent.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: []string{"ci-1", "ci-2"},
		ReadCount: 2, Complete: true, Records: []ownership.Record{
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
	var jobKey string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT count(*), max(required_agent_role), max(convert_from(payload, 'utf8')), max(idempotency_key)
			   FROM outbox WHERE tenant_id = $1 AND destination = 'cmdb.sync'`,
			h.tenant).Scan(&jobs, &role, &payload, &jobKey)
	}); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || role != "network" {
		t.Fatalf("dispatch produced %d jobs with role %q, want exactly one network-stamped job", jobs, role)
	}
	var intent ownership.CMDBSyncIntent
	if err := json.Unmarshal(payload, &intent); err != nil || intent.TokenRef != servedCMDBSecretRef {
		t.Fatalf("job intent = %s (%v); the relay redeems exactly this reference", payload, err)
	}

	// A second due tick must NOT stack a second identical read behind the
	// unclaimed first. The durable incomplete checkpoint is the waiting state;
	// last_run_at remains reserved for terminal success.
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
	if err != nil || sched2.CurrentSweepID == "" || sched2.CoverageComplete || sched2.LastRunAt != nil {
		t.Fatalf("waiting checkpoint = %+v; it must be incomplete and must not look like a successful run", sched2)
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
	report, err := json.Marshal(CMDBSyncReport{
		SweepID: intent.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: []string{"ci-1", "ci-2"},
		ReadCount: 2, Complete: true, Records: []ownership.Record{
			{OwnerName: "payments", ApplicationID: "APP-RELAY", SourceRef: "ci-1"},
			{OwnerName: "platform", ApplicationID: "APP-RELAY-2", SourceRef: "ci-2"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", jobKey, payload, string(report)); err != nil {
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

// AUD-46 end to end: the 501st local owner and the 501st CMDB CI both have to
// exist in the result. Page one commits an incomplete checkpoint and its exact
// next job; only the short second page may stamp last_run_at. Replaying page two
// must be a no-op rather than incrementing coverage or minting another job.
func TestCMDBSweepContinuesPastFiveHundredAndOnlyTerminalPageSucceedsAUD46(t *testing.T) {
	const instanceURL = "https://cmdb.internal.example"
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef}}
	})

	var target store.Owner
	for i := 1; i <= 501; i++ {
		owner := store.Owner{
			ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), TenantID: h.tenant,
			Kind: store.OwnerTeam, Name: fmt.Sprintf("owner-%04d", i),
		}
		if i == 501 {
			owner.Name = "target beyond five hundred"
			target = owner
		}
		if err := h.store.UpsertOwner(t.Context(), owner); err != nil {
			t.Fatalf("seed owner %d: %v", i, err)
		}
	}

	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-aud46-config", map[string]any{
			"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure schedule: %d %s", status, body)
	}
	sched, found, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !found {
		t.Fatalf("load schedule: found=%v err=%v", found, err)
	}
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)

	var firstKey string
	var firstPayload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT idempotency_key, payload FROM outbox
			  WHERE tenant_id = $1 AND destination = 'cmdb.sync' ORDER BY id LIMIT 1`, h.tenant).
			Scan(&firstKey, &firstPayload)
	}); err != nil {
		t.Fatal(err)
	}
	var first ownership.CMDBSyncIntent
	if err := json.Unmarshal(firstPayload, &first); err != nil {
		t.Fatal(err)
	}
	if first.SweepID == "" || first.AfterSysID != "" || first.ReadCount != 0 {
		t.Fatalf("initial intent = %+v, want a named sweep at the first keyset boundary", first)
	}

	refs := make([]string, 500)
	for i := range refs {
		refs[i] = fmt.Sprintf("ci-%04d", i+1)
	}
	unattributed := append([]string(nil), refs[:499]...)
	expected := 501
	pageOne := CMDBSyncReport{
		SweepID: first.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: refs,
		Records:      []ownership.Record{{SourceRef: "ci-0500", OwnerName: target.Name, ApplicationID: "APP-500", Environment: "production"}},
		Unattributed: unattributed,
		ReadCount:    500, ExpectedCount: &expected, Complete: false,
	}
	pageOneJSON := mustJSON(t, pageOne)
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", firstKey, firstPayload, pageOneJSON); err != nil {
		t.Fatalf("ingest first page: %v", err)
	}

	mid, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if mid.CoverageComplete || mid.ReadCount != 500 || mid.AfterSysID != "ci-0500" || mid.PagesCompleted != 1 {
		t.Fatalf("mid-sweep coverage = %+v, want incomplete 500/501 at ci-0500 after one page", mid)
	}
	if mid.LastRunAt != nil {
		t.Fatalf("last_run_at = %v after a full first page; dispatch/partial progress is not success", mid.LastRunAt)
	}

	var secondKey string
	var secondPayload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT idempotency_key, payload FROM outbox
			  WHERE tenant_id = $1 AND destination = 'cmdb.sync' ORDER BY id DESC LIMIT 1`, h.tenant).
			Scan(&secondKey, &secondPayload)
	}); err != nil {
		t.Fatal(err)
	}
	var second ownership.CMDBSyncIntent
	if err := json.Unmarshal(secondPayload, &second); err != nil {
		t.Fatal(err)
	}
	if second.SweepID != first.SweepID || second.AfterSysID != "ci-0500" || second.ReadCount != 500 {
		t.Fatalf("continuation intent = %+v, want the committed first-page boundary", second)
	}
	pageTwo := CMDBSyncReport{
		SweepID: first.SweepID, AfterSysID: "ci-0500", ObservedAt: time.Now().UTC(),
		SourceRefs: []string{"ci-0501"}, ReadCount: 501, ExpectedCount: &expected, Complete: true,
		Records: []ownership.Record{{SourceRef: "ci-0501", OwnerName: target.Name, ApplicationID: "APP-501", Environment: "production"}},
	}
	pageTwoJSON := mustJSON(t, pageTwo)
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", secondKey, secondPayload, pageTwoJSON); err != nil {
		t.Fatalf("ingest terminal page: %v", err)
	}
	// A signed receipt can be retried after the event append acknowledged but
	// before the job close. It must converge on the same page event.
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", secondKey, secondPayload, pageTwoJSON); err != nil {
		t.Fatalf("replay terminal page: %v", err)
	}
	// The first job may retry after page two has committed. Re-accept its exact
	// event, but never re-apply APP-500 over the later APP-501 fact.
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", firstKey, firstPayload, pageOneJSON); err != nil {
		t.Fatalf("replay older full page after terminal page: %v", err)
	}

	done, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !done.CoverageComplete || done.ReadCount != 501 || done.PagesCompleted != 2 || done.LastRunAt == nil {
		t.Fatalf("terminal coverage = %+v, want complete 501/501 after exactly two pages", done)
	}
	gotTarget, err := h.store.GetOwner(t.Context(), h.tenant, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget.ApplicationID != "APP-501" {
		t.Fatalf("501st owner's application = %q; the local owner lookup is still truncated at 500", gotTarget.ApplicationID)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/owners/cmdb-schedule", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read schedule: %d %s", status, body)
	}
	var served struct {
		CoverageComplete bool   `json:"coverage_complete"`
		ReadCount        int    `json:"read_count"`
		ExpectedCount    *int   `json:"expected_count"`
		NextCursor       string `json:"next_cursor"`
		PagesCompleted   int    `json:"pages_completed"`
	}
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatal(err)
	}
	if !served.CoverageComplete || served.ReadCount != 501 || served.ExpectedCount == nil || *served.ExpectedCount != 501 || served.NextCursor != "ci-0501" || served.PagesCompleted != 2 {
		t.Fatalf("served coverage = %+v; API must not turn bounded internal progress into a vague last-run timestamp", served)
	}
}

func TestCMDBSweepReconcilesChangesAndDeletionsIdempotentlyAUD46(t *testing.T) {
	const instanceURL = "https://cmdb.internal.example"
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef}}
	})
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "payments",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-aud46-delete-config", map[string]any{
			"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure: %d %s", status, body)
	}

	page := func(sweepID, application string, present bool) (string, []byte, string) {
		t.Helper()
		intent := ownership.CMDBSyncIntent{
			InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef, PageLimit: cmdbPageLimit,
			SweepID: sweepID,
		}
		if err := h.srv.orch.QueueCMDBSweep(t.Context(), h.tenant, intent, time.Now().UTC()); err != nil {
			t.Fatalf("queue sweep %s: %v", sweepID, err)
		}
		var key string
		var payload []byte
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(),
				`SELECT idempotency_key, payload FROM outbox
				  WHERE tenant_id = $1 AND destination = 'cmdb.sync'
				    AND convert_from(payload, 'utf8')::jsonb ->> 'sweep_id' = $2
				  ORDER BY id DESC LIMIT 1`, h.tenant, sweepID).Scan(&key, &payload)
		}); err != nil {
			t.Fatal(err)
		}
		expected := 0
		report := CMDBSyncReport{
			SweepID: sweepID, ObservedAt: time.Now().UTC(), ExpectedCount: &expected, Complete: true,
		}
		if present {
			expected = 1
			report.SourceRefs = []string{"ci-1"}
			report.ReadCount = 1
			report.Records = []ownership.Record{{
				SourceRef: "ci-1", OwnerName: "payments", ApplicationID: application, Environment: "production",
			}}
		}
		reportJSON := mustJSON(t, report)
		if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", key, payload, reportJSON); err != nil {
			t.Fatalf("record sweep %s: %v", sweepID, err)
		}
		return key, payload, reportJSON
	}

	page("33333333-3333-4333-8333-333333333331", "APP-1", true)
	got, err := h.store.GetOwner(t.Context(), h.tenant, owner.ID)
	if err != nil || got.ApplicationID != "APP-1" {
		t.Fatalf("first source addition = %+v err=%v, want APP-1", got, err)
	}
	page("33333333-3333-4333-8333-333333333332", "APP-2", true)
	got, err = h.store.GetOwner(t.Context(), h.tenant, owner.ID)
	if err != nil || got.ApplicationID != "APP-2" {
		t.Fatalf("source change = %+v err=%v, want APP-2", got, err)
	}
	changed, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || changed.ChangedCount != 1 || changed.RemovedCount != 0 {
		t.Fatalf("change coverage = %+v err=%v, want one changed CI and no removal", changed, err)
	}

	key, payload, reportJSON := page("33333333-3333-4333-8333-333333333333", "", false)
	got, err = h.store.GetOwner(t.Context(), h.tenant, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ApplicationID != "" || got.Environment != "" || got.OwnershipSource != "" {
		t.Fatalf("owner after source deletion = %+v; an unattested value still bound to the vanished CI must be withdrawn", got)
	}
	removed, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || removed.RemovedCount != 1 || removed.ReadCount != 0 || !removed.CoverageComplete {
		t.Fatalf("deletion coverage = %+v err=%v, want one removed CI on a complete empty sweep", removed, err)
	}
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", key, payload, reportJSON); err != nil {
		t.Fatalf("replay deleted terminal page: %v", err)
	}
	replayed, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || replayed.RemovedCount != 1 || replayed.PagesCompleted != 1 {
		t.Fatalf("replayed deletion = %+v err=%v; page/removal counts advanced twice", replayed, err)
	}
}

func TestCMDBSweepDeletionPreservesAttestationAndTenantFenceAUD46(t *testing.T) {
	const (
		instanceURL = "https://cmdb.internal.example"
		otherTenant = "22222222-2222-4222-8222-222222222246"
	)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef}}
	})
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "attested-payments",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-aud46-attested-delete-config", map[string]any{
			"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure: %d %s", status, body)
	}

	completeSweep := func(sweepID string, present bool) {
		t.Helper()
		intent := ownership.CMDBSyncIntent{
			InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef, PageLimit: cmdbPageLimit,
			SweepID: sweepID,
		}
		if err := h.srv.orch.QueueCMDBSweep(t.Context(), h.tenant, intent, time.Now().UTC()); err != nil {
			t.Fatalf("queue sweep %s: %v", sweepID, err)
		}
		var key string
		var payload []byte
		if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(),
				`SELECT idempotency_key, payload FROM outbox
				  WHERE tenant_id = $1 AND destination = 'cmdb.sync'
				    AND convert_from(payload, 'utf8')::jsonb ->> 'sweep_id' = $2
				  ORDER BY id DESC LIMIT 1`, h.tenant, sweepID).Scan(&key, &payload)
		}); err != nil {
			t.Fatal(err)
		}
		expected := 0
		report := CMDBSyncReport{
			SweepID: sweepID, ObservedAt: time.Now().UTC(), ExpectedCount: &expected, Complete: true,
		}
		if present {
			expected = 1
			report.SourceRefs = []string{"ci-attested"}
			report.ReadCount = 1
			report.Records = []ownership.Record{{
				SourceRef: "ci-attested", OwnerName: owner.Name,
				ApplicationID: "APP-CMDB", Environment: "production",
			}}
		}
		if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", key, payload, mustJSON(t, report)); err != nil {
			t.Fatalf("record sweep %s: %v", sweepID, err)
		}
	}

	completeSweep("44444444-4444-4444-8444-444444444441", true)
	owner, err = h.store.GetOwner(t.Context(), h.tenant, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	attestedAt := time.Now().UTC()
	owner.OwnershipVerifiedAt = &attestedAt
	owner.OwnershipVerifiedBy = "operator-aud46"
	if err := h.store.UpdateOwner(t.Context(), owner); err != nil {
		t.Fatal(err)
	}

	if _, err := h.store.SystemPool().Exec(t.Context(),
		`INSERT INTO tenants (tenant_id, name) VALUES ($1, 'aud46-other-tenant')`, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CMDBCIObservationsByRefs(t.Context(), otherTenant, []string{"ci-attested"}); err == nil {
		t.Fatal("another tenant read the first tenant's CMDB inventory row")
	}
	if _, found, err := h.store.GetCMDBReconcileSchedule(t.Context(), otherTenant); err != nil || found {
		t.Fatalf("other tenant schedule: found=%v err=%v; checkpoint crossed the tenant fence", found, err)
	}

	completeSweep("44444444-4444-4444-8444-444444444442", false)
	got, err := h.store.GetOwner(t.Context(), h.tenant, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ApplicationID != "APP-CMDB" || got.Environment != "production" || got.OwnershipSource != "cmdb" {
		t.Fatalf("attested owner after CI deletion = %+v; source disappearance must not erase a human-confirmed value", got)
	}
	schedule, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || schedule.RemovedCount != 1 || !schedule.CoverageComplete {
		t.Fatalf("terminal deletion coverage = %+v err=%v, want one removed CI without erasing attestation", schedule, err)
	}
}

func TestConcurrentDuplicateCMDBTerminalReportsConvergeAUD46(t *testing.T) {
	const instanceURL = "https://cmdb.internal.example"
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef}}
	})
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "concurrent-payments",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-aud46-concurrent-config", map[string]any{
			"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure: %d %s", status, body)
	}
	intent := ownership.CMDBSyncIntent{
		InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef, PageLimit: cmdbPageLimit,
		SweepID: "55555555-5555-4555-8555-555555555546",
	}
	if err := h.srv.orch.QueueCMDBSweep(t.Context(), h.tenant, intent, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var key string
	var payload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT idempotency_key, payload FROM outbox
			  WHERE tenant_id = $1 AND destination = 'cmdb.sync' ORDER BY id DESC LIMIT 1`, h.tenant).
			Scan(&key, &payload)
	}); err != nil {
		t.Fatal(err)
	}
	expected := 1
	report := mustJSON(t, CMDBSyncReport{
		SweepID: intent.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: []string{"ci-concurrent"},
		ReadCount: 1, ExpectedCount: &expected, Complete: true,
		Records: []ownership.Record{{
			SourceRef: "ci-concurrent", OwnerName: owner.Name,
			ApplicationID: "APP-CONCURRENT", Environment: "production",
		}},
	})
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			errs <- h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", key, payload, report)
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent duplicate report %d: %v", i+1, err)
		}
	}

	schedule, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !schedule.CoverageComplete || schedule.PagesCompleted != 1 || schedule.ReadCount != 1 {
		t.Fatalf("concurrent terminal checkpoint = %+v err=%v; duplicate receipt advanced progress twice", schedule, err)
	}
	got, err := h.store.GetOwner(t.Context(), h.tenant, owner.ID)
	if err != nil || got.ApplicationID != "APP-CONCURRENT" {
		t.Fatalf("concurrent owner projection = %+v err=%v", got, err)
	}
}

func TestCMDBReportCannotClaimAnExpectedTotalBehindItsReadCountAUD46(t *testing.T) {
	expected := 0
	intent := ownership.CMDBSyncIntent{
		SweepID: "66666666-6666-4666-8666-666666666646", PageLimit: 500,
	}
	report := ownership.CMDBSyncReport{
		SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
		SourceRefs: []string{"ci-1"}, Unattributed: []string{"orphan"},
		ReadCount: 1, ExpectedCount: &expected, Complete: true,
	}
	if err := validateCMDBSyncReport(intent, report); err == nil || !strings.Contains(err.Error(), "behind") {
		t.Fatalf("expected_count 0 with one observed row = %v; dishonest coverage denominator was accepted", err)
	}
	report.ExpectedCount = nil
	report.SourceRefs[0] = "ci-1^ORsys_id>anything"
	if err := validateCMDBSyncReport(intent, report); err == nil || !strings.Contains(err.Error(), "strict continuation") {
		t.Fatalf("encoded-query source ref = %v; a signed receipt could inject its next keyset query", err)
	}
}

func TestFailedCMDBPageRetainsAndResumesTheExactCursorAUD46(t *testing.T) {
	const instanceURL = "https://cmdb.internal.example"
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: instanceURL, TokenRef: servedCMDBSecretRef}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write")
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-aud46-resume-config", map[string]any{
			"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure: %d %s", status, body)
	}
	sched, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)

	var key string
	var payload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT idempotency_key, payload FROM outbox
			  WHERE tenant_id = $1 AND destination = 'cmdb.sync' ORDER BY id DESC LIMIT 1`, h.tenant).
			Scan(&key, &payload)
	}); err != nil {
		t.Fatal(err)
	}
	failedAt := time.Now().UTC().Truncate(time.Second)
	if err := h.srv.recordCMDBSyncFailure(t.Context(), h.tenant, key, payload, 1, failedAt,
		"cmdb read failed from this relay's vantage"); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.recordCMDBSyncFailure(t.Context(), h.tenant, key, payload, 1, failedAt,
		"cmdb read failed from this relay's vantage"); err != nil {
		t.Fatalf("replay exact failed receipt: %v", err)
	}
	if err := h.srv.recordCMDBSyncFailure(t.Context(), h.tenant, key, payload, 1, failedAt,
		"different failure under the same signed attempt"); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting failed receipt = %v, want idempotency conflict", err)
	}
	failed, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || failed.LastRunAt != nil || failed.CoverageComplete || failed.CurrentSweepID == "" ||
		failed.AfterSysID != "" || failed.ReadCount != 0 || !strings.Contains(failed.LastError, "read failed") {
		t.Fatalf("failed checkpoint = %+v err=%v; failure moved or completed the cursor", failed, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok,
		"cmdb-aud46-reconfigure-mid-sweep", map[string]any{
			"instance_url": instanceURL, "token_ref": servedCMDBSecretRef,
			"ci_query": "active=true", "interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusConflict || !strings.Contains(string(body), "incomplete") {
		t.Fatalf("mid-sweep reconfiguration = %d %s; replacing the query would make the retained cursor describe a different set", status, body)
	}

	// Model the append/SQL or outbox-retention gap a fresh process must heal:
	// the domain checkpoint remains, while its derived job row is absent.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(),
			`DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, failed)
	var resumedKey string
	var resumedPayload []byte
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT idempotency_key, payload FROM outbox
			  WHERE tenant_id = $1 AND destination = 'cmdb.sync' ORDER BY id DESC LIMIT 1`, h.tenant).
			Scan(&resumedKey, &resumedPayload)
	}); err != nil {
		t.Fatal(err)
	}
	if resumedKey != key || string(resumedPayload) != string(payload) {
		t.Fatalf("resumed command = %q %s, want exact %q %s", resumedKey, resumedPayload, key, payload)
	}
	var intent ownership.CMDBSyncIntent
	if err := json.Unmarshal(resumedPayload, &intent); err != nil {
		t.Fatal(err)
	}
	expected := 0
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", resumedKey, resumedPayload, mustJSON(t, CMDBSyncReport{
		SweepID: intent.SweepID, AfterSysID: intent.AfterSysID, ObservedAt: time.Now().UTC(),
		ReadCount: intent.ReadCount, ExpectedCount: &expected, Complete: true,
	})); err != nil {
		t.Fatal(err)
	}
	done, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil || !done.CoverageComplete || done.LastRunAt == nil || done.LastError != "" {
		t.Fatalf("resumed terminal checkpoint = %+v err=%v", done, err)
	}
}
