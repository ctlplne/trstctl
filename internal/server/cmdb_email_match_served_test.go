// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/store"
)

// A88: the CI-to-owner mapping joins on the owner reference's email as well
// as its display name. A CMDB that labels the team "Payments Platform" where
// this estate says "payments" still reconciles when both carry
// payments@example.test; a name is a label, an address is where the expiry
// notice goes. A CI matching neither is counted as unattributed, never created.
func TestServedCMDBReconcileMatchesOwnersByEmailA88(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{InstanceURL: "https://cmdb.internal.example", TokenRef: servedCMDBSecretRef, RelayOnly: true}}
	})
	byEmail, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "payments", Email: "Payments@Example.test"})
	if err != nil {
		t.Fatal(err)
	}
	byName, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "owners:read")
	if status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/cmdb-schedule", tok, "a88-schedule", map[string]any{
		"instance_url": "https://cmdb.internal.example", "token_ref": servedCMDBSecretRef, "interval_seconds": 3600, "enabled": true, "execution": "relay",
	}); status != http.StatusOK {
		t.Fatalf("configure schedule: %d %s", status, out)
	}
	sched, _, err := h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.dispatchCMDBSyncJob(t.Context(), h.tenant, sched)
	sched, _, _ = h.store.GetCMDBReconcileSchedule(t.Context(), h.tenant)
	intent := cmdbSyncIntent(sched)
	if err := h.srv.recordCMDBSync(t.Context(), h.tenant, "relay-1", "a88-report", []byte(mustJSON(t, intent)), mustJSON(t, CMDBSyncReport{
		SweepID: intent.SweepID, ObservedAt: time.Now().UTC(), SourceRefs: []string{"ci-1", "ci-2", "ci-3"}, ReadCount: 3, Complete: true,
		Records: []ownership.Record{
			// The CMDB's label differs; the mailbox is the join.
			{SourceRef: "ci-1", OwnerName: "Payments Platform", Email: "payments@example.test", ApplicationID: "APP-PAY"},
			// No mailbox on the reference: the name still joins.
			{SourceRef: "ci-2", OwnerName: "platform", ApplicationID: "APP-PLAT"},
			// Neither key matches: reported with both.
			{SourceRef: "ci-3", OwnerName: "Network Team", Email: "network@example.test", ApplicationID: "APP-NET"},
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
	if got := byID[byEmail.ID].ApplicationID; got != "APP-PAY" {
		t.Fatalf("owner matched by email has application %q, want APP-PAY: the mailbox join did not happen", got)
	}
	if got := byID[byName.ID].ApplicationID; got != "APP-PLAT" {
		t.Fatalf("owner matched by name has application %q, want APP-PLAT", got)
	}
	// No owner was invented for the CI that matched nothing.
	for _, o := range owners {
		if strings.EqualFold(o.Name, "Network Team") || strings.EqualFold(o.Email, "network@example.test") {
			t.Fatalf("an owner was created from the CMDB label: %+v", o)
		}
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/owners/cmdb-schedule", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("read schedule: %d %s", status, body)
	}
	if !h.hasEvent(t, "cmdb.sweep.page_observed") {
		t.Fatal("no page observation was recorded")
	}
}
