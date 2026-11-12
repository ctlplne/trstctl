// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
)

// directoryServiceProbeA267O1 is an AD discovery source whose one service
// account's native identity a test can change between scans.
type directoryServiceProbeA267O1 struct {
	dynsecret.Provider
	mu   sync.Mutex
	guid string
}

func (*directoryServiceProbeA267O1) Name() string                      { return "owned-ad-dependents" }
func (*directoryServiceProbeA267O1) DynamicSecretProviderType() string { return "ldap" }
func (p *directoryServiceProbeA267O1) DynamicSecretDiscoverAccounts(context.Context) ([]pamdiscovery.Account, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return []pamdiscovery.Account{{Key: "user:svc-orders", Name: "svc-orders", Kind: pamdiscovery.KindDirectoryServiceAccount,
		Details: map[string]string{"dn": "CN=svc-orders,OU=Services,DC=lab,DC=test", "service_account": "true", "configured_rotation_account": "true",
			"native_sid": "S-1-5-21-7-8-9-1107", "native_guid": p.guid}}}, nil
}

// TestServedADDiscoveryQueuesDependentInventoryA267O1 is A267-O1: an AD
// discovery run feeds the enrolled-host dependent inventory through the
// same-transaction outbox. Once an operator binds an enrolled host to a
// discovered service account, the next discovery run queues that host's
// read-only inventory as the binding's own run would: a queued dependent
// scan naming the run's requester, and an outbox row only that host can
// claim, carrying the binding's frozen authority. A rebuild queues nothing
// twice, and a run that finds the account's native identity changed queues
// nothing until the binding is reviewed.
func TestServedADDiscoveryQueuesDependentInventoryA267O1(t *testing.T) {
	ctx := t.Context()
	provider := &directoryServiceProbeA267O1{guid: strings.Repeat("a", 32)}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{servicedependents.InventoryDestination}, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: []dynsecret.Provider{provider}}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedTokenSubject(t, h.store, h.tenant, "discovery-operator", "access:read", "access:targets.write")
	source := "/api/v1/access/discovery/sources/" + provider.Name()
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPut, source, token, "a267o1-save", map[string]any{"interval_seconds": 0}); code != http.StatusOK {
		t.Fatalf("save the AD source = %d %s", code, body)
	}
	scans := 0
	scan := func() string {
		t.Helper()
		scans++
		code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, source+"/runs", token, "a267o1-scan-"+strconv.Itoa(scans), nil)
		var queued struct{ ID string }
		if code != http.StatusAccepted || json.Unmarshal(raw, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue scan %d = %d %s", scans, code, raw)
		}
		if _, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
			t.Fatal(err)
		}
		code, raw = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/runs/"+queued.ID, token, nil)
		var done struct{ Status string }
		if code != http.StatusOK || json.Unmarshal(raw, &done) != nil || done.Status != "completed" {
			t.Fatalf("scan %d = %d %s", scans, code, raw)
		}
		return queued.ID
	}
	dependentRows := func() int {
		t.Helper()
		var count int
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, h.tenant,
			servicedependents.InventoryDestination).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	// The first scan finds the service account; no host is bound yet.
	scan()
	accounts, err := h.store.ListPAMDiscoveredAccounts(ctx, h.tenant, provider.Name(), "staged", false)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("discovered accounts = %+v, %v", accounts, err)
	}
	if got := dependentRows(); got != 0 {
		t.Fatalf("a scan with no bound host queued %d inventories", got)
	}
	accountID, hostAgentID := accounts[0].ID, agentRowID(h.tenant, h.agent)
	dependents := "/api/v1/access/discovery/accounts/" + accountID + "/dependents"
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPut, dependents+"/"+hostAgentID, token, "a267o1-bind", map[string]any{"enabled": true}); code != http.StatusOK {
		t.Fatalf("bind the enrolled host = %d %s", code, body)
	}

	// The next scan feeds the bound host's inventory.
	scan()
	if got := dependentRows(); got != 1 {
		t.Fatalf("the scan after binding queued %d host inventories, want 1", got)
	}
	code, raw := secretsReq(t, h.servedHarness, http.MethodGet, dependents, token, nil)
	var listed struct {
		Items []struct {
			LatestScan *struct {
				ID       string `json:"id"`
				Status   string `json:"status"`
				QueuedBy string `json:"queued_by"`
			} `json:"latest_scan"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &listed) != nil || len(listed.Items) != 1 || listed.Items[0].LatestScan == nil {
		t.Fatalf("dependents = %d %s", code, raw)
	}
	head := listed.Items[0].LatestScan
	scanView, err := h.store.GetServiceDependentScan(ctx, h.tenant, head.ID)
	if err != nil || scanView.Status != "queued" || scanView.QueuedBy != "discovery-operator" || scanView.OutboxID == nil {
		t.Fatalf("the fed scan = %+v, %v", scanView, err)
	}
	var key, requiredAgent string
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT idempotency_key, COALESCE(required_agent_id::text,'') FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, *scanView.OutboxID).
		Scan(&key, &requiredAgent); err != nil || key != "service-dependent-inventory:"+head.ID || requiredAgent != hostAgentID {
		t.Fatalf("the fed scan's outbox row = %q for %q, %v", key, requiredAgent, err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("the bound host could not claim its inventory: %v", err)
	}
	intent, err := servicedependents.DecodeInventoryIntent(claimed.Jobs[0].Payload)
	if err != nil || intent.RunID != head.ID || intent.Binding.AgentID != hostAgentID || intent.Binding.Account.AccountID != accountID {
		t.Fatalf("the claimed inventory lost its frozen authority: %+v, %v", intent, err)
	}

	// A rebuild queues nothing twice.
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if got := dependentRows(); got != 1 {
		t.Fatalf("after a rebuild the host has %d inventory rows, want 1", got)
	}

	// A scan that finds the account's native identity changed queues
	// nothing: the binding waits for review.
	provider.mu.Lock()
	provider.guid = strings.Repeat("b", 32)
	provider.mu.Unlock()
	scan()
	if got := dependentRows(); got != 1 {
		t.Fatalf("a scan with a changed account identity queued an inventory (%d rows)", got)
	}
	t.Logf("A267O1_DISCOVERY_DEPENDENTS_OK scan=%s", head.ID)
}
