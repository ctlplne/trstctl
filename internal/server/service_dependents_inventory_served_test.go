// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
)

func TestServedEnrolledHostDependentInventoryA267(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{servicedependents.InventoryDestination}, func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	projector := projections.New(h.store)
	appendSource := func(kind string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		event, err := h.log.Append(ctx, events.Event{TenantID: h.tenant, Type: kind, Data: raw})
		if err != nil {
			t.Fatal(err)
		}
		if err = projector.Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	const provider = "owned-ad-services"
	const sid = "S-1-5-21-1-2-3-1001"
	appendSource(projections.EventPAMDiscoverySourceSaved, projections.PAMDiscoverySourceSaved{ProviderID: provider, ProviderType: "ldap", Actor: "fixture-reader", At: now})
	appendSource(projections.EventPAMDiscoveryRunCompleted, projections.PAMDiscoveryRunCompleted{RunID: uuid.NewString(), ProviderID: provider, Status: "completed", RequestedBy: "fixture-reader", StartedAt: now, FinishedAt: now, Accounts: []pamdiscovery.Account{{Key: "user:service", Name: "service", Kind: pamdiscovery.KindDirectoryServiceAccount, Details: map[string]string{"dn": "CN=service,DC=lab,DC=test", "service_account": "true", "configured_rotation_account": "true", "native_sid": sid, "native_guid": strings.Repeat("a", 32)}}}})
	accounts, err := h.store.ListPAMDiscoveredAccounts(ctx, h.tenant, provider, "staged", false)
	if err != nil || len(accounts) != 1 {
		t.Fatal("staged native identity missing", err)
	}
	accountID := accounts[0].ID
	hostAgentID := agentRowID(h.tenant, h.agent)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "inventory-operator", "access:read", "access:targets.write")
	root := "/api/v1/access/discovery/accounts/" + accountID + "/dependents"
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+hostAgentID, token, "bind-owned-host", map[string]any{"enabled": true})
	var host struct {
		Binding servicedependents.HostBinding `json:"binding"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &host) != nil || host.Binding.Account.SID != sid || host.Binding.AgentID != hostAgentID {
		t.Fatalf("exact host binding status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+hostAgentID+"/runs", token, "read-owned-host", nil)
	var queued struct {
		ID, Status string
		Intent     servicedependents.InventoryIntent
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("queue native inventory status=%d body=%s", status, body)
	}
	status, replay := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+hostAgentID+"/runs", token, "read-owned-host", nil)
	var replayed struct{ ID string }
	if status != http.StatusAccepted || json.Unmarshal(replay, &replayed) != nil || replayed.ID != queued.ID {
		t.Fatal("inventory queue idempotency changed the operation")
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatal("exact host could not claim read-only inventory", err)
	}
	job := claimed.Jobs[0]
	intent, err := servicedependents.DecodeInventoryIntent(job.Payload)
	if err != nil || intent.RunID != queued.ID || intent.Binding.AgentID != hostAgentID {
		t.Fatal("claim lost its frozen authority", err)
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); err == nil {
		t.Fatal("read-only host inventory redeemed credentials")
	}
	observed := servicedependents.InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(), Coverage: []servicedependents.FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "complete"}}, Services: []windependents.Service{{Name: "owned-service", AccountSID: sid, ConfigSHA256: strings.Repeat("b", 64)}}, Tasks: []windependents.Task{{Path: "\\owned\\task", AccountSID: sid, ConfigSHA256: strings.Repeat("c", 64), Enabled: true, LogonType: 1, ActionCount: 1}}, Pools: []windependents.Pool{{Name: "owned-pool", AccountSID: sid, ConfigSHA256: strings.Repeat("d", 64), EncryptionProvider: "owned-native", PasswordProtected: true}}}
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw)))
	if err != nil || !accepted.Accepted {
		t.Fatal("signed native inventory was not ingested", err)
	}
	runPath := "/api/v1/access/discovery/dependent-runs/" + queued.ID
	check := func() {
		t.Helper()
		code, raw := secretsReq(t, h.servedHarness, http.MethodGet, runPath, token, nil)
		var view struct {
			Status string
			Report *servicedependents.InventoryReport
		}
		if code != http.StatusOK || json.Unmarshal(raw, &view) != nil || view.Status != "complete" || view.Report == nil || len(view.Report.Services) != 1 || len(view.Report.Tasks) != 1 || len(view.Report.Pools) != 1 {
			t.Fatal("observed host inventory differs from the signed metadata")
		}
	}
	check()
	checkLatest := func() {
		t.Helper()
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, root, token, nil)
		var page struct {
			Items []struct {
				BindingDigest string                                      `json:"binding_digest"`
				Latest        *struct{ ID, Status, BindingDigest string } `json:"latest_scan"`
			}
		}
		if status != http.StatusOK || json.Unmarshal(raw, &page) != nil || len(page.Items) != 1 || page.Items[0].Latest == nil || page.Items[0].Latest.ID != queued.ID || page.Items[0].Latest.Status != "complete" || page.Items[0].BindingDigest != intent.BindingDigest {
			t.Fatal("reopening host inventory lost its last scan or current native binding")
		}
	}
	checkLatest()
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "host inventory isolation")
	otherToken := seedScopedToken(t, h.store, other, "access:read", "access:targets.write")
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, runPath, otherToken, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant native inventory read status=%d; require404", code)
	}
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+hostAgentID, otherToken, "foreign-host-binding", map[string]any{"enabled": true}); code != http.StatusNotFound {
		t.Fatalf("cross-tenant host binding status=%d; require404", code)
	}
	if err := projector.ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	check()
	checkLatest()
	// A derived-row rewrite must not send a source-approved read to another host.
	otherAgent := enrollAgentWithRoles(t, h.servedHarness, "inventory-other-host", h.serverName, []string{mtls.AgentRoleHost})
	credentials, err := otherAgent.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := transport.Dial(h.channelAddr, credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	otherClient := transport.NewAgentClient(connection)
	if _, err := otherClient.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "inventory-other-host", Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	code, rawDiverted := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+hostAgentID+"/runs", token, "inventory-diverted-row", nil)
	var diverted struct{ ID string }
	if code != http.StatusAccepted || json.Unmarshal(rawDiverted, &diverted) != nil || diverted.ID == "" {
		t.Fatal("second inventory was not queued")
	}
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE outbox SET required_agent_id=$3 WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, "service-dependent-inventory:"+diverted.ID, agentRowID(h.tenant, "inventory-other-host")); err != nil {
		t.Fatal(err)
	}
	wrongHost, err := otherClient.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(wrongHost.Jobs) != 0 {
		t.Fatal("derived-row rewrite routed a native read to a host absent from the source intent", err)
	}
	// Remove only this test's row-tampering fault before injecting independent row loss.
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE outbox SET required_agent_id=$3 WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, "service-dependent-inventory:"+diverted.ID, hostAgentID); err != nil {
		t.Fatal(err)
	}
	// Exact owned operational-row loss must not lose signed inventory or replay a read.
	if _, err := h.store.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, job.JobID); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatal("signed inventory did not recover after exact operational-row loss", err)
	}
	check()
	reclaimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 4, LeaseSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range reclaimed.Jobs {
		decoded, err := servicedependents.DecodeInventoryIntent(candidate.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.RunID == queued.ID {
			t.Fatal("completed signed source replayed its native read")
		}

	}
	failureAgentID := agentRowID(h.tenant, "inventory-other-host")
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+failureAgentID, token, "bind-failure-host", map[string]any{"enabled": true}); code != http.StatusOK {
		t.Fatal("failure host was not bound")
	}
	partialCode, partialRaw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+failureAgentID+"/runs", token, "inventory-partial-coverage", nil)
	var partialRun struct{ ID string }
	if partialCode != http.StatusAccepted || json.Unmarshal(partialRaw, &partialRun) != nil {
		t.Fatal("partial scan was not queued")
	}
	partialClaim, err := otherClient.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(partialClaim.Jobs) != 1 {
		t.Fatal("partial scan not claimed", err)
	}
	partialJob := partialClaim.Jobs[0]
	partialIntent, err := servicedependents.DecodeInventoryIntent(partialJob.Payload)
	if err != nil || partialIntent.RunID != partialRun.ID {
		t.Fatal("partial scan binding changed", err)
	}
	partialReport := observed
	partialReport.RunID = partialIntent.RunID
	partialReport.BindingDigest = partialIntent.BindingDigest
	partialReport.Pools = nil
	partialReport.Coverage = []servicedependents.FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "unavailable", Failure: "native_read_failed"}}
	partialBytes, err := json.Marshal(partialReport)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := otherClient.ReportJobResult(ctx, signedJobReport(t, otherAgent, partialJob.JobID, partialJob.Attempt, transport.JobOutcomeExecuted, string(partialBytes), crypto.SHA256Hex(partialBytes)))
	if err != nil || !receipt.Accepted {
		t.Fatal("partial coverage receipt refused", err)
	}
	partialView, err := h.store.GetServiceDependentScan(ctx, h.tenant, partialRun.ID)
	if err != nil || partialView.Status != "partial" || partialView.Report == nil || partialView.Report.Complete() || len(partialView.Report.Services) != 1 || len(partialView.Report.Tasks) != 1 {
		t.Fatal("unavailable native family became complete or lost successful families", err)
	}
	code, failedRaw := secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/"+failureAgentID+"/runs", token, "inventory-failure-recovery", nil)
	var failedRun struct{ ID string }
	if code != http.StatusAccepted || json.Unmarshal(failedRaw, &failedRun) != nil || failedRun.ID == "" {
		t.Fatal("failed-path scan was not queued")
	}
	failedClaims, err := otherClient.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.InventoryDestination}, Limit: 4, LeaseSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, candidate := range failedClaims.Jobs {
		decoded, err := servicedependents.DecodeInventoryIntent(candidate.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.RunID != failedRun.ID {
			continue
		}
		matched = true
		failed, err := otherClient.ReportJobResult(ctx, signedJobReport(t, otherAgent, candidate.JobID, candidate.Attempt, transport.JobOutcomeFailed, "native reader unavailable", ""))
		if err != nil || !failed.Accepted {
			t.Fatal("failed native job was not recorded", err)
		}
		getFailed := func() {
			t.Helper()
			value, err := h.store.GetServiceDependentScan(ctx, h.tenant, decoded.RunID)
			if err != nil || value.Status != "retrying" || value.Failure != "agent_execution_failed" || value.ReceiptJobID == nil || *value.ReceiptJobID != candidate.JobID {
				t.Fatalf("signed failed source lost retry state or historical job: status=%s failure=%s receipt=%v err=%v", value.Status, value.Failure, value.ReceiptJobID, err)
			}
		}
		getFailed()
		if _, err := h.store.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, candidate.JobID); err != nil {
			t.Fatal(err)
		}
		if err := projector.Rebuild(ctx, h.log); err != nil {
			t.Fatal(err)
		}
		getFailed()
		current, err := h.store.GetServiceDependentScan(ctx, h.tenant, decoded.RunID)
		if err != nil || current.OutboxID == nil {
			t.Fatal("retry intent missing", err)
		}
		if _, err = h.store.SystemPool().Exec(ctx, `UPDATE outbox SET status='failed' WHERE tenant_id=$1 AND id=$2`, h.tenant, *current.OutboxID); err != nil {
			t.Fatal(err)
		}
		status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/discovery/dependent-runs/"+decoded.RunID, token, nil)
		var view struct {
			Delivery string `json:"delivery_status"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &view) != nil || view.Delivery != "failed" {
			t.Fatal("dead delivery still presented as retrying without terminal transport state")
		}
	}
	if !matched {
		t.Fatal("failed-path exact host job was never claimed")
	}
	type page struct {
		Items []struct {
			Binding struct {
				AgentID string `json:"agent_id"`
			}
		}
		Next string `json:"next_cursor"`
	}
	code, rawPage := secretsReq(t, h.servedHarness, http.MethodGet, root+"?limit=1", token, nil)
	var first page
	if code != http.StatusOK || json.Unmarshal(rawPage, &first) != nil || len(first.Items) != 1 || first.Next == "" {
		t.Fatal("host page omitted cursor")
	}
	code, rawPage = secretsReq(t, h.servedHarness, http.MethodGet, root+"?limit=1&after="+first.Next, token, nil)
	var second page
	if code != http.StatusOK || json.Unmarshal(rawPage, &second) != nil || len(second.Items) != 1 || second.Next != "" || first.Items[0].Binding.AgentID == second.Items[0].Binding.AgentID {
		t.Fatal("host paging repeated or omitted a selected host")
	}
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, root+"?limit=257", token, nil); code != http.StatusBadRequest {
		t.Fatal("unbounded host page admitted")
	}
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, root+"/"+hostAgentID, token, "disable-original-inventory", map[string]any{"enabled": false}); code != http.StatusOK {
		t.Fatal("host inventory disable failed")
	}
	code, staleRaw := secretsReq(t, h.servedHarness, http.MethodGet, root, token, nil)
	var stalePage struct {
		Items []struct {
			Binding servicedependents.HostBinding
			Latest  *struct{ Current bool } `json:"latest_scan"`
		}
	}
	if code != http.StatusOK || json.Unmarshal(staleRaw, &stalePage) != nil {
		t.Fatal("historical host binding could not be reopened")
	}
	foundStale := false
	for _, host := range stalePage.Items {
		if host.Binding.AgentID == hostAgentID {
			foundStale = host.Latest != nil && !host.Latest.Current && !host.Binding.Enabled
		}
	}
	if !foundStale {
		t.Fatal("disabled binding still presents earlier native coverage as current")
	}
	check()

}
