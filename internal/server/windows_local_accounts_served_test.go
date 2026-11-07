// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedEnrolledWindowsLocalAdministratorInventoryA268(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{hostaccounts.InventoryDestination}, func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	hostID := agentRowID(h.tenant, h.agent)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "local-inventory-operator", "access:read", "access:targets.write")
	root := "/api/v1/access/discovery/windows-hosts/" + hostID + "/local-administrators/runs"
	type scanView struct {
		ID             string                        `json:"id"`
		Status         string                        `json:"status"`
		Failure        string                        `json:"failure"`
		ReportDigest   string                        `json:"report_digest"`
		DeliveryStatus string                        `json:"delivery_status"`
		Intent         hostaccounts.InventoryIntent  `json:"intent"`
		Report         *hostaccounts.InventoryReport `json:"report"`
		ReceiptJobID   *int64                        `json:"receipt_job_id"`
		Attempt        *int                          `json:"attempt"`
	}

	queue := func(path, key string) scanView {
		t.Helper()
		code, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, path, token, key, nil)
		var v scanView
		if code != http.StatusAccepted || json.Unmarshal(raw, &v) != nil || v.ID == "" || v.Status != "queued" || v.Intent.AgentID == "" || v.Intent.TenantID != h.tenant {
			t.Fatalf("enrolled-host inventory queue status=%d body=%s", code, raw)
		}
		return v
	}
	queued := queue(root, "read-local-admins")
	sourceView, err := h.srv.pam.ListPAMDiscoverySources(ctx, h.tenant)
	if err != nil || len(sourceView) != 1 || sourceView[0].LastRun == nil || sourceView[0].LastRun.ID != queued.ID || sourceView[0].LastRun.Status != "queued" {
		t.Fatal("discovery source hid the host's pending read", err)
	}
	again := queue(root, "read-local-admins")
	if again.ID != queued.ID {
		t.Fatal("idempotent request queued a second native read")
	}
	claims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 1 {
		t.Fatal("exact host did not claim inventory", err)
	}
	job := claims.Jobs[0]
	intent, err := hostaccounts.DecodeInventoryIntent(job.Payload)
	if err != nil || intent != queued.Intent {
		t.Fatal("claimed read differs from queued source", err)
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); err == nil {
		t.Fatal("read-only inventory redeemed a credential")
	}
	observed := hostaccounts.InventoryReport{RunID: intent.RunID, BindingDigest: intent.BindingDigest, ObservedAt: time.Now().UTC(), Status: "complete", Inventory: &winaccounts.Inventory{Machine: winaccounts.Machine{Name: "OWNED-HOST", SID: "S-1-5-21-1-2-3", Role: 3}, Accounts: []winaccounts.Account{{Name: "OwnedAdmin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}}}
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	receipt := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw))
	accepted, err := h.client.ReportJobResult(ctx, receipt)
	if err != nil || !accepted.Accepted {
		t.Fatal("signed host-local inventory was refused", err)
	}
	check := func() {
		t.Helper()
		code, raw := secretsReq(t, h.servedHarness, http.MethodGet, root+"/"+queued.ID, token, nil)
		var v scanView
		if code != http.StatusOK || json.Unmarshal(raw, &v) != nil || v.Status != "complete" || v.Report == nil || v.ReportDigest != crypto.SHA256Hex(mustLocalInventoryJSON(t, observed)) || v.ReceiptJobID == nil || *v.ReceiptJobID != job.JobID || v.Attempt == nil || *v.Attempt != job.Attempt || len(v.Report.Inventory.Accounts) != 1 {
			t.Fatalf("signed local inventory unavailable status=%d body=%s", code, raw)
		}
	}
	check()
	completedRun, err := h.store.GetPAMDiscoveryRun(ctx, h.tenant, queued.ID)
	if err != nil || completedRun.Status != "completed" || completedRun.DeliveryStatus != "delivered" || completedRun.Accounts != 1 {
		t.Fatal("discovery timeline disagreed with the signed host read and actual delivery", err)
	}
	code, pageRaw := secretsReq(t, h.servedHarness, http.MethodGet, root+"?limit=1", token, nil)
	var page struct {
		Items      []scanView `json:"items"`
		NextCursor string     `json:"next_cursor"`
	}
	if code != http.StatusOK || json.Unmarshal(pageRaw, &page) != nil || len(page.Items) != 1 || page.Items[0].ID != queued.ID || page.Items[0].Status != "complete" || page.Items[0].Report != nil || page.Items[0].DeliveryStatus != "delivered" {
		t.Fatal("bounded scan summaries lost signed completion or loaded full reports")
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "local inventory isolation")
	otherToken := seedScopedToken(t, h.store, other, "access:read", "access:targets.write")
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, root+"/"+queued.ID, otherToken, nil); code != http.StatusNotFound {
		t.Fatal("foreign tenant read native host metadata", code)
	}
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, otherToken, "foreign-host-read", nil); code != http.StatusNotFound {
		t.Fatal("foreign tenant queued native host read", code)
	}
	readOnly := seedScopedTokenSubject(t, h.store, h.tenant, "local-inventory-reader", "access:read")
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, readOnly, "reader-mutation", nil); code != http.StatusForbidden {
		t.Fatal("reader queued native read", code)
	}
	// No host polling is required to retain work due for a host that is away.
	pending := queue(root, "offline-local-admins")
	if code, raw := secretsReq(t, h.servedHarness, http.MethodGet, root+"/"+pending.ID, token, nil); code != http.StatusOK {
		t.Fatal("offline pending read disappeared", string(raw))
	}
	projector := projections.New(h.store)
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
	accepted, err = h.client.ReportJobResult(ctx, receipt)
	// A replayed terminal statement acknowledges historical evidence only.
	if err != nil || accepted.Accepted || !accepted.ReceiptRecorded || accepted.LeaseExpiresUnix != 0 {
		t.Fatalf("historical receipt acknowledgement changed current authority: response=%+v err=%v", accepted, err)
	}
	claims, err = h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 2, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 1 {
		t.Fatal("offline read was lost or completed read ran again", err)
	}
	resumed, err := hostaccounts.DecodeInventoryIntent(claims.Jobs[0].Payload)
	if err != nil || resumed.RunID != pending.ID {
		t.Fatal("returning host got a different native read", err)
	}
	// Unavailable coverage is retained without erasing the last complete inventory.
	unavailable := hostaccounts.InventoryReport{RunID: resumed.RunID, BindingDigest: resumed.BindingDigest, ObservedAt: time.Now().UTC(), Status: "unavailable", Failure: "native_read_failed"}
	unavailableRaw := mustLocalInventoryJSON(t, unavailable)
	resumedJob := claims.Jobs[0]
	response, err := h.client.ReportJobResult(ctx, h.report(t, resumedJob.JobID, resumedJob.Attempt, transport.JobOutcomeExecuted, string(unavailableRaw), crypto.SHA256Hex(unavailableRaw)))
	if err != nil || !response.Accepted {
		t.Fatal("explicit unavailable coverage refused", err)
	}
	staged, err := h.store.ListPAMDiscoveredAccounts(ctx, h.tenant, store.WindowsHostAccountProviderID(hostID), "staged", false)
	if err != nil || len(staged) != 1 || staged[0].Account.Details["native_sid"] != "S-1-5-21-1-2-3-1001" {
		t.Fatal("failed native read erased or replaced complete account inventory", err)
	}
	// A derived completion bit supplies no signed fact.
	spoof := queue(root, "spoof-local-cache")
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE windows_local_account_scans SET status='complete' WHERE tenant_id=$1 AND id=$2`, h.tenant, spoof.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, root+"/"+spoof.ID, token, nil); code != http.StatusInternalServerError {
		t.Fatal("SQL completion bit became native proof", code)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE windows_local_account_scans SET status='queued' WHERE tenant_id=$1 AND id=$2`, h.tenant, spoof.ID); err != nil {
		t.Fatal(err)
	}
	claims, err = h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claims.Jobs) != 1 {
		t.Fatal("source-gap inventory claim absent", err)
	}
	gapJob := claims.Jobs[0]
	gapIntent, err := hostaccounts.DecodeInventoryIntent(gapJob.Payload)
	if err != nil {
		t.Fatal(err)
	}
	gapReport := observed
	gapReport.RunID = gapIntent.RunID
	gapReport.BindingDigest = gapIntent.BindingDigest
	gapReport.ObservedAt = time.Now().UTC()
	gapRaw := mustLocalInventoryJSON(t, gapReport)
	gapReceipt := h.report(t, gapJob.JobID, gapJob.Attempt, transport.JobOutcomeExecuted, string(gapRaw), crypto.SHA256Hex(gapRaw))
	// Interrupt exactly the new source's projection, after its immutable append.
	const install = `CREATE FUNCTION c585_local_inventory_update_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned local inventory projection interruption'; END $$;
 CREATE TRIGGER c585_local_inventory_update_failure BEFORE UPDATE ON windows_local_account_scans FOR EACH ROW WHEN (NEW.report_digest <> '') EXECUTE FUNCTION c585_local_inventory_update_failure()`
	const remove = `DROP TRIGGER IF EXISTS c585_local_inventory_update_failure ON windows_local_account_scans; DROP FUNCTION IF EXISTS c585_local_inventory_update_failure()`
	if _, err := h.store.SystemPool().Exec(ctx, install); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := h.store.SystemPool().Exec(context.Background(), remove); err != nil {
			t.Errorf("remove owned projection interruption: %v", err)
		}
	})
	response, err = h.client.ReportJobResult(ctx, gapReceipt)
	if err == nil && response.Accepted {
		t.Fatal("interrupted native projection was acknowledged as applied")
	}
	sourceID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl/windows-local-inventory/observed/"+h.tenant+"/"+gapIntent.RunID)).String()
	retained, found, err := h.log.EventByID(ctx, sourceID)
	if err != nil || !found || retained.Type != projections.EventWindowsLocalAccountScanObserved {
		t.Fatal("native report was not retained before SQL interruption", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, remove); err != nil {
		t.Fatal(err)
	}
	response, err = h.client.ReportJobResult(ctx, gapReceipt)
	if err != nil || !response.Accepted {
		t.Fatal("exact retained report could not finish after projection recovery", err)
	}
	recovered, err := h.store.GetWindowsLocalAccountScan(ctx, h.tenant, gapIntent.RunID)
	if err != nil || recovered.ObservedEventID != retained.ID || recovered.ReportDigest != crypto.SHA256Hex(gapRaw) {
		t.Fatal("projection recovery replaced original signed observation", err)
	}
	// A malformed signed report is a failed run, not a successful empty scan.
	rejected := queue(root, "invalid-local-native-report")
	rejectedClaims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(rejectedClaims.Jobs) != 1 {
		t.Fatal("invalid-report fixture claim absent", err)
	}
	rejectedJob := rejectedClaims.Jobs[0]
	rejectedIntent, err := hostaccounts.DecodeInventoryIntent(rejectedJob.Payload)
	if err != nil || rejectedIntent.RunID != rejected.ID {
		t.Fatalf("invalid-report claim binding differs: run=%s expected=%s err=%v", rejectedIntent.RunID, rejected.ID, err)
	}
	var invalid hostaccounts.InventoryReport
	if err := json.Unmarshal(mustLocalInventoryJSON(t, observed), &invalid); err != nil {
		t.Fatal(err)
	}
	invalid.RunID = rejected.ID
	invalid.BindingDigest = rejected.Intent.BindingDigest
	invalid.ObservedAt = time.Now().UTC()
	invalid.Inventory.Accounts[0].SID = "S-1-5-21-9-8-7-1001"
	invalidRaw := mustLocalInventoryJSON(t, invalid)
	response, reportErr := h.client.ReportJobResult(ctx, h.report(t, rejectedJob.JobID, rejectedJob.Attempt, transport.JobOutcomeExecuted, string(invalidRaw), crypto.SHA256Hex(invalidRaw)))
	// Accepted acknowledges the terminal failed claim, not native inventory.
	// Require acknowledgement so the host does not retry the refused observation.
	if reportErr != nil || !response.Accepted || response.LeaseExpiresUnix != 0 {
		t.Fatalf("permanent native refusal was not acknowledged: response=%+v err=%v", response, reportErr)
	}
	failed, err := h.store.GetWindowsLocalAccountScan(ctx, h.tenant, rejected.ID)
	if err != nil || failed.Status != "failed" || failed.Failure != "invalid_native_report" || failed.Report != nil {
		t.Fatalf("invalid signed observation did not retain bounded failure: scan=%+v response=%+v reportErr=%v readErr=%v", failed, response, reportErr, err)
	}
	discoveryRun, err := h.store.GetPAMDiscoveryRun(ctx, h.tenant, rejected.ID)
	if err != nil || discoveryRun.Status != "failed" || discoveryRun.Failure != "invalid_native_report" {
		t.Fatal("discovery timeline kept a permanently refused native read pending", err)
	}
	staged, err = h.store.ListPAMDiscoveredAccounts(ctx, h.tenant, store.WindowsHostAccountProviderID(hostID), "staged", false)
	if err != nil || len(staged) != 1 || staged[0].Account.Details["native_sid"] != "S-1-5-21-1-2-3-1001" {
		t.Fatal("rejected foreign SID altered staged local inventory", err)
	}
	// Losing a queue projection must replay the same source, not mint a new run.
	beforeQueueGap, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const installQueueGap = `CREATE FUNCTION c585_local_inventory_insert_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned local inventory insert interruption'; END $$;
 CREATE TRIGGER c585_local_inventory_insert_failure BEFORE INSERT ON windows_local_account_scans FOR EACH ROW EXECUTE FUNCTION c585_local_inventory_insert_failure()`
	const removeQueueGap = `DROP TRIGGER IF EXISTS c585_local_inventory_insert_failure ON windows_local_account_scans; DROP FUNCTION IF EXISTS c585_local_inventory_insert_failure()`
	if _, err := h.store.SystemPool().Exec(ctx, installQueueGap); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := h.store.SystemPool().Exec(context.Background(), removeQueueGap); err != nil {
			t.Errorf("remove owned queue interruption: %v", err)
		}
	})
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, root, token, "retained-native-queue", nil); code != http.StatusInternalServerError {
		t.Fatal("interrupted queue was acknowledged as ready", code)
	}
	var retainedQueue projections.WindowsLocalAccountScanQueued
	queueSources := 0
	if err := h.log.Replay(ctx, beforeQueueGap, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == projections.EventWindowsLocalAccountScanQueued {
			queueSources++
			return json.Unmarshal(e.Data, &retainedQueue)
		}
		return nil
	}); err != nil || queueSources != 1 {
		t.Fatal("queue intent did not survive its projection interruption", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, removeQueueGap); err != nil {
		t.Fatal(err)
	}
	retriedQueue := queue(root, "retained-native-queue")
	if retriedQueue.ID != retainedQueue.Intent.RunID {
		t.Fatal("same interrupted request minted a second native inventory intent")
	}
	queueGapClaims, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 2, LeaseSeconds: 120})
	if err != nil || len(queueGapClaims.Jobs) != 1 {
		t.Fatal("queue recovery lost or duplicated native work", err)
	}
	queueGapJob := queueGapClaims.Jobs[0]
	queueGapIntent, err := hostaccounts.DecodeInventoryIntent(queueGapJob.Payload)
	if err != nil || queueGapIntent.RunID != retriedQueue.ID {
		t.Fatal("recovered queue changed source authority", err)
	}
	queueGapReport := hostaccounts.InventoryReport{RunID: queueGapIntent.RunID, BindingDigest: queueGapIntent.BindingDigest, ObservedAt: time.Now().UTC(), Status: "unavailable", Failure: "unsupported_os"}
	queueGapRaw := mustLocalInventoryJSON(t, queueGapReport)
	response, err = h.client.ReportJobResult(ctx, h.report(t, queueGapJob.JobID, queueGapJob.Attempt, transport.JobOutcomeExecuted, string(queueGapRaw), crypto.SHA256Hex(queueGapRaw)))
	if err != nil || !response.Accepted {
		t.Fatal("recovered source could not finish its exact read", err)
	}
	// The certificate-bound role and source, not an edited outbox row, own the read.
	otherHost := enrollAgentWithRoles(t, h.servedHarness, "local-inventory-other-host", h.serverName, []string{mtls.AgentRoleHost})
	credentials, err := otherHost.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := transport.Dial(h.channelAddr, credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	otherClient := transport.NewAgentClient(connection)
	if _, err := otherClient.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "local-inventory-other-host", Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	gateway := enrollAgentWithRoles(t, h.servedHarness, "local-inventory-gateway", h.serverName, []string{mtls.AgentRoleGateway})
	gatewayCredentials, err := gateway.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	gatewayConnection, err := transport.Dial(h.channelAddr, gatewayCredentials)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gatewayConnection.Close() }()
	if _, err := transport.NewAgentClient(gatewayConnection).Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "local-inventory-gateway", Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	gatewayID := agentRowID(h.tenant, "local-inventory-gateway")
	if code, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/windows-hosts/"+gatewayID+"/local-administrators/runs", token, "gateway-local-read", nil); code != http.StatusUnprocessableEntity {
		t.Fatal("known enrolled gateway was admitted as a Windows host", code)
	}
	diverted := queue(root, "wrong-host-native-read")
	wrong, err := otherClient.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(wrong.Jobs) != 0 {
		t.Fatal("another host claimed exact-host inventory", err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE outbox SET required_agent_id=$3 WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, "windows-local-inventory:"+diverted.ID, agentRowID(h.tenant, "local-inventory-other-host")); err != nil {
		t.Fatal(err)
	}
	wrong, err = otherClient.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{hostaccounts.InventoryDestination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(wrong.Jobs) != 0 {
		t.Fatal("rewritten SQL grant bypassed exact queued source", err)
	}
}
func mustLocalInventoryJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
