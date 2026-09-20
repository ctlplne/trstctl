// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedADCSSourceSchedulesRelayAndProjectsACLPostureAUD35 proves the
// shipped producer-to-relay-to-projector journey. It deliberately starts from
// the authenticated source API instead of seeding an outbox row: the missing
// producer was the defect.
func TestServedADCSSourceSchedulesRelayAndProjectsACLPostureAUD35(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindADCSInventory)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "aud35-test", Status: "active",
	}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	relayID := agentRowID(h.tenant, h.agent)
	const (
		secretName = "adcs/domain-reader"          // #nosec G101 -- this is a logical fixture name, not secret material (CWE-798).
		secretRef  = "secret://adcs/domain-reader" // #nosec G101 -- this is a non-secret reference, not secret material (CWE-798).
		secretBody = "aud35-directory-bind-canary"
	)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, secretName, []byte(secretBody))
	if err != nil {
		t.Fatalf("seal AD CS bind secret: %v", err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, secretName, sealed)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "notifications:read")

	sourceRequest := map[string]any{
		"name": "corp-adcs",
		"kind": "adcs",
		"config": map[string]any{
			"url":              "ldaps://dc01.corp.example:636",
			"configuration_dn": "CN=Configuration,DC=corp,DC=example",
			"bind_dn":          "CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example",
			"password_ref":     secretRef,
			"relay_agent_id":   relayID,
			"enrollment_endpoints": []map[string]any{
				{"enrollment_service": "CORP-CA", "kind": "web_enrollment", "url": "https://ca01.corp.example/certsrv/"},
				{"enrollment_service": "CORP-CA", "kind": "ndes_admin", "url": "http://ca01.corp.example/certsrv/mscep_admin/"},
			},
		},
	}
	var sourceBodies [2][]byte
	var sourceCodes [2]int
	var wg sync.WaitGroup
	for i := range sourceBodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sourceCodes[i], sourceBodies[i] = secretsReqKey(t, h.servedHarness, http.MethodPost,
				"/api/v1/discovery/sources", token, "aud35-source", sourceRequest)
		}(i)
	}
	wg.Wait()
	if sourceCodes[0] != http.StatusCreated || sourceCodes[1] != http.StatusCreated ||
		!bytes.Equal(sourceBodies[0], sourceBodies[1]) {
		t.Fatalf("concurrent source replay = (%d,%s) (%d,%s)", sourceCodes[0], sourceBodies[0], sourceCodes[1], sourceBodies[1])
	}
	if bytes.Contains(sourceBodies[0], []byte(secretBody)) {
		t.Fatal("source response persisted the bind credential instead of its reference")
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(sourceBodies[0], &source); err != nil || source.ID == "" {
		t.Fatalf("decode source: id=%q err=%v", source.ID, err)
	}

	scheduleRequest := map[string]any{
		"source_id": source.ID, "name": "every-hour", "interval_seconds": 3600,
	}
	firstCode, firstBody := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/discovery/schedules", token, "aud35-schedule", scheduleRequest)
	secondCode, secondBody := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/discovery/schedules", token, "aud35-schedule", scheduleRequest)
	if firstCode != http.StatusCreated || secondCode != http.StatusCreated || !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("schedule replay = (%d,%s) (%d,%s)", firstCode, firstBody, secondCode, secondBody)
	}

	// Two leader loops racing the same due schedule still create one immutable
	// run and one outbox effect. This is the restart/concurrency edge that a
	// read-then-queue scheduler otherwise loses.
	queued := make(chan int, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			n, queueErr := h.srv.RunDiscoverySchedulerOnce(ctx)
			queued <- n
			errs <- queueErr
		}()
	}
	queuedTotal := 0
	for range 2 {
		queuedTotal += <-queued
		if err := <-errs; err != nil {
			t.Fatalf("scheduler race: %v", err)
		}
	}
	if queuedTotal != 1 {
		t.Fatalf("concurrent scheduler queued %d runs, want exactly one", queuedTotal)
	}
	runs, err := h.store.ListDiscoveryRunsPage(ctx, h.tenant, store.ZeroUUID, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("scheduled runs = %d err=%v, want one", len(runs), err)
	}
	run := runs[0]
	if run.SourceID != source.ID || run.Status != "queued" || run.Execution != "relay" ||
		run.RequiredAgentRole != mtls.AgentRoleNetwork || run.RequiredAgentID != relayID {
		t.Fatalf("AD CS run lost source/relay lifecycle binding: %+v", run)
	}

	var destination, role, requiredAgent string
	var payload []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT destination, payload, required_agent_role,
		       COALESCE(required_agent_id::text, '')
		  FROM outbox
		 WHERE tenant_id = $1 AND destination = 'adcs.inventory'`, h.tenant).
			Scan(&destination, &payload, &role, &requiredAgent)
	}); err != nil {
		t.Fatalf("read produced AD CS job: %v", err)
	}
	var intent struct {
		ID                string `json:"id"`
		SourceID          string `json:"source_id"`
		URL               string `json:"url"`
		ConfigurationDN   string `json:"configuration_dn"`
		BindDN            string `json:"bind_dn"`
		PasswordRef       string `json:"password_ref"`
		RequiredAgentRole string `json:"required_agent_role"`
		RequiredAgentID   string `json:"required_agent_id"`
	}
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	if destination != relay.KindADCSInventory || role != mtls.AgentRoleNetwork || requiredAgent != relayID ||
		intent.ID != run.ID || intent.SourceID != source.ID || intent.URL == "" || intent.ConfigurationDN == "" ||
		intent.BindDN == "" || intent.PasswordRef != secretRef || intent.RequiredAgentRole != role || intent.RequiredAgentID != relayID {
		t.Fatalf("produced AD CS intent is incomplete: destination=%q role=%q agent=%q intent=%+v", destination, role, requiredAgent, intent)
	}
	if bytes.Contains(payload, []byte(secretBody)) {
		t.Fatal("AD CS outbox payload contains the bind credential")
	}

	// Simulate the append-before-SQL crash edge: the immutable event survived,
	// while its outbox row did not. Boot reconciliation must restore the exact
	// AD CS destination, selected relay, and reference-only command bytes.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND destination = 'adcs.inventory'`, h.tenant)
		return err
	}); err != nil {
		t.Fatalf("remove produced AD CS job: %v", err)
	}
	healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log)
	if err != nil || healed != 1 {
		t.Fatalf("reconcile lost AD CS command: healed=%d err=%v", healed, err)
	}
	var healedPayload []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'adcs.inventory'`, h.tenant).Scan(&healedPayload)
	}); err != nil {
		t.Fatalf("read healed AD CS job: %v", err)
	}
	if !bytes.Equal(healedPayload, payload) {
		t.Fatalf("healed AD CS command changed: got %s want %s", healedPayload, payload)
	}

	// The control-plane worker recognizes this as estate-owned and performs no
	// directory I/O. A host role cannot claim it; the selected network relay can.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("control-plane drain: %v", err)
	}
	wrongRole, err := h.store.ClaimAgentJobs(ctx, h.tenant, relayID,
		[]string{relay.KindADCSInventory}, []string{mtls.AgentRoleHost}, 1, time.Minute, time.Now().UTC())
	if err != nil || len(wrongRole) != 0 {
		t.Fatalf("host claimed AD CS job: jobs=%d err=%v", len(wrongRole), err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindADCSInventory}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("network relay claim: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	if job.Kind != relay.KindADCSInventory || !bytes.Equal(job.Payload, payload) {
		t.Fatalf("claimed job = kind %q payload %s", job.Kind, job.Payload)
	}
	assertADCSRunningLifecycleAUD35(t, h, token, run.ID, source.ID)
	redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
	if err != nil || len(redeemed.Items) != 1 || redeemed.Items[0].Name != secretRef ||
		!bytes.Equal(redeemed.Items[0].Value, []byte(secretBody)) {
		t.Fatalf("single-use AD CS redemption = %+v err=%v", redeemed, err)
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); err == nil {
		t.Fatal("AD CS bind credential redeemed twice for one claim")
	}

	inventory := aud37Inventory([]adcsdiscovery.Template{{
		Name: "UserAuth", DisplayName: "User Authentication", SchemaVersion: 4,
		EKUs:                 []string{adcsdiscovery.EKUClientAuth},
		EnrollmentPrincipals: []string{"S-1-5-11", "S-1-5-21-111-222-333-1001"},
		PublishedBy:          []string{"CORP-CA"},
	}})
	report := adcsdiscovery.InventoryReport{
		Status: "succeeded", DirectoryVerified: true, Inventory: inventory,
		Findings: adcsdiscovery.Findings(inventory),
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	requests := []*transport.ReportJobResultRequest{
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), "sha256:aud35-directory-read"),
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), "sha256:aud35-directory-read"),
	}
	accepted := make(chan bool, 2)
	reportErrs := make(chan error, 2)
	for _, request := range requests {
		go func(request *transport.ReportJobResultRequest) {
			response, reportErr := h.client.ReportJobResult(ctx, request)
			accepted <- response != nil && response.Accepted
			reportErrs <- reportErr
		}(request)
	}
	acceptedCount := 0
	for range requests {
		if <-accepted {
			acceptedCount++
		}
		if err := <-reportErrs; err != nil {
			t.Fatalf("signed AD CS report: %v", err)
		}
	}
	if acceptedCount != 1 {
		t.Fatalf("concurrent signed AD CS reports accepted=%d, want one", acceptedCount)
	}

	assertADCSServedProjectionAUD35(t, h, token, source.ID, run.ID)
	if !h.hasEvent(t, projections.EventDiscoveryRunStarted) ||
		!h.hasEvent(t, projections.EventDiscoveryRunCompleted) ||
		!h.hasEvent(t, "adcs.template.inventory.observed") {
		t.Fatal("AD CS receipt did not append lifecycle and posture events")
	}
	var sawCompletePostureEvent bool
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && (bytes.Contains(event.Data, []byte(secretBody)) || bytes.Contains(event.Data, []byte("nTSecurityDescriptor"))) {
			t.Fatalf("event %s persisted bind material or raw security descriptor", event.Type)
		}
		if event.TenantID == h.tenant && event.Type == projections.EventADCSInventoryObserved {
			if event.SchemaVersion != adcsdiscovery.InventoryEventSchemaVersion || !bytes.Contains(event.Data, []byte(`"enrollment_services"`)) {
				t.Fatalf("AD CS observation is not complete v%d evidence: schema=%d data=%s", adcsdiscovery.InventoryEventSchemaVersion, event.SchemaVersion, event.Data)
			}
			sawCompletePostureEvent = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !sawCompletePostureEvent {
		t.Fatal("AD CS receipt emitted no complete posture event")
	}

	// Cold replay is the authority. If posture existed only because the warm
	// callback wrote SQL, this rebuild would erase it.
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild AD CS projection: %v", err)
	}
	assertADCSServedProjectionAUD35(t, h, token, source.ID, run.ID)

	otherTenant := uuid.NewString()
	otherToken := seedScopedToken(t, h.store, otherTenant, "discovery:read")
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", otherToken, nil)
	if code != http.StatusOK || bytes.Contains(body, []byte("UserAuth")) || bytes.Contains(body, []byte(source.ID)) {
		t.Fatalf("cross-tenant AD CS posture = %d %s", code, body)
	}

	assertADCSDriftHistoryAndAlertAUD36(t, h, token, otherToken, source.ID)

	assertADCSFailedLifecycleAUD35(t, h, token, source.ID)
}

// assertADCSDriftHistoryAndAlertAUD36 performs the one-sweep journey missing in
// the audit: queue the next real source run, let the selected relay report one
// dangerous semantic/ACL change, then read the immutable before/after record and
// its notification from the public surfaces. Replaying the signed receipt must
// not duplicate either effect.
func assertADCSDriftHistoryAndAlertAUD36(t *testing.T, h *roleHarness, token, otherToken, sourceID string) {
	t.Helper()
	ctx := context.Background()
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs",
		token, "aud36-worsened-run", map[string]any{"source_id": sourceID})
	if code != http.StatusCreated {
		t.Fatalf("queue AUD-36 drift sweep: %d %s", code, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain AUD-36 drift sweep: %v", err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindADCSInventory}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim AUD-36 drift sweep: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	var driftIntent struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(job.Payload, &driftIntent); err != nil || driftIntent.ID == "" {
		t.Fatalf("decode AUD-36 drift command: id=%q err=%v", driftIntent.ID, err)
	}
	inventory := aud37Inventory([]adcsdiscovery.Template{{
		Name: "UserAuth", DisplayName: "User Authentication", SchemaVersion: 4,
		EnrolleeSuppliesSubject: true, EKUs: []string{adcsdiscovery.EKUClientAuth},
		EnrollmentPrincipals: []string{"S-1-5-11", "S-1-5-21-111-222-333-1001", "S-1-5-21-111-222-333-2002"},
		PublishedBy:          []string{"CORP-CA"},
	}})
	report := adcsdiscovery.InventoryReport{Status: "succeeded", DirectoryVerified: true, Inventory: inventory, Findings: adcsdiscovery.Findings(inventory)}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	receipt := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), "sha256:aud36-directory-drift")
	response, err := h.client.ReportJobResult(ctx, receipt)
	if err != nil || response == nil || !response.Accepted {
		t.Fatalf("report AUD-36 drift sweep: response=%+v err=%v", response, err)
	}
	response, err = h.client.ReportJobResult(ctx, receipt)
	if err != nil || response == nil || response.Accepted {
		t.Fatalf("replay AUD-36 drift receipt: response=%+v err=%v", response, err)
	}

	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs/drift", token, nil)
	if code != http.StatusOK {
		t.Fatalf("get AUD-36 drift history: %d %s", code, body)
	}
	var history struct {
		Items []struct {
			ID         string `json:"id"`
			RunID      string `json:"run_id"`
			SourceID   string `json:"source_id"`
			Domain     string `json:"domain"`
			AgentID    string `json:"agent_id"`
			ObservedBy string `json:"observed_by"`
			ObservedAt string `json:"observed_at"`
			Direction  string `json:"direction"`
			Changes    []struct {
				Template  string `json:"template"`
				Direction string `json:"direction"`
				Attribute string `json:"attribute"`
				Before    string `json:"before"`
				After     string `json:"after"`
			} `json:"changes"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &history); err != nil || len(history.Items) != 1 {
		t.Fatalf("decode AUD-36 drift history: items=%+v err=%v body=%s", history.Items, err, body)
	}
	item := history.Items[0]
	if item.ID == "" || item.RunID != driftIntent.ID || item.SourceID != sourceID ||
		item.Domain != "CORP-CA" || item.AgentID != agentRowID(h.tenant, h.agent) ||
		item.ObservedBy != h.agent || item.ObservedAt == "" || item.Direction != "worse" {
		t.Fatalf("AUD-36 drift authority/provenance = %+v", item)
	}
	var sawACL bool
	for _, change := range item.Changes {
		if change.Template == "UserAuth" && change.Direction == "worse" &&
			change.Attribute == "nTSecurityDescriptor enrollment trustees" &&
			change.Before == "S-1-5-11, S-1-5-21-111-222-333-1001" &&
			strings.Contains(change.After, "S-1-5-21-111-222-333-2002") {
			sawACL = true
		}
	}
	if !sawACL || bytes.Contains(body, []byte("security_descriptor")) {
		t.Fatalf("AUD-36 history lost ACL before/after or exposed raw descriptor: %s", body)
	}

	code, otherBody := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs/drift", otherToken, nil)
	if code != http.StatusOK || bytes.Contains(otherBody, []byte(item.ID)) || bytes.Contains(otherBody, []byte("UserAuth")) {
		t.Fatalf("cross-tenant AUD-36 history = %d %s", code, otherBody)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/notifications", token, nil)
	if code != http.StatusOK {
		t.Fatalf("get AUD-36 notification inbox: %d %s", code, body)
	}
	var inbox struct {
		Items []struct {
			Kind        string `json:"kind"`
			Destination string `json:"destination"`
			Subject     string `json:"subject"`
			Detail      string `json:"detail"`
			Severity    string `json:"severity"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &inbox); err != nil {
		t.Fatalf("decode AUD-36 notification inbox: %v (%s)", err, body)
	}
	alerts := 0
	for _, notification := range inbox.Items {
		if notification.Kind != "adcs.template_drift" {
			continue
		}
		alerts++
		if notification.Destination != "notification.drift" || notification.Severity != "critical" ||
			!strings.Contains(notification.Subject, "UserAuth") ||
			!strings.Contains(notification.Detail, "S-1-5-21-111-222-333-2002") {
			t.Fatalf("AUD-36 inbox alert lost drift facts: %+v", notification)
		}
	}
	if alerts != 1 {
		t.Fatalf("AUD-36 inbox drift alerts = %d, want exactly one after receipt replay (%s)", alerts, body)
	}

	// A neutral EKU edit that preserves client authentication and a real hardening
	// sweep stay readable but do not page. The identical sweep after them produces
	// no fourth history row.
	neutralInventory := aud37Inventory([]adcsdiscovery.Template{{
		Name: "UserAuth", DisplayName: "Renamed User Authentication", SchemaVersion: 4,
		EnrolleeSuppliesSubject: true,
		EKUs:                    []string{"1.3.6.1.5.5.7.3.1", adcsdiscovery.EKUClientAuth},
		EnrollmentPrincipals:    []string{"S-1-5-11", "S-1-5-21-111-222-333-1001", "S-1-5-21-111-222-333-2002"},
		PublishedBy:             []string{"CORP-CA"},
	}})
	neutralReport := adcsdiscovery.InventoryReport{Status: "succeeded", DirectoryVerified: true, Inventory: neutralInventory, Findings: adcsdiscovery.Findings(neutralInventory)}
	runADCSSweepAUD36(t, h, token, sourceID, "aud36-neutral-run", "sha256:aud36-directory-neutral", neutralReport)
	improvedInventory := aud37Inventory([]adcsdiscovery.Template{{
		Name: "UserAuth", DisplayName: "Renamed User Authentication", SchemaVersion: 4,
		RequiresManagerApproval: true,
		EKUs:                    []string{"1.3.6.1.5.5.7.3.1", adcsdiscovery.EKUClientAuth},
		EnrollmentPrincipals:    []string{"S-1-5-11", "S-1-5-21-111-222-333-1001"},
		PublishedBy:             []string{"CORP-CA"},
	}})
	improvedReport := adcsdiscovery.InventoryReport{Status: "succeeded", DirectoryVerified: true, Inventory: improvedInventory, Findings: adcsdiscovery.Findings(improvedInventory)}
	runADCSSweepAUD36(t, h, token, sourceID, "aud36-improved-run", "sha256:aud36-directory-hardened", improvedReport)
	runADCSSweepAUD36(t, h, token, sourceID, "aud36-unchanged-run", "sha256:aud36-directory-unchanged", improvedReport)
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs/drift", token, nil)
	var finalHistory struct {
		Items []struct {
			ID        string `json:"id"`
			Direction string `json:"direction"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &finalHistory) != nil || len(finalHistory.Items) != 3 ||
		finalHistory.Items[0].Direction != "better" || finalHistory.Items[1].Direction != "neutral" ||
		finalHistory.Items[2].Direction != "worse" {
		t.Fatalf("AUD-36 neutral/better/unchanged history = status %d items %+v body %s", code, finalHistory.Items, body)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/notifications", token, nil)
	if code != http.StatusOK || strings.Count(string(body), `"kind":"adcs.template_drift"`) != 1 {
		t.Fatalf("AUD-36 better/unchanged sweeps paged or removed the alert: %d %s", code, body)
	}

	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild AUD-36 drift history: %v", err)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs/drift", token, nil)
	var rebuiltHistory struct {
		Items []struct {
			ID        string `json:"id"`
			Direction string `json:"direction"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &rebuiltHistory) != nil || len(rebuiltHistory.Items) != 3 ||
		rebuiltHistory.Items[0].Direction != "better" || rebuiltHistory.Items[1].Direction != "neutral" ||
		rebuiltHistory.Items[2].ID != item.ID || rebuiltHistory.Items[2].Direction != "worse" {
		t.Fatalf("rebuilt AUD-36 drift history did not converge: %d %s", code, body)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/notifications", token, nil)
	if code != http.StatusOK || strings.Count(string(body), `"kind":"adcs.template_drift"`) != 1 {
		t.Fatalf("AUD-36 rebuild duplicated or removed the drift alert: %d %s", code, body)
	}
}

func runADCSSweepAUD36(
	t *testing.T,
	h *roleHarness,
	token, sourceID, requestKey, digest string,
	report adcsdiscovery.InventoryReport,
) {
	t.Helper()
	ctx := context.Background()
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs",
		token, requestKey, map[string]any{"source_id": sourceID})
	if code != http.StatusCreated {
		t.Fatalf("queue %s AD CS sweep: %d %s", requestKey, code, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain %s AD CS sweep: %v", requestKey, err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindADCSInventory}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim %s AD CS sweep: jobs=%d err=%v", requestKey, len(claimed.Jobs), err)
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	job := claimed.Jobs[0]
	response, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, string(reportJSON), digest))
	if err != nil || response == nil || !response.Accepted {
		t.Fatalf("report %s AD CS sweep: response=%+v err=%v", requestKey, response, err)
	}
}

func aud37Inventory(templates []adcsdiscovery.Template) adcsdiscovery.Inventory {
	return adcsdiscovery.Inventory{
		Templates: templates,
		EnrollmentServices: []adcsdiscovery.EnrollmentService{{
			Name: "CORP-CA", DNSName: "ca01.corp.example", Templates: []string{"UserAuth"},
			AgentRestrictions: adcsdiscovery.EnrollmentAgentRestrictions{State: adcsdiscovery.EvidenceEnabled, Source: "windows_certutil"},
			Endpoints: []adcsdiscovery.EnrollmentEndpoint{
				{Kind: adcsdiscovery.EndpointNDESAdmin, URL: "http://ca01.corp.example/certsrv/mscep_admin/", State: adcsdiscovery.EndpointAnonymousAccess, HTTPStatus: 200, ExtendedProtection: adcsdiscovery.EvidenceUnobserved},
				{Kind: adcsdiscovery.EndpointWebEnrollment, URL: "https://ca01.corp.example/certsrv/", State: adcsdiscovery.EndpointAuthenticationNeeded, HTTPStatus: 401, Authentication: []string{"Negotiate"}, TLSVerified: true, ExtendedProtection: adcsdiscovery.EvidenceEnabled},
			},
		}},
	}
}

func assertADCSRunningLifecycleAUD35(t *testing.T, h *roleHarness, token, runID, sourceID string) {
	t.Helper()
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+runID, token, nil)
	var run struct {
		Status string `json:"status"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &run) != nil || run.Status != "running" {
		t.Fatalf("claimed AD CS run lifecycle = status %d run %+v body %s", code, run, body)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, nil)
	var posture struct {
		Sources []struct {
			SourceID      string `json:"source_id"`
			LastRunID     string `json:"last_run_id"`
			LastRunStatus string `json:"last_run_status"`
		} `json:"sources"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &posture) != nil || len(posture.Sources) != 1 ||
		posture.Sources[0].SourceID != sourceID || posture.Sources[0].LastRunID != runID ||
		posture.Sources[0].LastRunStatus != "running" {
		t.Fatalf("claimed AD CS posture lifecycle = status %d sources %+v body %s", code, posture.Sources, body)
	}
}

func assertADCSFailedLifecycleAUD35(t *testing.T, h *roleHarness, token, sourceID string) {
	t.Helper()
	ctx := context.Background()
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs",
		token, "aud35-failed-run", map[string]any{"source_id": sourceID})
	if code != http.StatusCreated {
		t.Fatalf("queue failed-path AD CS run: %d %s", code, body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.ID == "" {
		t.Fatalf("decode failed-path AD CS run: id=%q err=%v (%s)", queued.ID, err, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain failed-path AD CS run: %v", err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindADCSInventory}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim failed-path AD CS run: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	report := `{"status":"failed","error_code":"directory_authentication_failed","inventory":{"templates":[],"enrollment_services":[]},"findings":[],"directory_verified":false}`
	response, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, report, "sha256:aud35-directory-auth-failed"))
	if err != nil || response == nil || !response.Accepted {
		t.Fatalf("report failed-path AD CS run: response=%+v err=%v", response, err)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, token, nil)
	var run struct {
		Status string `json:"status"`
		Failed int    `json:"failed"`
		Error  string `json:"error"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &run) != nil || run.Status != "failed" ||
		run.Failed != 1 || run.Error != "directory_authentication_failed" {
		t.Fatalf("failed-path AD CS lifecycle = status %d run %+v body %s", code, run, body)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, nil)
	var posture struct {
		Sources []struct {
			LastRunID     string `json:"last_run_id"`
			LastRunStatus string `json:"last_run_status"`
			LastRunError  string `json:"last_run_error"`
		} `json:"sources"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &posture) != nil || len(posture.Sources) != 1 ||
		posture.Sources[0].LastRunID != queued.ID || posture.Sources[0].LastRunStatus != "failed" ||
		posture.Sources[0].LastRunError != "directory_authentication_failed" {
		t.Fatalf("failed-path AD CS posture lifecycle = status %d %+v body %s", code, posture.Sources, body)
	}
}

func assertADCSServedProjectionAUD35(t *testing.T, h *roleHarness, token, sourceID, runID string) {
	t.Helper()
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+runID, token, nil)
	if code != http.StatusOK {
		t.Fatalf("get AD CS run: %d %s", code, body)
	}
	var run struct {
		Status            string `json:"status"`
		ExecutedByAgentID string `json:"executed_by_agent_id"`
		Discovered        int    `json:"discovered"`
	}
	if err := json.Unmarshal(body, &run); err != nil || run.Status != "succeeded" ||
		run.ExecutedByAgentID != agentRowID(h.tenant, h.agent) || run.Discovered != 1 {
		t.Fatalf("served AD CS run = %+v err=%v body=%s", run, err, body)
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/posture/adcs", token, nil)
	if code != http.StatusOK {
		t.Fatalf("get AD CS posture: %d %s", code, body)
	}
	var posture struct {
		Observed bool `json:"observed"`
		Sources  []struct {
			SourceID      string `json:"source_id"`
			LastRunID     string `json:"last_run_id"`
			LastRunStatus string `json:"last_run_status"`
		} `json:"sources"`
		Templates []struct {
			Template             string   `json:"template"`
			EnrollmentPrincipals []string `json:"enrollment_principals"`
		} `json:"templates"`
		EnrollmentServices []struct {
			Service                string `json:"service"`
			AgentRestrictionState  string `json:"agent_restriction_state"`
			AgentRestrictionSource string `json:"agent_restriction_source"`
			Endpoints              []struct {
				Kind        string `json:"kind"`
				State       string `json:"state"`
				TLSVerified bool   `json:"tls_verified"`
			} `json:"endpoints"`
			Findings []struct {
				ID string `json:"id"`
			} `json:"findings"`
		} `json:"enrollment_services"`
		Guidance string `json:"guidance"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatalf("decode AD CS posture: %v (%s)", err, body)
	}
	if !posture.Observed || len(posture.Sources) != 1 || posture.Sources[0].SourceID != sourceID ||
		posture.Sources[0].LastRunID != runID || posture.Sources[0].LastRunStatus != "succeeded" {
		t.Fatalf("AD CS source lifecycle = %+v", posture.Sources)
	}
	wantPrincipals := []string{"S-1-5-11", "S-1-5-21-111-222-333-1001"}
	if len(posture.Templates) != 1 || posture.Templates[0].Template != "UserAuth" ||
		!slices.Equal(posture.Templates[0].EnrollmentPrincipals, wantPrincipals) {
		t.Fatalf("served enrollment principals = %+v, want %v", posture.Templates, wantPrincipals)
	}
	if len(posture.EnrollmentServices) != 1 || posture.EnrollmentServices[0].Service != "CORP-CA" ||
		posture.EnrollmentServices[0].AgentRestrictionState != "enabled" ||
		posture.EnrollmentServices[0].AgentRestrictionSource != "windows_certutil" ||
		len(posture.EnrollmentServices[0].Endpoints) != 2 || len(posture.EnrollmentServices[0].Findings) != 2 {
		t.Fatalf("served enrollment-service evidence = %+v", posture.EnrollmentServices)
	}
	if strings.Contains(strings.ToLower(posture.Guidance), "not yet decoded") {
		t.Fatalf("served guidance still denies the proven ACL capability: %q", posture.Guidance)
	}
}
