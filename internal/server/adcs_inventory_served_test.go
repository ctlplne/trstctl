// SPDX-License-Identifier: MPL-2.0

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
		secretName = "adcs/domain-reader"
		secretRef  = "secret://adcs/domain-reader"
		secretBody = "aud35-directory-bind-canary"
	)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, secretName, []byte(secretBody))
	if err != nil {
		t.Fatalf("seal AD CS bind secret: %v", err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, secretName, sealed)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	sourceRequest := map[string]any{
		"name": "corp-adcs",
		"kind": "adcs",
		"config": map[string]any{
			"url":              "ldaps://dc01.corp.example:636",
			"configuration_dn": "CN=Configuration,DC=corp,DC=example",
			"bind_dn":          "CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example",
			"password_ref":     secretRef,
			"relay_agent_id":   relayID,
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

	report := map[string]any{
		"status": "succeeded", "directory_verified": true,
		"inventory": map[string]any{
			"templates": []map[string]any{{
				"name": "UserAuth", "display_name": "User Authentication", "schema_version": 4,
				"ekus":                  []string{"1.3.6.1.5.5.7.3.2"},
				"enrollment_principals": []string{"S-1-5-11", "S-1-5-21-111-222-333-1001"},
				"published_by":          []string{"CORP-CA"},
			}},
			"enrollment_services": []map[string]any{{"name": "CORP-CA", "dns_name": "ca01.corp.example", "templates": []string{"UserAuth"}}},
		},
		"findings": []any{},
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
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && (bytes.Contains(event.Data, []byte(secretBody)) || bytes.Contains(event.Data, []byte("nTSecurityDescriptor"))) {
			t.Fatalf("event %s persisted bind material or raw security descriptor", event.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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

	assertADCSFailedLifecycleAUD35(t, h, token, source.ID)
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
	if strings.Contains(strings.ToLower(posture.Guidance), "not yet decoded") {
		t.Fatalf("served guidance still denies the proven ACL capability: %q", posture.Guidance)
	}
}
