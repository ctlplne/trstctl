// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

const (
	auditFeedSplunkID   = "52525252-5252-4525-8525-525252525201"
	auditFeedSentinelID = "52525252-5252-4525-8525-525252525202"
)

// AUD-52 acceptance is a delivery journey, not another export-format test. The
// API records standing tenant instructions, the scheduler records exact bounded
// work before any network call, the outbox owns retries, and only a collector
// acknowledgement becomes green evidence.
func TestServedAuditFeedsDeliverSplunkAndSentinelWithRetryAUD52(t *testing.T) {
	collector := newAuditFeedCollectorAUD52(t)
	t.Setenv("TRSTCTL_AUD52_SPLUNK_TOKEN", "aud52-splunk-token")
	t.Setenv("TRSTCTL_AUD52_SENTINEL_TOKEN", "aud52-sentinel-token")

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{
			"env:TRSTCTL_AUD52_SPLUNK_TOKEN",
			"env:TRSTCTL_AUD52_SENTINEL_TOKEN",
		}
	})
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "aud52-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/52525252-5252-4525-8525-525252525200", token, "aud52-reject-url-credentials", map[string]any{
		"name": "must not persist", "provider": "splunk-hec",
		"endpoint_url": "https://collector-user:do-not-persist@collector.example.test/events",
		"token_ref":    "env:TRSTCTL_AUD52_SPLUNK_TOKEN", "interval_seconds": 300,
		"batch_size": 100, "enabled": true,
	})
	if status != http.StatusBadRequest || eventCount(t, h.log, h.tenant, projections.EventAuditFeedDestinationConfigured) != 0 {
		t.Fatalf("credential-bearing endpoint was not rejected before immutable evidence: status=%d body=%s", status, body)
	}

	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "aud52-seed-owner", map[string]any{
		"kind": "team", "name": "Audit Feed Team", "email": "audit-feed@example.test",
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed audit record: status=%d body=%s", status, body)
	}

	privateCIDR := serviceNowSinkCIDR(t, collector.URL("/"))
	putAuditFeedAUD52(t, h, token, auditFeedSplunkID, map[string]any{
		"name": "Splunk security lake", "provider": "splunk-hec",
		"endpoint_url":     collector.URL("/services/collector/event"),
		"token_ref":        "env:TRSTCTL_AUD52_SPLUNK_TOKEN",
		"interval_seconds": 300, "batch_size": 100, "enabled": true,
		"allow_private_endpoint": true, "private_egress_cidrs": []string{privateCIDR},
	})
	putAuditFeedAUD52(t, h, token, auditFeedSentinelID, map[string]any{
		"name": "Sentinel audit table", "provider": "sentinel",
		"endpoint_url":     collector.URL("/dataCollectionRules/dcr-aud52/streams/Custom-trstctl"),
		"token_ref":        "env:TRSTCTL_AUD52_SENTINEL_TOKEN",
		"interval_seconds": 300, "batch_size": 100, "enabled": true,
		"allow_private_endpoint": true, "private_egress_cidrs": []string{privateCIDR},
	})
	if got := collector.Count(); got != 0 {
		t.Fatalf("configuration performed %d inline external calls; want zero", got)
	}

	queued, err := h.srv.RunAuditFeedSchedulerOnce(t.Context())
	if err != nil || queued != 2 {
		t.Fatalf("queue due audit feeds: queued=%d err=%v", queued, err)
	}
	if got := collector.Count(); got != 0 {
		t.Fatalf("scheduler performed %d inline external calls; want zero", got)
	}
	for _, destination := range []string{orchestrator.DestinationAuditFeedSplunk, orchestrator.DestinationAuditFeedSentinel} {
		var count int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, destination).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s outbox count=%d err=%v; want one exact batch", destination, count, err)
		}
	}
	var sentinelPayloadBefore []byte
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`DELETE FROM outbox
		  WHERE tenant_id = $1 AND destination = $2
		  RETURNING payload`, h.tenant, orchestrator.DestinationAuditFeedSentinel).Scan(&sentinelPayloadBefore); err != nil {
		t.Fatalf("simulate lost Sentinel outbox transaction: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox_reconciliation_checkpoint SET reconciled_seq = 0, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatalf("rewind boot reconciliation cursor: %v", err)
	}
	healed, err := h.srv.orch.ReconcileOutbox(t.Context(), h.log)
	if err != nil || healed != 1 {
		t.Fatalf("boot reconciliation: healed=%d err=%v, want one exact missing batch", healed, err)
	}
	var sentinelPayloadAfter []byte
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, orchestrator.DestinationAuditFeedSentinel).Scan(&sentinelPayloadAfter); err != nil {
		t.Fatalf("load reconciled Sentinel payload: %v", err)
	}
	if !bytes.Equal(sentinelPayloadBefore, sentinelPayloadAfter) {
		t.Fatal("boot reconciliation changed the immutable Sentinel batch payload")
	}

	// Splunk refuses the first attempt while Sentinel accepts. That failed call
	// must remain retryable and visible; it is not permission to advance the
	// Splunk cursor or label its batch delivered.
	processed, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler)
	if err != nil || processed != 2 {
		t.Fatalf("first dispatch: processed=%d err=%v", processed, err)
	}
	feeds := getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, feeds, auditFeedSplunkID, "retrying", 0)
	assertAuditFeedStatusAUD52(t, feeds, auditFeedSentinelID, "delivered", 1)

	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox SET next_attempt_at = now() - interval '1 second'
		  WHERE tenant_id = $1 AND destination = $2 AND status = 'pending'`,
		h.tenant, orchestrator.DestinationAuditFeedSplunk); err != nil {
		t.Fatalf("make Splunk retry due: %v", err)
	}
	processed, err = h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler)
	if err != nil || processed != 1 {
		t.Fatalf("retry dispatch: processed=%d err=%v", processed, err)
	}
	feeds = getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, feeds, auditFeedSplunkID, "delivered", 1)
	assertAuditFeedStatusAUD52(t, feeds, auditFeedSentinelID, "delivered", 1)

	splunk := collector.Last("/services/collector/event")
	if splunk.Authorization != "Splunk aud52-splunk-token" || splunk.IdempotencyKey == "" || splunk.ContentType != "application/json" {
		t.Fatalf("bad Splunk delivery headers: %+v", splunk)
	}
	if !bytes.Contains(splunk.Body, []byte(`"sourcetype":"trstctl:audit"`)) ||
		!bytes.Contains(splunk.Body, []byte(`"type":"owner.created"`)) {
		t.Fatalf("Splunk did not receive production audit mapping: %s", splunk.Body)
	}
	sentinel := collector.Last("/dataCollectionRules/dcr-aud52/streams/Custom-trstctl")
	if sentinel.Authorization != "Bearer aud52-sentinel-token" || sentinel.IdempotencyKey == "" || sentinel.ContentType != "application/json" {
		t.Fatalf("bad Sentinel delivery headers: %+v", sentinel)
	}
	var sentinelRows []map[string]any
	if err := json.Unmarshal(sentinel.Body, &sentinelRows); err != nil || len(sentinelRows) == 0 {
		t.Fatalf("Sentinel body is not a non-empty JSON array: rows=%d err=%v body=%s", len(sentinelRows), err, sentinel.Body)
	}
	if sentinelRows[0]["TimeGenerated"] == nil || sentinelRows[0]["EventType"] == nil || sentinelRows[0]["BatchId"] == nil {
		t.Fatalf("Sentinel rows do not use the production mapping: %+v", sentinelRows[0])
	}
	if !h.hasEvent(t, projections.EventAuditFeedBatchQueued) || !h.hasEvent(t, projections.EventAuditFeedBatchDelivered) {
		t.Fatal("missing immutable audit-feed queue or delivery receipt evidence")
	}

	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second'
		  WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatalf("make empty schedules due: %v", err)
	}
	queued, err = h.srv.RunAuditFeedSchedulerOnce(t.Context())
	if err != nil || queued != 0 {
		t.Fatalf("empty schedule produced a batch: queued=%d err=%v", queued, err)
	}
	if !h.hasEvent(t, projections.EventAuditFeedScheduleChecked) {
		t.Fatal("empty schedule did not advance through immutable check evidence")
	}
	queued, err = h.srv.RunAuditFeedSchedulerOnce(t.Context())
	if err != nil || queued != 0 {
		t.Fatalf("schedule hot-looped after empty check: queued=%d err=%v", queued, err)
	}
	if got := collector.CountPath("/services/collector/event"); got != 2 {
		t.Fatalf("Splunk attempts=%d, want one refusal plus one exact retry", got)
	}

	status, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "aud52-terminal-seed", map[string]any{
		"kind": "team", "name": "Audit Feed Terminal Failure Team", "email": "audit-feed-terminal@example.test",
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed terminal audit record: status=%d body=%s", status, body)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second'
		  WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatalf("make terminal schedules due: %v", err)
	}
	queued, err = h.srv.RunAuditFeedSchedulerOnce(t.Context())
	if err != nil || queued != 2 {
		t.Fatalf("queue terminal audit batches: queued=%d err=%v", queued, err)
	}
	collector.SetSentinelFailure(true)
	terminalWorker := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
	processed, err = terminalWorker.DispatchScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{
		IncludePrefixes: []string{orchestrator.DestinationAuditFeedSentinel},
	})
	if err != nil || processed != 1 {
		t.Fatalf("terminal Sentinel dispatch: processed=%d err=%v", processed, err)
	}
	feeds = getAuditFeedsAUD52(t, h, token)
	assertAuditFeedFailureAUD52(t, feeds, auditFeedSentinelID, "collector_http_error")
	if !h.hasEvent(t, projections.EventAuditFeedBatchFailed) {
		t.Fatal("retry exhaustion did not append immutable audit-feed failure evidence")
	}
	if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold rebuild audit-feed projections from immutable history: %v", err)
	}
	feeds = getAuditFeedsAUD52(t, h, token)
	assertAuditFeedFailureAUD52(t, feeds, auditFeedSentinelID, "collector_http_error")
	var retainedErrors string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT COALESCE(string_agg(last_error, ' '), '') FROM outbox
		  WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, orchestrator.DestinationAuditFeedSentinel).Scan(&retainedErrors); err != nil {
		t.Fatalf("read retained Sentinel errors: %v", err)
	}
	if bytes.Contains([]byte(retainedErrors), []byte("collector-secret-echo-must-not-persist")) {
		t.Fatalf("collector response body leaked into durable error posture: %q", retainedErrors)
	}

	tenantB := "52525252-5252-4525-8525-525252525299"
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`INSERT INTO tenants (tenant_id, name) VALUES ($1, 'AUD-52 neighbor')`, tenantB); err != nil {
		t.Fatalf("register neighbor tenant: %v", err)
	}
	neighborToken := seedServedAPIToken(t, t.Context(), h.store, tenantB, "aud52-neighbor", []string{string(authz.AuditRead)})
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/feeds", neighborToken, "", nil)
	if status != http.StatusOK {
		t.Fatalf("neighbor list: status=%d body=%s", status, body)
	}
	var neighbor auditFeedListAUD52
	if err := json.Unmarshal(body, &neighbor); err != nil || len(neighbor.Items) != 0 {
		t.Fatalf("neighbor saw another tenant's audit feeds: items=%+v err=%v", neighbor.Items, err)
	}
}

func putAuditFeedAUD52(t *testing.T, h *servedHarness, token, id string, body map[string]any) {
	t.Helper()
	status, response := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/"+id, token, "aud52-config-"+id, body)
	if status != http.StatusOK {
		t.Fatalf("configure audit feed %s: status=%d body=%s", id, status, response)
	}
}

type auditFeedListAUD52 struct {
	Items []struct {
		ID                    string `json:"id"`
		Status                string `json:"status"`
		LastDeliveredSequence uint64 `json:"last_delivered_sequence"`
		LagRecords            int    `json:"lag_records"`
		LastErrorCode         string `json:"last_error_code"`
	} `json:"items"`
}

func assertAuditFeedFailureAUD52(t *testing.T, list auditFeedListAUD52, id, errorCode string) {
	t.Helper()
	for _, item := range list.Items {
		if item.ID != id {
			continue
		}
		if item.Status != "failed" || item.LagRecords < 1 || item.LastErrorCode != errorCode {
			t.Fatalf("feed %s terminal posture = status %q lag %d error %q", id, item.Status, item.LagRecords, item.LastErrorCode)
		}
		return
	}
	t.Fatalf("feed %s absent from list: %+v", id, list.Items)
}

func getAuditFeedsAUD52(t *testing.T, h *servedHarness, token string) auditFeedListAUD52 {
	t.Helper()
	status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/feeds", token, "", nil)
	if status != http.StatusOK {
		t.Fatalf("list audit feeds: status=%d body=%s", status, body)
	}
	var out auditFeedListAUD52
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode audit feeds: %v body=%s", err, body)
	}
	return out
}

func assertAuditFeedStatusAUD52(t *testing.T, list auditFeedListAUD52, id, status string, minSequence uint64) {
	t.Helper()
	for _, item := range list.Items {
		if item.ID != id {
			continue
		}
		if item.Status != status || item.LastDeliveredSequence < minSequence {
			t.Fatalf("feed %s = status %q sequence %d, want %q sequence >= %d", id, item.Status, item.LastDeliveredSequence, status, minSequence)
		}
		return
	}
	t.Fatalf("feed %s absent from list: %+v", id, list.Items)
}

type auditFeedCollectorRecordAUD52 struct {
	Path           string
	Authorization  string
	IdempotencyKey string
	ContentType    string
	Body           []byte
}

type auditFeedCollectorAUD52 struct {
	server       *httptest.Server
	mu           sync.Mutex
	records      []auditFeedCollectorRecordAUD52
	splunkFailed bool
	sentinelFail bool
}

func newAuditFeedCollectorAUD52(t *testing.T) *auditFeedCollectorAUD52 {
	t.Helper()
	c := &auditFeedCollectorAUD52{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		rec := auditFeedCollectorRecordAUD52{
			Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
			IdempotencyKey: r.Header.Get("X-Trstctl-Idempotency-Key"),
			ContentType:    r.Header.Get("Content-Type"), Body: append([]byte(nil), raw...),
		}
		c.mu.Lock()
		c.records = append(c.records, rec)
		if r.URL.Path == "/services/collector/event" && !c.splunkFailed {
			c.splunkFailed = true
			c.mu.Unlock()
			http.Error(w, "collector temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if strings.Contains(r.URL.Path, "/dataCollectionRules/") && c.sentinelFail {
			c.mu.Unlock()
			http.Error(w, "collector-secret-echo-must-not-persist", http.StatusServiceUnavailable)
			return
		}
		c.mu.Unlock()
		w.Header().Set("X-Collector-Request-ID", "collector-aud52")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *auditFeedCollectorAUD52) URL(path string) string { return c.server.URL + path }

func (c *auditFeedCollectorAUD52) SetSentinelFailure(fail bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sentinelFail = fail
}

func (c *auditFeedCollectorAUD52) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.records)
}

func (c *auditFeedCollectorAUD52) CountPath(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, record := range c.records {
		if record.Path == path {
			n++
		}
	}
	return n
}

func (c *auditFeedCollectorAUD52) Last(path string) auditFeedCollectorRecordAUD52 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.records) - 1; i >= 0; i-- {
		if c.records[i].Path == path {
			return c.records[i]
		}
	}
	return auditFeedCollectorRecordAUD52{}
}

// Keep a direct reference to the retry timing contract in this served test: an
// outbox error is durable posture, never a scheduler sleep or an inline retry.
