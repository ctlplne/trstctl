// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// billingReceiver is a target that verifies each push's HMAC and bearer,
// dedupes on Idempotency-Key, and can answer 503 to its first request.
type billingReceiver struct {
	srv       *httptest.Server
	mu        sync.Mutex
	requests  int
	accepted  map[string][]byte
	refused   int
	failFirst bool
}

func newBillingReceiver(t *testing.T, key, token string) *billingReceiver {
	r := &billingReceiver{accepted: map[string][]byte{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.requests++
		if req.Header.Get("Authorization") != "Bearer "+token || secretsync.VerifyWebhookSignature([]byte(key),
			req.Header.Get(secretsync.WebhookTimestampHeader), body, req.Header.Get(secretsync.WebhookSignatureHeader), time.Now(), 0) != nil {
			r.refused++
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		if r.failFirst && r.requests == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		key := req.Header.Get("Idempotency-Key")
		if _, dup := r.accepted[key]; !dup {
			r.accepted[key] = body
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// MSP-2 Done-when (core delivery): a signable period queued for a customer is
// pushed exactly once to the company its mapping names, signed with the
// target's HMAC key and carrying its bearer and stable Idempotency-Key; a
// second queue of the same period is a no-op and a 503 retry is deduplicated
// by the receiver; after the customer is remapped to another company a
// period queued for the old one is refused before any request; an unsignable
// period is held with one alert and never sent; no credential appears in any
// recorded error.
func TestServedBillingSyncPushesASignedPeriodOnceMSP2(t *testing.T) {
	ctx := context.Background()
	const hmacKey, bearer = "billing-sync-shared-key", "billing-sync-bearer"
	receiver := newBillingReceiver(t, hmacKey, bearer)
	receiver.failFirst = true
	target := config.ProviderBillingTarget{ID: "psa", Type: "json", Endpoint: receiver.srv.URL + "/usage", AllowInsecureLoopback: true,
		SigningKeyRef: writeServedCredentialFile(t, "billing-hmac", hmacKey), TokenRef: writeServedCredentialFile(t, "billing-bearer", bearer)}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.BillingSync = config.ProviderBillingSync{Targets: []config.ProviderBillingTarget{target}}
	})
	registerServedTenant(t, h, "billing sync customer")
	mapCompany := func(company string) {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'psa', $2, 'operator@example.test', now())
			ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id`, h.tenant, company); err != nil {
			t.Fatal(err)
		}
	}
	mapCompany("COMPANY-A")
	period := func(month time.Month) (time.Time, time.Time) {
		start := time.Date(2026, month, 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0)
	}
	start, end := period(time.August)
	push := projections.BillingSyncPushEvent{TargetID: "psa", PeriodStart: start, PeriodEnd: end, ExternalCompanyID: "COMPANY-A",
		EvidenceDigest: "sha256:aug", EvidenceJWS: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
		Lines: []projections.BillingUsageLine{{Meter: "certificates_current", Kind: "gauge", Value: 42}, {Meter: "agents", Kind: "gauge", Value: 3}}}
	if queued, err := h.srv.orch.QueueBillingSyncPush(ctx, h.tenant, push); err != nil || !queued {
		t.Fatalf("queue August = %v %v", queued, err)
	}
	if queued, err := h.srv.orch.QueueBillingSyncPush(ctx, h.tenant, push); err != nil || queued {
		t.Fatalf("a second queue of August = %v %v, want a no-op", queued, err)
	}
	drainUntil := func(what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for !done() {
			if err := h.srv.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not happen", what)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	status := func(start time.Time) store.BillingSyncPush {
		t.Helper()
		p, found, err := h.store.BillingSyncPushFor(ctx, h.tenant, "psa", start)
		if err != nil || !found {
			t.Fatalf("push %s: found=%v err=%v", start, found, err)
		}
		return p
	}
	drainUntil("delivery of August", func() bool { return status(start).Status == store.BillingSyncDelivered })
	receiver.mu.Lock()
	requests, accepted, refused := receiver.requests, len(receiver.accepted), receiver.refused
	body := receiver.accepted[orchestrator.BillingSyncPushKey("psa", start)]
	receiver.mu.Unlock()
	if requests != 2 || accepted != 1 || refused != 0 {
		t.Fatalf("receiver saw %d requests, accepted %d periods, refused %d; want a retried request and one period", requests, accepted, refused)
	}
	var got struct {
		CustomerID        string                         `json:"customer_id"`
		ExternalCompanyID string                         `json:"external_company_id"`
		Lines             []projections.BillingUsageLine `json:"lines"`
		EvidenceJWS       string                         `json:"evidence_jws"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.CustomerID != h.tenant || got.ExternalCompanyID != "COMPANY-A" ||
		len(got.Lines) != 2 || got.Lines[0].Value != 42 || got.EvidenceJWS != push.EvidenceJWS {
		t.Fatalf("pushed body %s (%v)", body, err)
	}
	if p := status(start); p.ResponseStatus != http.StatusOK || p.ExternalCompanyID != "COMPANY-A" {
		t.Fatalf("delivered record = %+v", p)
	}

	// Remapped to another company: a period queued for the old one is
	// refused before any request.
	sepStart, sepEnd := period(time.September)
	sep := push
	sep.PeriodStart, sep.PeriodEnd, sep.EvidenceDigest = sepStart, sepEnd, "sha256:sep"
	if queued, err := h.srv.orch.QueueBillingSyncPush(ctx, h.tenant, sep); err != nil || !queued {
		t.Fatalf("queue September = %v %v", queued, err)
	}
	mapCompany("COMPANY-B")
	before := requests
	var lastError string
	var attempts int
	var outboxStatus string
	deadline := time.Now().Add(45 * time.Second)
	for {
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		_ = h.store.SystemPool().QueryRow(ctx, `SELECT coalesce(last_error, ''), attempts, status FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
			h.tenant, orchestrator.BillingSyncPushKey("psa", sepStart)).Scan(&lastError, &attempts, &outboxStatus)
		if attempts > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("September was never attempted: status=%s attempts=%d error=%q", outboxStatus, attempts, lastError)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The outbox keeps only a sanitized error class, never the cause text.
	if outboxStatus != "pending" || lastError != "external_delivery_failed" {
		t.Fatalf("September attempt: status=%s attempts=%d error=%q", outboxStatus, attempts, lastError)
	}
	receiver.mu.Lock()
	after := receiver.requests
	receiver.mu.Unlock()
	if after != before || status(sepStart).Status != store.BillingSyncQueued {
		t.Fatalf("a remapped customer's period reached the receiver (%d→%d requests) or left queued: %+v", before, after, status(sepStart))
	}

	// An unsignable period is held with one alert and never sent.
	octStart, octEnd := period(time.October)
	held := projections.BillingSyncPushEvent{TargetID: "psa", PeriodStart: octStart, PeriodEnd: octEnd, ExternalCompanyID: "COMPANY-B",
		EvidenceDigest: "sha256:oct", Reason: "metering coverage has a gap in this period"}
	if ok, err := h.srv.orch.HoldBillingSyncPush(ctx, h.tenant, held); err != nil || !ok {
		t.Fatalf("hold October = %v %v", ok, err)
	}
	if ok, err := h.srv.orch.HoldBillingSyncPush(ctx, h.tenant, held); err != nil || ok {
		t.Fatalf("holding October again with the same reason = %v %v, want a no-op", ok, err)
	}
	if p := status(octStart); p.Status != store.BillingSyncHeld || !strings.Contains(p.Reason, "coverage") {
		t.Fatalf("held record = %+v", p)
	}
	var alerts, deliveries int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE destination = $2),
		count(*) FILTER (WHERE destination = $3 AND idempotency_key = $4)
		FROM outbox WHERE tenant_id = $1`, h.tenant, notify.DestinationBillingSync, orchestrator.DestinationBillingSync,
		orchestrator.BillingSyncPushKey("psa", octStart)).Scan(&alerts, &deliveries); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 || deliveries != 0 {
		t.Fatalf("held October: %d alerts, %d deliveries; want one alert and nothing sent", alerts, deliveries)
	}
	var leaked int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1
		AND (coalesce(last_error, '') LIKE '%' || $2 || '%' OR coalesce(last_error, '') LIKE '%' || $3 || '%')`,
		h.tenant, hmacKey, bearer).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("a recorded error carries a credential (%d rows, %v)", leaked, err)
	}
	t.Logf("MSP2_DELIVERY_OK requests=%d", after)
}
