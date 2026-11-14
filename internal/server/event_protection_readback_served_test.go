// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A233-L4 Done-when (served): GET /api/v1/privacy/event-protection opens the
// tenant key through the shared, bounded readback. One read opens it once; a
// burst of forty concurrent reads all answer active; with every readback slot
// held by other keys the read answers unavailable within its budget instead
// of opening the key anyway (503, "busy", not the custody error), and answers
// active again once a slot frees.
func TestServedEventProtectionStatusReadbacksAreBoundedA233L4(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "5b1c33d4-6a2e-4f0b-9c55-3a0d7e2b4c11"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"bounded readbacks"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, runtime.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	token := seedServedAPIToken(t, t.Context(), st, tenant, "privacy-operator-a233l4@example.invalid", []string{string(authz.PrivacyRead), string(authz.PrivacyWrite)})
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	const endpoint = "/api/v1/privacy/event-protection"
	call := func(method, body, idempotency string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, endpoint, bytes.NewBufferString(body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		if idempotency != "" {
			request.Header.Set("Idempotency-Key", idempotency)
		}
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response
	}
	if accepted := call(http.MethodPost, `{"registration_identity":"`+registration.ID+`","retention":"1h0m0s"}`, "a233l4-enable"); accepted.Code != http.StatusAccepted {
		t.Fatalf("enable HTTP=%d body=%s", accepted.Code, accepted.Body.String())
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	active := func(response *httptest.ResponseRecorder) bool {
		var status struct {
			State string `json:"state"`
		}
		return response.Code == http.StatusOK && json.Unmarshal(response.Body.Bytes(), &status) == nil && status.State == "active"
	}

	before := runtime.readbacks.opened.Load()
	if response := call(http.MethodGet, "", ""); !active(response) {
		t.Fatalf("status HTTP=%d body=%s", response.Code, response.Body.String())
	}
	if opened := runtime.readbacks.opened.Load() - before; opened != 1 {
		t.Fatalf("one status read opened the key %d times, want 1", opened)
	}

	before = runtime.readbacks.opened.Load()
	var wg sync.WaitGroup
	results := make(chan bool, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- active(call(http.MethodGet, "", ""))
		}()
	}
	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Fatal("a concurrent status read did not answer active")
		}
	}
	burst := runtime.readbacks.opened.Load() - before
	if burst < 1 || burst > 40 {
		t.Fatalf("forty concurrent reads opened the key %d times", burst)
	}

	// Every slot held by other keys: the read is bounded, not queued forever.
	hold := make(chan struct{})
	started := make(chan struct{}, statusReadbackSlots)
	var holders sync.WaitGroup
	for i := 0; i < statusReadbackSlots; i++ {
		holders.Add(1)
		go func(i int) {
			defer holders.Done()
			_ = runtime.readbacks.readBack(context.Background(), eventprotect.KeyRef{TenantID: "holder", ID: strconv.Itoa(i)},
				func(context.Context) error { started <- struct{}{}; <-hold; return nil })
		}(i)
	}
	for i := 0; i < statusReadbackSlots; i++ {
		<-started
	}
	held := runtime.readbacks.opened.Load()
	if response := call(http.MethodGet, "", ""); response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "busy") {
		close(hold)
		t.Fatalf("with every readback slot held the status read answered HTTP=%d %s, want 503 busy", response.Code, response.Body.String())
	}
	if runtime.readbacks.opened.Load() != held {
		close(hold)
		t.Fatal("the status read opened the key while every slot was held")
	}
	close(hold)
	holders.Wait()
	if response := call(http.MethodGet, "", ""); !active(response) {
		t.Fatalf("after the slots freed the status read answered HTTP=%d", response.Code)
	}
	t.Logf("A233L4_OK burst_opens=%d of 40", burst)
}
