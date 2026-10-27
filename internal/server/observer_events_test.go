// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

// A180: the observer's answer decides the outbox outcome — 2xx delivered, a
// 4xx refusal (other than 408 and 429) final, anything else retried — and an
// unreadable row is final without a request.
func TestObserverEventDeliveryOutcomes(t *testing.T) {
	status := http.StatusAccepted
	requests := 0
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(status)
	}))
	t.Cleanup(sink.Close)
	d := &observerEventDelivery{client: sink.Client(), skipEndpointValidation: true}
	// A nil store reaches the network only through a stubbed observer lookup,
	// so these cases cover the response classification alone.
	post := func(code int) error {
		status = code
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, sink.URL, nil)
		resp, err := d.client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return classifyObserverResponse(resp.StatusCode)
	}
	for code, final := range map[int]bool{http.StatusAccepted: false, http.StatusBadRequest: true, http.StatusRequestTimeout: false,
		http.StatusTooManyRequests: false, http.StatusServiceUnavailable: false} {
		err := post(code)
		switch {
		case code/100 == 2 && err != nil:
			t.Errorf("%d: %v", code, err)
		case code/100 != 2 && err == nil:
			t.Errorf("%d: accepted", code)
		case err != nil && orchestrator.IsDefiniteNoEffect(err) != final:
			t.Errorf("%d: final = %v, want %v", code, orchestrator.IsDefiniteNoEffect(err), final)
		}
	}
	before := requests
	if err := d.Deliver(context.Background(), orchestrator.Message{TenantID: "t", Payload: json.RawMessage(`{"observer_id":""}`)}); !orchestrator.IsDefiniteNoEffect(err) || requests != before {
		t.Fatalf("an unreadable row: %v (requests %d→%d)", err, before, requests)
	}
}
