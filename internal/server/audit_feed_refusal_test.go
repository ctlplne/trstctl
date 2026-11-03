// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A refusal no retry can repair is a definite no-effect, so the outbox stops
// instead of spending the row's retries, and a provider without a credential
// scheme is refused before the batch is sent rather than posted without one.
func TestAuditFeedRefusalsAreDefiniteNoEffect(t *testing.T) {
	d := &issuanceDispatcher{orch: &orchestrator.Orchestrator{}}
	payload, err := json.Marshal(auditsink.FeedBatch{Provider: auditsink.ProviderSplunkHEC})
	if err != nil {
		t.Fatal(err)
	}
	err = d.handleAuditFeedBatch(context.Background(), orchestrator.Message{Destination: orchestrator.DestinationAuditFeedSentinel, Payload: payload})
	if err == nil || !orchestrator.IsDefiniteNoEffect(err) || !strings.Contains(err.Error(), "authority is incomplete or mismatched") {
		t.Fatalf("a batch whose authority does not match its destination: %v; want a definite no-effect", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://collector.invalid/ingest", nil)
	if err := authorizeAuditFeedRequest(req, "future-collector", "batch-1", []byte("token")); err == nil || !orchestrator.IsDefiniteNoEffect(err) {
		t.Fatalf("a provider with no credential scheme: %v; want a definite no-effect", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("a refused provider's request carries an Authorization header")
	}
	for provider, scheme := range map[string]string{
		auditsink.ProviderSplunkHEC: "Splunk ", auditsink.ProviderSentinel: "Bearer ", auditsink.ProviderElastic: "ApiKey ",
	} {
		req := httptest.NewRequest(http.MethodPost, "https://collector.invalid/ingest", nil)
		if err := authorizeAuditFeedRequest(req, provider, "batch-1", []byte("token")); err != nil || req.Header.Get("Authorization") != scheme+"token" {
			t.Errorf("%s: %v, Authorization %q; want %q", provider, err, req.Header.Get("Authorization"), scheme+"token")
		}
	}
}
