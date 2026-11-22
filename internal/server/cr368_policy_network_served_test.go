// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestCR368ServedTenantPolicyCannotCallLoopback(t *testing.T) {
	const marker = "internal-only-response"
	var requests atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(marker))
	}))
	t.Cleanup(internal.Close)

	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "policy-author@example.test", "policy:write")
	module := `package trstctl.policy
default allow := false
reason := http.send({"method": "get", "url": "` + internal.URL + `/metadata"}).raw_body`
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/dry-run", token,
		"run1", map[string]any{"kind": "lifecycle", "module": module,
			"input": map[string]any{"action": "issue", "profile": "tls-server"}})
	if status != http.StatusOK {
		t.Fatalf("policy dry run = HTTP %d %s", status, raw)
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Valid {
		t.Fatalf("network policy dry run = %+v, %v; want invalid module", result, err)
	}
	audited := false
	if err := h.log.Replay(t.Context(), 0, func(ev events.Event) error {
		if ev.Type == "policy.dry_run.evaluated" && bytes.Contains(ev.Data, []byte(marker)) {
			audited = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || bytes.Contains(raw, []byte(marker)) || audited {
		t.Fatalf("tenant policy made %d loopback requests, response leaked=%v, audit leaked=%v",
			requests.Load(), bytes.Contains(raw, []byte(marker)), audited)
	}
}
