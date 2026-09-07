// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// DP2-053: identical in-flight retries of a secret-store create (same
// Idempotency-Key, same body, same caller, all at once) execute the command once
// and every caller receives the canonical 201, or the documented in-progress 409
// followed by the replay on the next attempt. On the starting candidate the route
// ran on the durable idempotency path, which let concurrent identical callers
// execute the callback, and one of them answered 404 (g300) or 409 'already
// exists' (g297).
func TestServedIdenticalSecretCreatesCoalesceAndReplay(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "identical secret creates tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	const callers = 12
	statuses := make([]int, callers)
	bodies := make([]string, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			st, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "secret-retry-storm",
				map[string]any{"name": "retry-storm", "value": "one-value"})
			statuses[i], bodies[i] = st, string(body)
		}(i)
	}
	close(start)
	wg.Wait()

	created, inProgress := 0, 0
	for i, st := range statuses {
		switch st {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			if !strings.Contains(bodies[i], "still in progress") {
				t.Fatalf("caller %d: 409 that is not the documented in-progress answer: %s", i, bodies[i])
			}
			inProgress++
		default:
			t.Fatalf("caller %d: status %d (want 201 or the documented in-progress 409): %s", i, st, bodies[i])
		}
	}
	if created == 0 {
		t.Fatalf("no caller received the canonical 201 (created=%d in-progress=%d)", created, inProgress)
	}
	// Whoever was told "in progress" gets the replay on its next attempt.
	if inProgress > 0 {
		st, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "secret-retry-storm",
			map[string]any{"name": "retry-storm", "value": "one-value"})
		if st != http.StatusCreated {
			t.Fatalf("replay after in-progress: %d %s", st, body)
		}
	}
	// Exactly one secret version exists: the command ran once.
	st, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store", tok, nil)
	if st != http.StatusOK {
		t.Fatalf("list secrets: %d %s", st, body)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	matches := 0
	for _, it := range listed.Items {
		if it["name"] == "retry-storm" {
			matches++
			if v, ok := it["version"].(float64); ok && v != 1 {
				t.Fatalf("secret version after the identical-retry storm = %v, want 1: %s", v, body)
			}
		}
	}
	if matches != 1 {
		t.Fatalf("secrets named retry-storm = %d, want exactly one: %s", matches, body)
	}
}
