// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// Q6-L2: registrations of one secret as a decoy that arrive together make one
// decoy; every other is refused (409) instead of passing the live-decoy check
// alongside it.
func TestServedConcurrentDecoyRegistrationsMakeOneDecoyQ6L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.EnableSecretsAPI = true })
	planter := seedScopedTokenSubject(t, h.store, h.tenant, "decoy-planter", "secrets:read", "secrets:write")
	const bait = "prod/billing/stripe-key"
	if status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", planter, "q6l2-bait", map[string]any{"name": bait, "value": "sk-decoy-shaped-value"}); status != http.StatusCreated {
		t.Fatalf("create bait: HTTP %d %s", status, out)
	}
	const racers = 16
	statuses := make([]int, racers)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range racers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			statuses[i], _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/secrets", planter, fmt.Sprintf("q6l2-register-%d", i),
				map[string]any{"secret_name": bait, "name": fmt.Sprintf("billing bait %d", i), "placement": "billing repo"})
		}()
	}
	start.Done()
	done.Wait()
	created, conflicts := 0, 0
	for _, status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		}
	}
	if created != 1 || conflicts != racers-1 {
		t.Fatalf("concurrent registrations = %v, want one 201 and %d 409", statuses, racers-1)
	}
	var decoys int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM honey_tokens WHERE tenant_id = $1 AND kind = 'secret' AND secret_name = $2`, h.tenant, bait).Scan(&decoys); err != nil {
		t.Fatal(err)
	}
	if decoys != 1 {
		t.Fatalf("%d decoys watch %s, want 1", decoys, bait)
	}
}
