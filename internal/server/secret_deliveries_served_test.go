// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A240: a deleted secret takes its consumers' delivery evidence with it. A
// secret recreated under the same name starts again at version 1, so the old
// secret's reports must not count for the new one: a static rotation's
// retirement gate reads this evidence, and a consumer's report of the old
// version 3 would otherwise adopt the new secret's version 2 before the
// consumer ever read it.
func TestServedSecretDeleteClearsDeliveryEvidenceA240(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A240 delivery evidence tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "orders-operator", "secrets:read", "secrets:write")
	const name = "orders/db-password"
	// write creates the secret, or rotates it to its next version.
	write := func(key, value string, create bool) {
		t.Helper()
		method, path, request := http.MethodPut, "/api/v1/secrets/store/"+name, map[string]any{"value": value}
		if create {
			method, path, request = http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": name, "value": value}
		}
		if status, body := secretsReqKey(t, h, method, path, tok, key, request); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("write %s: %d %s", key, status, body)
		}
	}
	report := func(key string, version int) int {
		t.Helper()
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deliveries", tok, key, map[string]any{
			"consumer": "orders-app", "state": "verified", "secrets": []map[string]any{{"name": name, "version": version}}})
		return status
	}
	type consumerState struct {
		Consumer        string `json:"consumer"`
		VerifiedVersion int    `json:"verified_version"`
	}
	consumers := func() (int, []consumerState) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/deliveries?name="+name, tok, nil)
		var out struct {
			CurrentVersion int             `json:"current_version"`
			Consumers      []consumerState `json:"consumers"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("deliveries: %d %s", status, body)
		}
		return out.CurrentVersion, out.Consumers
	}

	for version := 1; version <= 3; version++ {
		write(fmt.Sprintf("orders-write-%d", version), fmt.Sprintf("password-%d", version), version == 1)
	}
	if status := report("orders-report-3", 3); status != http.StatusOK {
		t.Fatalf("report version 3: %d", status)
	}
	if current, states := consumers(); current != 3 || len(states) != 1 || states[0].VerifiedVersion != 3 {
		t.Fatalf("evidence before the delete: current=%d %+v", current, states)
	}

	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+name, tok, "orders-delete", nil); status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", status, body)
	}
	write("orders-recreate-1", "fresh-password-1", true)
	write("orders-recreate-2", "fresh-password-2", false)
	if current, states := consumers(); current != 2 || len(states) != 0 {
		t.Fatalf("the recreated secret inherited delivery evidence: current=%d %+v", current, states)
	}
	if status := report("orders-report-old-3", 3); status == http.StatusOK {
		t.Fatal("a report of a version the recreated secret does not have was accepted")
	}
	if status := report("orders-report-new-2", 2); status != http.StatusOK {
		t.Fatalf("report version 2 of the recreated secret: %d", status)
	}
	if _, states := consumers(); len(states) != 1 || states[0].VerifiedVersion != 2 {
		t.Fatalf("fresh evidence for the recreated secret: %+v", states)
	}
}
