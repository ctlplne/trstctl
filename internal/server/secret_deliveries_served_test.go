// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

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

// A240: a read returns the version its value came from. A consumer reports
// the version it read as adopted, and the retirement gate trusts that report;
// a read that paired version N with N-1's value let the gate retire the
// credential the consumer was still using (the two-user rotation test, CI
// 41533216865). Reads racing back-to-back rotations always pair each value
// with its own version.
func TestServedSecretReadPairsValueWithItsVersionA240(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A240 read consistency tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "orders-operator", "secrets:read", "secrets:write")
	const name = "orders/api-token"
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "token-1", map[string]any{"name": name, "value": "value-1"}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create: %d %s", status, body)
	}
	done, stop := make(chan struct{}), make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		defer close(done)
		for version := 2; version <= 40; version++ {
			select {
			case <-stop:
				return
			default:
			}
			if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+name, tok, fmt.Sprintf("token-%d", version),
				map[string]any{"value": fmt.Sprintf("value-%d", version)}); status != http.StatusOK {
				t.Errorf("rotate to version %d: %d %s", version, status, body)
				return
			}
		}
	}()
	// A failed read ends the test; the writer stops first.
	defer func() { close(stop); writer.Wait() }()
	reads, newest := 0, 0
	for deadline := time.Now().Add(2 * time.Minute); ; reads++ {
		select {
		case <-done:
			if reads < 20 || newest < 2 {
				t.Fatalf("%d reads saw versions up to %d; the race was not exercised", reads, newest)
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the rotations did not finish")
		}
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+name, tok, nil)
		var read struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &read) != nil {
			t.Fatalf("read: %d %s", status, body)
		}
		if read.Value != fmt.Sprintf("value-%d", read.Version) {
			t.Fatalf("read %d returned version %d with value %q", reads, read.Version, read.Value)
		}
		newest = max(newest, read.Version)
	}
}
