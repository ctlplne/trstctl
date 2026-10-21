// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/config"
)

// A50/A53/A54 on the assembled binary: an operator replaces a credential's
// policy over the API and the ACME mount enforces it at once; a rotation
// registers a successor from a secret-store reference the operator wrote
// beforehand, the successor binds accounts with that key, the predecessor
// keeps working until disabled, no response carries the key in any encoding,
// and both changes survive a server restart through the ACME state log.
func TestServedACMEEABPolicyAndRotationAreServedAndSurviveRestart(t *testing.T) {
	configuredKey := bytes.Repeat([]byte{0x63}, 32)
	successorKey := bytes.Repeat([]byte{0x64}, 32)
	protocols := config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEAB: config.ACMEExternalAccountBinding{Required: true, Keys: []config.ACMEExternalAccountBindingKey{
			{KeyID: "payments-team", HMACKey: configuredKey, AllowedIdentifiers: []string{"*.example.test"}},
		}},
	}
	h := newOperatingServedHarness(t, protocols)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")
	ctx := context.Background()
	const (
		secretName = "acme/eab/payments-team-2"          // #nosec G101 -- logical fixture name, not secret material (CWE-798)
		secretRef  = "secret://acme/eab/payments-team-2" // #nosec G101 -- a reference, not secret material (CWE-798)
	)
	// The operator writes the successor key to the tenant secret store first;
	// here it is sealed under the harness KEK exactly as the secrets API would.
	sealed, err := sealTenantValue(ctx, nil, h.kek, h.tenant, successorKey, []byte(h.tenant+"/secret-store/"+secretName))
	if err != nil {
		t.Fatalf("seal successor MAC key: %v", err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, secretName, sealed)

	// A53: the served policy narrows the configured scope and adds a quota.
	status, body := secretsReq(t, h, http.MethodPut, "/api/v1/acme/eab-credentials/payments-team/policy", tok, map[string]any{
		"allowed_identifiers": []string{"*.payments.example.test"}, "max_orders": 3,
	})
	if status != http.StatusOK {
		t.Fatalf("update policy = %d %s", status, body)
	}
	var updated struct {
		AllowedIdentifiers []string `json:"allowed_identifiers"`
		MaxOrders          int      `json:"max_orders"`
		State              string   `json:"state"`
	}
	_ = json.Unmarshal(body, &updated)
	if updated.State != "active" || updated.MaxOrders != 3 || len(updated.AllowedIdentifiers) != 1 {
		t.Fatalf("policy response = %s", body)
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/acme/eab-credentials/payments-team/policy", tok, map[string]any{"max_orders": -1}); status != http.StatusBadRequest {
		t.Fatalf("negative quota = %d %s, want 400", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/acme/eab-credentials/nobody/policy", tok, map[string]any{}); status != http.StatusNotFound {
		t.Fatalf("unknown credential = %d %s, want 404", status, body)
	}
	payments := registerWithEAB(t, h, "payments-team", configuredKey)
	if _, err := payments.AuthorizeOrder(ctx, xacme.DomainIDs("api.billing.example.test")); err == nil {
		t.Fatal("the served mount still admits an identifier the updated policy excludes")
	}
	if _, err := payments.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("in-scope order under the updated policy: %v", err)
	}

	// A50/A54: rotation from a reference. The key itself is refused in the
	// request, an unresolvable reference is refused, and a good one registers
	// the successor with the predecessor's policy.
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/payments-team/rotate", tok, map[string]any{
		"successor_key_id": "payments-team-2", "hmac_key_ref": base64.StdEncoding.EncodeToString(successorKey),
	}); status != http.StatusBadRequest {
		t.Fatalf("a raw key in hmac_key_ref = %d %s, want 400", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/payments-team/rotate", tok, map[string]any{
		"successor_key_id": "payments-team-2", "hmac_key_ref": "secret://acme/eab/missing",
	}); status != http.StatusUnprocessableEntity || strings.Contains(string(body), "no rows") {
		t.Fatalf("an unresolvable reference = %d %s, want 422 without store internals", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/payments-team/rotate", tok, map[string]any{
		"successor_key_id": "payments-team-2", "hmac_key_ref": secretRef,
	})
	if status != http.StatusCreated {
		t.Fatalf("rotate = %d %s", status, body)
	}
	var rotated struct {
		KeyID              string   `json:"key_id"`
		State              string   `json:"state"`
		HMACKeyRef         string   `json:"hmac_key_ref"`
		AllowedIdentifiers []string `json:"allowed_identifiers"`
		MaxOrders          int      `json:"max_orders"`
	}
	_ = json.Unmarshal(body, &rotated)
	if rotated.KeyID != "payments-team-2" || rotated.State != "active" || rotated.HMACKeyRef != secretRef || rotated.MaxOrders != 3 || len(rotated.AllowedIdentifiers) != 1 {
		t.Fatalf("rotation response = %s; want the successor active under the predecessor's policy", body)
	}
	assertNoKeyMaterial := func(where string, body []byte) {
		t.Helper()
		for name, enc := range map[string]string{
			"hex": hex.EncodeToString(successorKey), "base64": base64.StdEncoding.EncodeToString(successorKey),
			"base64url": base64.RawURLEncoding.EncodeToString(successorKey),
		} {
			if strings.Contains(string(body), enc) {
				t.Fatalf("%s carries the successor MAC key (%s)", where, name)
			}
		}
		if bytes.Contains(body, successorKey) {
			t.Fatalf("%s carries the successor MAC key raw", where)
		}
	}
	assertNoKeyMaterial("rotation response", body)
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/acme/eab-credentials", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"key_id":"payments-team-2"`) {
		t.Fatalf("list after rotation = %d %s", status, body)
	}
	assertNoKeyMaterial("credential listing", body)

	successor := registerWithEAB(t, h, "payments-team-2", successorKey)
	if _, err := successor.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("order under the successor: %v", err)
	}
	if _, err := successor.AuthorizeOrder(ctx, xacme.DomainIDs("api.billing.example.test")); err == nil {
		t.Fatal("the successor inherited no scope")
	}
	// The predecessor keeps working until disabled, then stops.
	registerWithEAB(t, h, "payments-team", configuredKey)
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/eab-credentials/payments-team/disable", tok, nil); status != http.StatusOK {
		t.Fatalf("disable predecessor = %d %s", status, body)
	}
	if _, err := registerWithEABResult(h, "payments-team", configuredKey); err == nil {
		t.Fatal("a disabled predecessor still admits new accounts")
	}

	// Restart: policy and successor come back from the ACME state log, the
	// successor's key resolved again from the secret store.
	h.ts.Close()
	restarted, err := Build(ctx, Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, Protocols: protocols, KEK: h.kek,
	})
	if err != nil {
		t.Fatalf("restart server build: %v", err)
	}
	cleanupServedServer(t, restarted)
	ts2 := httptest.NewServer(restarted.Handler())
	t.Cleanup(ts2.Close)
	h.srv, h.ts = restarted, ts2
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/acme/eab-credentials", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list after restart = %d %s", status, body)
	}
	var listing struct {
		Items []struct {
			KeyID              string   `json:"key_id"`
			State              string   `json:"state"`
			HMACKeyRef         string   `json:"hmac_key_ref"`
			AllowedIdentifiers []string `json:"allowed_identifiers"`
			MaxOrders          int      `json:"max_orders"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &listing)
	seen := map[string]bool{}
	for _, item := range listing.Items {
		seen[item.KeyID] = true
		switch item.KeyID {
		case "payments-team-2":
			if item.State != "active" || item.HMACKeyRef != secretRef || item.MaxOrders != 3 {
				t.Fatalf("successor after restart = %+v", item)
			}
		case "payments-team":
			if len(item.AllowedIdentifiers) != 1 || item.AllowedIdentifiers[0] != "*.payments.example.test" || item.MaxOrders != 3 {
				t.Fatalf("predecessor policy after restart = %+v", item)
			}
		}
	}
	if !seen["payments-team-2"] || !seen["payments-team"] {
		t.Fatalf("listing after restart = %s", body)
	}
	assertNoKeyMaterial("listing after restart", body)
	after := registerWithEAB(t, h, "payments-team-2", successorKey)
	if _, err := after.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("order under the successor after restart: %v", err)
	}
	if _, err := after.AuthorizeOrder(ctx, xacme.DomainIDs("api.billing.example.test")); err == nil {
		t.Fatal("the replayed successor lost its scope")
	}
}
