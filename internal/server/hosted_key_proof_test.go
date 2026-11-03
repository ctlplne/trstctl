// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// hostedKeyProof is one hosted rotator's served proof (A240) against a
// stand-in of its vendor's API: the provider as configured, the role and its
// stored secret's name, the stored value a seed starts from, how to read the
// key out of a credential document, and whether the stand-in accepts a key.
type hostedKeyProof struct {
	provider       config.DynamicSecretProviderConfig
	role           string
	seed           string
	keyOf          func(t *testing.T, credential string) string
	authenticates  func(t *testing.T, key string) bool
	newRefPrefix   string
	leases         bool
	wantVerifyMode string
	// firstOldRef is the first rotation's old_ref: "none", or a credential
	// the provider must retire (an Okta app holds two secrets, so the first
	// rotation retires the app's original one).
	firstOldRef string
}

// run proves, through the served API: a lease's key authenticates until
// revocation deletes it (when the vendor issues leases); and a static
// rotation is two-phase, both keys authenticating between verification and
// the approved retirement deadline, after which only the predecessor is
// deleted.
func (p hostedKeyProof) run(t *testing.T) {
	t.Helper()
	configs := []config.DynamicSecretProviderConfig{p.provider}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A240 "+p.provider.Type+" tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	providerID := p.provider.ID

	if p.leases {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a240-"+providerID+"-lease-1",
			map[string]any{"provider": providerID, "role": p.role, "ttl_seconds": 600})
		var lease dynamicLeaseView
		if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &lease) != nil || lease.Credential == "" {
			t.Fatalf("issue: %d %s", status, body)
		}
		leased := p.keyOf(t, lease.Credential)
		if !p.authenticates(t, leased) {
			t.Fatal("the leased key does not authenticate")
		}
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke: %d %s", status, body)
		}
		for deadline := time.Now().Add(30 * time.Second); ; {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
			var view dynamicLeaseView
			if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the revocation did not complete: %d %s", status, body)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if p.authenticates(t, leased) {
			t.Fatal("the revoked key still authenticates")
		}
	}

	await := func(id string, until func(staticRotationCommandView) bool) staticRotationCommandView {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); ; {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
			var view staticRotationCommandView
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("read command %s: %d %s", id, status, body)
			}
			if until(view) {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("command %s: %+v", id, view)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	rotate := func(idempotencyKey string, request map[string]any) string {
		t.Helper()
		request["provider"], request["key"] = providerID, p.role
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotencyKey, request)
		var queued struct {
			CommandID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
			t.Fatalf("rotate: %d %s", status, body)
		}
		return queued.CommandID
	}
	stored := func() string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+p.role, tok, nil)
		var value struct {
			Value string `json:"value"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &value) != nil {
			t.Fatalf("read the stored key: %d", status)
		}
		return p.keyOf(t, value.Value)
	}
	terminal := func(view staticRotationCommandView) bool { return view.Terminal }
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-"+providerID,
		map[string]any{"name": p.role, "value": p.seed}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	firstOldRef := p.firstOldRef
	if firstOldRef == "" {
		firstOldRef = "none"
	}
	first := await(rotate(providerID+"-rotate-1", map[string]any{"old_ref": firstOldRef}), terminal)
	if first.Phase != store.SecretStaticRotationCompleted || first.RotationPhase != "two_phase" || first.VerifyMode != p.wantVerifyMode ||
		!strings.HasPrefix(first.NewRef, p.newRefPrefix) {
		t.Fatalf("the first rotation: %+v", first)
	}
	predecessor := stored()
	second := rotate(providerID+"-rotate-2", map[string]any{"old_ref": first.NewRef, "retire_after_seconds": 2})
	verified := await(second, func(view staticRotationCommandView) bool {
		return view.Phase == store.SecretStaticRotationVerified || view.Terminal
	})
	successor := stored()
	if verified.Phase != store.SecretStaticRotationVerified || successor == predecessor ||
		!p.authenticates(t, predecessor) || !p.authenticates(t, successor) {
		t.Fatalf("both keys must authenticate between cutover and retirement: %+v", verified)
	}
	if retired := await(second, terminal); retired.Phase != store.SecretStaticRotationCompleted || retired.OldRef != first.NewRef {
		t.Fatalf("the second rotation at retirement: %+v", retired)
	}
	if p.authenticates(t, predecessor) || !p.authenticates(t, successor) {
		t.Fatal("retirement must delete the predecessor's key and only that one")
	}
}
