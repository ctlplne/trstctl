// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Exercise the recovery assembly against events emitted by the HTTP command
// path. Reusing the running server's projector would hide missing recovery
// options, which is how a real full restore rejected a valid deployed event.
func TestRecoveryReplaysServedOwnershipDecision(t *testing.T) {
	cfg := config.Default()
	cadence, err := ownershipAttestationCadenceFromConfig(cfg.Lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OwnershipAttestationCadence = cadence
	})
	ctx := context.Background()
	var postgresVersion string
	if err := h.store.SystemPool().QueryRow(ctx, "SHOW server_version").Scan(&postgresVersion); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual PostgreSQL version: %s", postgresVersion)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "recovery-owner@example.test",
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:issue")
	ownerID := servedCreateID(t, h, token, "recovery-owner", "/api/v1/owners", map[string]any{
		"kind": "service", "name": "recovery service", "email": "recovery-owner@example.test",
		"application_id": "APP-RECOVERY", "service": "recovery", "business_unit": "platform",
		"environment": "test", "escalation_chain": []string{"oncall@example.test"},
	})
	identityID := aud44CreateIssuedIdentity(t, h, token, ownerID, "recovery-owned-leaf")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+ownerID+"/attest",
		token, "recovery-attest", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("attest: %d %s", status, body)
	}
	status, body = aud44Transition(t, h, token, identityID, "recovery-deploy", "deployed")
	if status != http.StatusOK {
		t.Fatalf("deploy: %d %s", status, body)
	}
	var deployed int
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventIdentityDeployed {
			deployed++
		}
		return nil
	}); err != nil || deployed != 1 {
		t.Fatalf("served deployment events = %d, error = %v", deployed, err)
	}

	for _, tc := range []struct {
		name      string
		factories []EditionProjectionOptionsFactory
	}{
		{name: "core"},
		{name: "edition-seam", factories: []EditionProjectionOptionsFactory{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := newServerTestStore(t)
			if err := rebuildRestoredReadModel(ctx, cfg, target, h.log, "cold recovery", tc.factories); err != nil {
				t.Fatalf("recover emitted ownership decision: %v", err)
			}
			identity, err := target.GetIdentity(ctx, h.tenant, identityID)
			if err != nil || identity.Status != "deployed" {
				t.Fatalf("recovered identity = %+v, error = %v", identity, err)
			}
			owner, err := target.GetOwner(ctx, h.tenant, ownerID)
			if err != nil || owner.OwnershipVerifiedBy != "recovery-owner@example.test" {
				t.Fatalf("recovered owner = %+v, error = %v", owner, err)
			}
		})
	}
}

func TestRecoveryRejectsMalformedOwnershipCadence(t *testing.T) {
	cfg := config.Default()
	cfg.Lifecycle.OwnershipAttestationCadence = "invalid"
	if _, err := recoveryProjectionOptions(context.Background(), cfg, nil, nil, nil); err == nil {
		t.Fatal("recovery accepted an invalid ownership cadence without edition factories")
	}
}
