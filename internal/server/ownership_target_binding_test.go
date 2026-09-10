// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A served deployment supplies real matching authority. Retarget only the outer
// identity in an isolated retained-event fixture: live projection and full replay
// must reject borrowing a different owner's attestation before writing any state.
// This is an adversarial source regression, not a claim of a public API exploit.
func TestOwnershipEvidenceCannotAuthorizeDifferentIdentity(t *testing.T) {
	cfg := config.Default()
	cadence, err := ownershipAttestationCadenceFromConfig(cfg.Lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.OwnershipAttestationCadence = cadence })
	ctx := context.Background()
	token := seedScopedTokenSubject(t, h.store, h.tenant, "binding-reviewer@example.test",
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:issue")
	makeIdentity := func(name string) (string, string) {
		owner := servedCreateID(t, h, token, name+"-owner", "/api/v1/owners", map[string]any{
			"kind": "service", "name": name, "email": name + "@example.test", "application_id": "APP-" + name,
			"service": name, "business_unit": "platform", "environment": "test", "escalation_chain": []string{"oncall@example.test"},
		})
		return owner, aud44CreateIssuedIdentity(t, h, token, owner, name)
	}
	ownerA, identityA := makeIdentity("binding-attested")
	_, identityB := makeIdentity("binding-unattested")
	status, body := aud44Transition(t, h, token, identityB, "binding-denied", "deployed")
	if status != http.StatusConflict || !strings.Contains(string(body), "ownership") {
		t.Fatalf("unattested customer deployment: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+ownerA+"/attest", token,
		"binding-attest", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("attest: %d %s", status, body)
	}
	status, body = aud44Transition(t, h, token, identityA, "binding-genuine-deployment", "deployed")
	if status != http.StatusOK {
		t.Fatalf("matching customer deployment: %d %s", status, body)
	}
	var prefix []events.Event
	var deployed events.Event
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == projections.EventIdentityDeployed {
			if deployed.ID != "" {
				return fmt.Errorf("unexpected second deployment")
			}
			deployed = e
		} else if deployed.ID == "" {
			prefix = append(prefix, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if deployed.ID == "" || deployed.SchemaVersion != projections.LifecycleOwnershipReadinessEventSchemaVersion {
		t.Fatalf("expected genuine v6 deployment, got id=%q schema=%d", deployed.ID, deployed.SchemaVersion)
	}

	for _, version := range []int{projections.LifecycleOwnershipReadinessEventSchemaVersion, projections.LifecycleCompletedSideEffectEventSchemaVersion} {
		for _, mode := range []string{"live-projection", "full-replay"} {
			t.Run(fmt.Sprintf("v%d/%s", version, mode), func(t *testing.T) {
				target := newServerTestStore(t)
				log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = log.Close() })
				for _, e := range prefix {
					if _, err := log.Append(ctx, e); err != nil {
						t.Fatal(err)
					}
				}
				if err := rebuildRestoredReadModel(ctx, cfg, target, log, "binding prefix", nil); err != nil {
					t.Fatal(err)
				}
				before := ownershipTargetBindingState(t, target, h.tenant, identityB)
				beforeIdentity, err := target.GetIdentity(ctx, h.tenant, identityB)
				if err != nil || beforeIdentity.Status != "issued" {
					t.Fatalf("prefix target: %+v %v", beforeIdentity, err)
				}

				var payload map[string]json.RawMessage
				if err := json.Unmarshal(deployed.Data, &payload); err != nil {
					t.Fatal(err)
				}
				candidate := deployed
				candidate.SchemaVersion = version
				if version == projections.LifecycleCompletedSideEffectEventSchemaVersion {
					// The completed-receipt schema is a constructed parser variant, not a
					// fabricated customer delivery receipt. It must bind the same target too.
					var effect map[string]json.RawMessage
					if err := json.Unmarshal(payload["side_effect"], &effect); err != nil {
						t.Fatal(err)
					}
					effect["completed"] = json.RawMessage(`true`)
					delete(effect, "payload")
					delete(effect, "required_agent_role")
					payload["side_effect"], err = json.Marshal(effect)
					if err != nil {
						t.Fatal(err)
					}
				}
				candidate.Data, err = json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := projections.ValidateLifecycleApprovalEvent(candidate); err != nil {
					t.Fatalf("matching schema control: %v", err)
				}
				payload["identity_id"], err = json.Marshal(identityB)
				if err != nil {
					t.Fatal(err)
				}
				candidate.Data, err = json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := projections.ValidateLifecycleApprovalEvent(candidate); err == nil || !strings.Contains(err.Error(), "ownership-readiness target mismatch") {
					t.Errorf("retargeted self-contained authority check = %v", err)
				}
				switch mode {
				case "live-projection":
					opts, err := recoveryProjectionOptions(ctx, cfg, target, log, nil)
					if err != nil {
						t.Fatal(err)
					}
					err = projections.New(target, opts...).Apply(ctx, candidate)
					if err == nil || !strings.Contains(err.Error(), "ownership-readiness target mismatch") {
						t.Errorf("retargeted live event: %v", err)
					}
				case "full-replay":
					if _, err := log.Append(ctx, candidate); err != nil {
						t.Fatal(err)
					}
					err = rebuildRestoredReadModel(ctx, cfg, target, log, "binding adversarial replay", nil)
					if err == nil || !strings.Contains(err.Error(), "ownership-readiness target mismatch") {
						t.Errorf("retargeted full replay: %v", err)
					}
				}
				if after := ownershipTargetBindingState(t, target, h.tenant, identityB); after != before {
					t.Errorf("retargeted event changed identity/history/outbox/checkpoint: before=%s after=%s", before, after)
				}
			})
		}
	}
}

func ownershipTargetBindingState(t *testing.T, s *store.Store, tenantID, identityID string) string {
	t.Helper()
	ctx := context.Background()
	var raw []byte
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT jsonb_build_object(
   'identity', (SELECT to_jsonb(i.*) FROM identities i WHERE tenant_id=$1 AND id=$2),
   'history', (SELECT coalesce(jsonb_agg(to_jsonb(h.*) ORDER BY seq), '[]'::jsonb) FROM identity_transitions h WHERE tenant_id=$1 AND identity_id=$2),
   'outbox', (SELECT count(*) FROM outbox WHERE tenant_id=$1)
  )`, tenantID, identityID).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%d:%s", checkpoint, raw)
}
