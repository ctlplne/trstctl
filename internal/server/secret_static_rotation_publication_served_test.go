// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type staticPublicationRestorer struct {
	*staticRotationProviderDouble
	restored atomic.Int32
	refuse   bool
}

func (*staticPublicationRestorer) RotationPhase(string) string { return dynsecret.RotationSinglePhase }
func (p *staticPublicationRestorer) RestoreStaticCredential(context.Context, string, string, []byte) error {
	if p.refuse {
		return errors.New("fixture native inverse refused")
	}
	p.restored.Add(1)
	return nil
}

type staticRollbackAppendFault struct {
	expectedVersion int
	interrupted     atomic.Bool
}

func (*staticRollbackAppendFault) WithKey(context.Context, eventprotect.KeyRef, func(seal.KeyWrapper) error) error {
	return errors.New("fixture should only append unprotected events")
}

func (*staticRollbackAppendFault) WithTenantEventProtection(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}

func (f *staticRollbackAppendFault) EventProtectionFor(_ context.Context, e events.Event) (events.EventProtectionDecision, error) {
	if e.Type == projections.EventApplicationSecretRotated {
		var payload projections.ApplicationSecretMutation
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return events.EventProtectionDecision{}, err
		}
		if payload.ExpectedVersion == f.expectedVersion && f.interrupted.CompareAndSwap(false, true) {
			return events.EventProtectionDecision{}, errors.New("fixture interrupted rollback append before receipt")
		}
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
}

type staticPreparedPublicationRestorer struct {
	*staticPublicationRestorer
	stageReady atomic.Bool
}

func (*staticPreparedPublicationRestorer) StaticRotationBinding(string) string {
	return strings.Repeat("e", 64)
}

func (*staticPreparedPublicationRestorer) PrepareStaticCredential(context.Context, dynsecret.GenerateRequest) ([]byte, error) {
	return []byte("fixture-prepared-native-credential"), nil
}

func (p *staticPreparedPublicationRestorer) GenerateStaticPrepared(ctx context.Context, req dynsecret.GenerateRequest, _ []byte) (dynsecret.Credential, error) {
	if !p.stageReady.Load() {
		return dynsecret.Credential{}, errors.New("fixture forward provider temporarily unavailable")
	}
	return p.Generate(ctx, req)
}

func (p *staticPreparedPublicationRestorer) RestorePreparedStaticCredential(context.Context, dynsecret.GenerateRequest, []byte, []byte) error {
	p.restored.Add(1)
	return nil
}

func TestServedStaticRotationResumesPreparedRollbackBeforeForwardEffect(t *testing.T) {
	const key, reference = "publication-key", "fixture-original-reference"
	provider := &staticRotationProviderDouble{name: "publication-provider", role: key, initialRef: reference}
	native := &staticPreparedPublicationRestorer{staticPublicationRestorer: &staticPublicationRestorer{staticRotationProviderDouble: provider}}
	fault := &staticRollbackAppendFault{expectedVersion: 1}
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{
		events.WithRequiredPrivacyEventPolicies(), events.WithEventProtection(events.EventProtection{Admission: fault, Keys: fault}),
	}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {native}}
	})
	registerServedTenant(t, h, "Prepared rollback publication fixture")
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "publication-seed",
		map[string]any{"name": key, "value": "fixture-original-value"})
	if status != http.StatusCreated {
		t.Fatalf("fixture secret status=%d", status)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, "publication-rotate",
		map[string]any{"provider": provider.name, "key": key, "old_ref": reference, "acknowledge_single_phase": true})
	var queued struct {
		ID string `json:"command_id"`
	}
	if err := json.Unmarshal(raw, &queued); status != http.StatusOK || err != nil || queued.ID == "" {
		t.Fatalf("fixture command status=%d err=%v", status, err)
	}
	if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 1); err == nil {
		t.Fatal("fixture expected the initial forward provider refusal")
	}
	before, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
	if err != nil || before.Phase != store.SecretStaticRotationPrepared {
		t.Fatalf("fixture did not persist the prepared phase: phase=%s err=%v", before.Phase, err)
	}
	if err := h.srv.api.FailStaticSecretRotation(ctx, h.tenant, queued.ID); err == nil || !fault.interrupted.Load() {
		t.Fatalf("fixture did not interrupt the prepared rollback append: %v", err)
	}
	native.stageReady.Store(true)
	err = h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 4)
	minted, _, _ := provider.snapshot()
	if err != nil || len(minted) != 0 {
		t.Fatalf("prepared rollback resumed forward work: forward-effects=%d err=%v", len(minted), err)
	}
	result, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
	if err != nil || result.Phase != store.SecretStaticRotationRolledBack || result.RestoredVersion != 2 || native.restored.Load() != 1 {
		t.Fatalf("prepared rollback recovery: phase=%s version=%d restores=%d err=%v", result.Phase, result.RestoredVersion, native.restored.Load(), err)
	}
}

// CR-231: a committed vault publication determines cleanup even when
// projecting the later worker phase fails. The provider only records calls.
func TestServedStaticRotationRecoversPublishedGenerationBeforeCleanup(t *testing.T) {
	const original = "fixture-original-reference"
	for _, tc := range []struct {
		name, blockedPhase, wantPhase                                             string
		exhausted, pendingPublication, inPlace, inverseRefused, appendInterrupted bool
	}{
		{name: "cutover-retry", blockedPhase: store.SecretStaticRotationCutover, wantPhase: store.SecretStaticRotationCompleted},
		{name: "cutover-exhausted", blockedPhase: store.SecretStaticRotationCutover, wantPhase: store.SecretStaticRotationRolledBack, exhausted: true},
		{name: "rollback-retry", blockedPhase: store.SecretStaticRotationRolledBack, wantPhase: store.SecretStaticRotationRolledBack},
		{name: "cutover-publication-pending", blockedPhase: store.SecretStaticRotationCutover, wantPhase: store.SecretStaticRotationCompleted, exhausted: true, pendingPublication: true},
		{name: "rollback-publication-pending", blockedPhase: store.SecretStaticRotationRolledBack, wantPhase: store.SecretStaticRotationRolledBack, pendingPublication: true, inPlace: true},
		{name: "ordinary-rollback-publication-pending", blockedPhase: store.SecretStaticRotationRolledBack, wantPhase: store.SecretStaticRotationRolledBack, pendingPublication: true},
		{name: "reconciler-waits-for-native-inverse", blockedPhase: store.SecretStaticRotationRolledBack, inPlace: true, inverseRefused: true},
		{name: "restore-survives-publication-without-receipt", blockedPhase: store.SecretStaticRotationRolledBack, inPlace: true, appendInterrupted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &staticRotationProviderDouble{name: "publication-provider", role: "publication-key", initialRef: original,
				verifyFail: tc.blockedPhase == store.SecretStaticRotationRolledBack}
			var servedProvider dynsecret.Provider = provider
			var restorer *staticPublicationRestorer
			if tc.inPlace {
				restorer = &staticPublicationRestorer{staticRotationProviderDouble: provider, refuse: tc.inverseRefused}
				servedProvider = restorer
			}
			eventOptions := []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}
			appendFault := &staticRollbackAppendFault{expectedVersion: 2}
			if tc.appendInterrupted {
				eventOptions = append(eventOptions, events.WithEventProtection(events.EventProtection{Admission: appendFault, Keys: appendFault}))
			}
			h := newServedHarnessWithEventOptions(t, config.Protocols{}, eventOptions, withSecretsEnabled(t, nil), func(d *Deps) {
				d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {servedProvider}}
			})
			registerServedTenant(t, h, "Static rotation publication fixture")
			ctx := t.Context()
			token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
			status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "publication-seed",
				map[string]any{"name": provider.role, "value": "fixture-original-value"})
			if status != http.StatusCreated {
				t.Fatalf("fixture secret status=%d", status)
			}
			status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, "publication-rotate",
				map[string]any{"provider": provider.name, "key": provider.role, "old_ref": original, "acknowledge_single_phase": restorer != nil})
			var queued struct {
				ID string `json:"command_id"`
			}
			if err := json.Unmarshal(raw, &queued); status != http.StatusOK || err != nil || queued.ID == "" {
				t.Fatalf("fixture command status=%d err=%v", status, err)
			}
			if tc.inverseRefused {
				if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 3); err != nil {
					t.Fatal(err)
				}
				result, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
				if err != nil || result.Phase != store.SecretStaticRotationRollbackFailed {
					t.Fatalf("native inverse did not fail at the fixture: phase=%s err=%v", result.Phase, err)
				}
				if _, err := h.srv.api.ReconcileApplicationSecretMutationFences(ctx); err != nil {
					t.Fatal(err)
				}
				current, err := h.store.GetSecret(ctx, h.tenant, provider.role)
				if err != nil || current.Version != 2 {
					t.Fatalf("reconciler published before the native inverse succeeded: version=%d err=%v", current.Version, err)
				}
				status, _ := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+provider.role, token, "publication-operator-recovery",
					map[string]any{"value": "fixture-operator-verified-value"})
				if status != http.StatusOK {
					t.Fatalf("the failed unpublished rollback blocked operator recovery: HTTP %d", status)
				}
				return
			}
			if tc.appendInterrupted {
				if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 3); err == nil || !appendFault.interrupted.Load() {
					t.Fatalf("fixture did not interrupt append before receipt: %v", err)
				}
				if count, err := h.srv.api.ReconcileApplicationSecretMutationFences(ctx); err != nil || count != 0 {
					t.Fatalf("generic reconciliation took the worker's publication: count=%d err=%v", count, err)
				}
				if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 3); err != nil {
					t.Fatal(err)
				}
				result, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
				if err != nil || result.Phase != store.SecretStaticRotationRolledBack || result.RestoredVersion != 3 || restorer.restored.Load() != 1 {
					t.Fatalf("recovery after publication interruption: phase=%s version=%d restores=%d err=%v", result.Phase, result.RestoredVersion, restorer.restored.Load(), err)
				}
				return
			}
			const installFault = `CREATE FUNCTION block_fixture_rotation_phase() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'secret_store' THEN
    RAISE EXCEPTION 'owned fixture publication failure';
  ELSIF NEW.phase = TG_ARGV[0] THEN
    RAISE EXCEPTION 'owned fixture phase projection failure';
  END IF;
  RETURN NEW;
END $$`
			if _, err := h.store.SystemPool().Exec(ctx, installFault); err != nil {
				t.Fatal(err)
			}
			const clearFault = `DROP TRIGGER IF EXISTS block_fixture_rotation_phase ON secret_static_rotation_commands;
DROP TRIGGER IF EXISTS block_fixture_rotation_phase ON secret_store;
DROP FUNCTION IF EXISTS block_fixture_rotation_phase()`
			t.Cleanup(func() { _, _ = h.store.SystemPool().Exec(context.Background(), clearFault) })
			trigger := `CREATE TRIGGER block_fixture_rotation_phase BEFORE UPDATE ON secret_static_rotation_commands
FOR EACH ROW EXECUTE FUNCTION block_fixture_rotation_phase('cutover')`
			attempt, publishedVersion, phaseBeforeRetry := 1, 2, store.SecretStaticRotationStaged
			if tc.blockedPhase == store.SecretStaticRotationRolledBack {
				trigger = `CREATE TRIGGER block_fixture_rotation_phase BEFORE UPDATE ON secret_static_rotation_commands
FOR EACH ROW EXECUTE FUNCTION block_fixture_rotation_phase('rolled_back')`
				attempt, publishedVersion, phaseBeforeRetry = 3, 3, store.SecretStaticRotationCutover
			}
			if tc.pendingPublication {
				if tc.blockedPhase == store.SecretStaticRotationRolledBack {
					if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 1); err == nil {
						t.Fatal("fixture expected to commit cutover before attempting rollback")
					}
				}
				trigger = `CREATE TRIGGER block_fixture_rotation_phase BEFORE UPDATE ON secret_store
FOR EACH ROW EXECUTE FUNCTION block_fixture_rotation_phase('publication')`
				publishedVersion--
			}
			if _, err := h.store.SystemPool().Exec(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, attempt); err == nil {
				t.Fatal("fault fixture did not interrupt the worker")
			}
			current, err := h.store.GetSecret(ctx, h.tenant, provider.role)
			if err != nil || current.Version != publishedVersion {
				t.Fatalf("vault publication did not commit: version=%d err=%v", current.Version, err)
			}
			interrupted, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
			if err != nil || interrupted.Phase != phaseBeforeRetry || interrupted.NewRef == "" {
				t.Fatalf("fixture did not leave the previous phase: phase=%s err=%v", interrupted.Phase, err)
			}
			if tc.pendingPublication && tc.exhausted {
				err := h.srv.api.FailStaticSecretRotation(ctx, h.tenant, queued.ID)
				_, revoked, _ := provider.snapshot()
				if err == nil || len(revoked) != 0 {
					t.Fatalf("pending cutover did not hold successor cleanup: deferred=%t retirements=%d", err != nil, len(revoked))
				}
			}
			if _, err := h.store.SystemPool().Exec(ctx, clearFault); err != nil {
				t.Fatal(err)
			}
			if tc.pendingPublication {
				if reconciled, err := h.srv.api.ReconcileApplicationSecretMutationFences(ctx); err != nil || reconciled != 1 {
					t.Fatalf("reconcile already-appended publication: count=%d err=%v", reconciled, err)
				}
			}
			provider.mu.Lock()
			provider.verifyFail = false
			provider.mu.Unlock()
			if tc.exhausted && !tc.pendingPublication {
				err = h.srv.api.FailStaticSecretRotation(ctx, h.tenant, queued.ID)
			} else {
				err = h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, attempt+1)
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
			if err != nil || result.Phase != tc.wantPhase {
				t.Fatalf("recovered phase=%s, want %s, err=%v", result.Phase, tc.wantPhase, err)
			}
			wantRevoked := original
			if result.Phase == store.SecretStaticRotationRolledBack {
				wantRevoked = interrupted.NewRef
			}
			minted, revoked, _ := provider.snapshot()
			if restorer != nil {
				if len(minted) != 1 || len(revoked) != 0 || restorer.restored.Load() != 1 {
					t.Fatalf("in-place recovery repeated a native effect: mints=%d restores=%d retirements=%d", len(minted), restorer.restored.Load(), len(revoked))
				}
				return
			}
			if len(minted) != 1 || len(revoked) != 1 || revoked[0] != wantRevoked {
				t.Fatalf("recovery chose the wrong effect: mints=%d retirements=%d", len(minted), len(revoked))
			}
		})
	}
}
