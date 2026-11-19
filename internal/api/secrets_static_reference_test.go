// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// CR-663. Fresh and recovered unsupported terminals use the same reference
// guard. A native source cannot authorize a changed predecessor or successor.
func TestUnsupportedLegacyNativeTerminalChecksTheFrozenReference(t *testing.T) {
	a := &API{}
	for _, tc := range []struct {
		name, frozen, oldRef, newRef string
		nativeUnsupported, allowed   bool
	}{
		{"exact native tuple", "fixture-native", "fixture-native", "", true, true},
		{"unproved provider", "fixture-native", "fixture-native", "", false, false},
		{"other predecessor", "fixture-native", "fixture-other", "", true, false},
		{"unexpected successor", "fixture-native", "fixture-native", "fixture-successor", true, false},
		{"qualified value", "fixture-binding/fixture-value", "fixture-binding/fixture-value", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := a.authorizeScheduledStaticReferences(t.Context(), "fixture-tenant",
				store.SecretRotationSchedule{Provider: "fixture-native", OldRef: tc.frozen},
				"fixture-key", "fixture-binding", tc.oldRef, tc.newRef, tc.nativeUnsupported)
			if (err == nil) != tc.allowed {
				t.Fatalf("allow=%t, want %t: %v", err == nil, tc.allowed, err)
			}
		})
	}
}

func TestGuardedStaticStageValidatesStableCiphertextAcrossKeyRewrap(t *testing.T) {
	log := openApplicationSecretRecoveryLog(t)
	ctx := t.Context()
	original, err := seal.NewLocalKEK(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer original.Destroy()
	current, err := seal.NewLocalKEK(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer current.Destroy()
	command := store.SecretStaticRotationCommand{
		TenantID: "11111111-1111-4111-8111-111111111171", ID: "fixture-command", TenantEpoch: "fixture-epoch",
		Provider: "fixture-hosted", ProviderType: "openrouter", Key: "fixture/rotation", NewRef: "unlimited/fixture-id",
	}
	aad := staticRotationAAD(command.TenantID, command.ID, "new")
	credential := []byte(`{"api_key":"fixture-material","key_hash":"fixture-id"}`)
	defer secret.Wipe(credential)
	historical, err := seal.Seal(original, credential, aad)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(wrapped []byte) ([]byte, bool, error) {
		key, err := original.UnwrapDEK(wrapped)
		if err != nil {
			return nil, false, err
		}
		defer secret.Wipe(key)
		rewrapped, err := current.WrapDEK(key)
		return rewrapped, err == nil, err
	}
	restamped, changed, err := seal.RewrapContainerDEK(historical, wrap)
	if err != nil || !changed || bytes.Equal(restamped, historical) {
		t.Fatalf("create an independent custody wrapper: %v", err)
	}
	raw, err := json.Marshal(projections.SecretStaticRotationHostedStaged{
		ID: command.ID, TenantEpoch: command.TenantEpoch, FromPhase: store.SecretStaticRotationQueued,
		Phase: store.SecretStaticRotationStaged, ProviderType: command.ProviderType, NewRef: command.NewRef, SealedNew: historical,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID:       staticRotationEventID(command, store.SecretStaticRotationStaged),
		TenantID: command.TenantID, SchemaVersion: projections.SecretStaticRotationHostedStageSchemaVersion,
		Type: projections.EventSecretStaticRotationAdvanced, Data: raw,
	}); err != nil {
		t.Fatal(err)
	}
	a := &API{log: log, secrets: &secretsService{be: SecretsBackend{KEK: current}}}
	command.SealedNew = restamped
	if proven, err := a.guardedStaticStage(ctx, command, command.ProviderType, command.NewRef); err != nil || !proven {
		t.Fatalf("valid new custody did not preserve the admitted payload: %v", err)
	}
	command.SealedNew, err = seal.Seal(current, credential, aad)
	if err != nil {
		t.Fatal(err)
	}
	if proven, err := a.guardedStaticStage(ctx, command, command.ProviderType, command.NewRef); proven || !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("a separately sealed payload inherited the old stage admission: %v", err)
	}
}
