// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// TestSecretRotationRetryBodyKeepsTheRotationsGateA245L4: retrying a failed
// secret rotation sends the same provider, key and predecessor, and keeps its
// lifetime, consumers, retirement gate and single-phase acknowledgment; a
// plain static rotation sends only what it had.
func TestSecretRotationRetryBodyKeepsTheRotationsGateA245L4(t *testing.T) {
	full := secretRotationRetryBody(store.SecretStaticRotationCommand{
		Provider: "pg", Key: "payments/prod/db", OldRef: "role-a", TTLSeconds: 3600,
		Consumers: []string{"web-1/app"}, RetireAfterSeconds: 600, SinglePhaseAcknowledged: true,
	})
	want := map[string]any{"provider": "pg", "key": "payments/prod/db", "old_ref": "role-a", "ttl_seconds": 3600,
		"consumers": []string{"web-1/app"}, "retire_after_seconds": 600, "acknowledge_single_phase": true}
	if !reflect.DeepEqual(full, want) {
		t.Fatalf("retry body = %v, want %v", full, want)
	}
	plain, err := json.Marshal(secretRotationRetryBody(store.SecretStaticRotationCommand{Provider: "pg", Key: "k", OldRef: "role-a"}))
	if err != nil || string(plain) != `{"key":"k","old_ref":"role-a","provider":"pg"}` {
		t.Fatalf("plain retry body = %s, %v", plain, err)
	}
}
