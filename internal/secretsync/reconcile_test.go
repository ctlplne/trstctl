// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"testing"
)

// A lost delivery result resolves by reading the receiver back under the same
// operation ID: a matching value proves the command landed, a different value
// proves it did not, and neither path writes.
func TestVaultKVV2ReconcileOperationReadsBackWithoutWriting(t *testing.T) {
	token := []byte("vault-kv-reconcile-token")
	emulator := newVaultKVV2Emulator(t, token, "platform/team-a")
	emulator.seed("database", 4, map[string][]byte{"value": []byte("rotated-database-password")})
	pusher, err := NewVaultKVV2Pusher(VaultKVV2Config{
		Endpoint: emulator.server.URL, HTTPClient: emulator.server.Client(), Token: token,
		Mount: "team-secrets", PathPrefix: "apps", Field: "value", Namespace: "platform/team-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	target := NewVaultKVV2Target(pusher)
	if !target.CanReconcile() {
		t.Fatal("Vault KV v2 target must be able to read its receiver back")
	}
	state, err := target.ReconcileOperation(t.Context(), "sync-vault-lost-result", "database", []byte("rotated-database-password"))
	if err != nil || state != ReceiverStateMatches {
		t.Fatalf("matching readback = %q, %v; want matches", state, err)
	}
	state, err = target.ReconcileOperation(t.Context(), "sync-vault-lost-result", "database", []byte("some-other-password"))
	if err != nil || state != ReceiverStateDiffers {
		t.Fatalf("differing readback = %q, %v; want differs", state, err)
	}
	state, err = target.ReconcileOperation(t.Context(), "sync-vault-lost-result", "missing", []byte("rotated-database-password"))
	if err != nil || state != ReceiverStateDiffers {
		t.Fatalf("missing-path readback = %q, %v; want differs", state, err)
	}
	if emulator.writeCalls != 0 || emulator.writes != 0 {
		t.Fatalf("reconciliation wrote to the receiver: calls=%d writes=%d", emulator.writeCalls, emulator.writes)
	}
	if emulator.readCalls != 3 {
		t.Fatalf("reconciliation reads = %d, want one per readback", emulator.readCalls)
	}
	for i, got := range emulator.operationIDs {
		if got != "sync-vault-lost-result" {
			t.Fatalf("readback %d carried operation id %q", i+1, got)
		}
	}
	if _, err := target.ReconcileOperation(t.Context(), "", "database", []byte("x")); err == nil {
		t.Fatal("a readback without the durable operation id must be refused")
	}
	if generic := NewCITarget(&CIPusher{}); generic.CanReconcile() {
		t.Fatal("the generic CI JSON target cannot read its receiver back")
	}
}
