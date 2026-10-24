// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"encoding/json"
	"testing"
)

// A104: schema v3 carries the pinned agent's role, so a remote Envoy's
// rollback returns to the network relay that recorded its predecessor.
func TestTLSRollbackRequestedProducerBindsAgentAndRoleInSchemaV3(t *testing.T) {
	sealed := json.RawMessage(`{"sealed":"ciphertext-fixture"}`)
	event, err := newTLSRollbackRequestedEvent("tenant-a", "run-a", []sealedTLSRollbackIntent{{
		TargetID: "target-a", AssetIDs: []string{"asset-a"}, IdempotencyKey: "rollback-a",
		Payload: sealed, RequiredAgentID: "agent-a", RequiredAgentRole: "network",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != eventTLSRollbackRequested || event.SchemaVersion != 3 || event.TenantID != "tenant-a" {
		t.Fatalf("agent rollback event envelope = %+v", event)
	}
	var command tlsRollbackRequested
	if err := json.Unmarshal(event.Data, &command); err != nil {
		t.Fatal(err)
	}
	if command.RunID != "run-a" || len(command.Intents) != 1 ||
		command.Intents[0].RequiredAgentID != "agent-a" || command.Intents[0].RequiredAgentRole != "network" ||
		string(command.Intents[0].Payload) != string(sealed) {
		t.Fatalf("host assignment or sealed payload lost: %+v", command)
	}
}
