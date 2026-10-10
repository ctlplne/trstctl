// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"encoding/json"
	"testing"
)

func TestTLSRollbackRequestedProducerBindsHostAssignmentInSchemaV2(t *testing.T) {
	sealed := json.RawMessage(`{"sealed":"ciphertext-fixture"}`)
	event, err := newTLSRollbackRequestedEvent("tenant-a", "run-a", []sealedTLSRollbackIntent{{
		TargetID: "target-a", AssetIDs: []string{"asset-a"}, IdempotencyKey: "rollback-a",
		Payload: sealed, RequiredAgentID: "agent-a",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != eventTLSRollbackRequested || event.SchemaVersion != 2 || event.TenantID != "tenant-a" {
		t.Fatalf("host rollback event envelope = %+v", event)
	}
	var command tlsRollbackRequested
	if err := json.Unmarshal(event.Data, &command); err != nil {
		t.Fatal(err)
	}
	if command.RunID != "run-a" || len(command.Intents) != 1 ||
		command.Intents[0].RequiredAgentID != "agent-a" ||
		string(command.Intents[0].Payload) != string(sealed) {
		t.Fatalf("host assignment or sealed payload lost: %+v", command)
	}
}
