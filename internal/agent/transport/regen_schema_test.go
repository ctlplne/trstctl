// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"encoding/json"
	"os"
	"testing"
)

// TestRegenerateAgentServiceSchema rewrites the committed wire contract from the
// live service descriptor. It is opt-in via TRSTCTL_REGEN_AGENT_SCHEMA=1 so the
// contract stays a ratchet: changing the wire is a deliberate act with a diff to
// review, not something a test run does behind your back.
func TestRegenerateAgentServiceSchema(t *testing.T) {
	if os.Getenv("TRSTCTL_REGEN_AGENT_SCHEMA") != "1" {
		t.Skip("set TRSTCTL_REGEN_AGENT_SCHEMA=1 to rewrite agent_service_schema.json")
	}
	current := currentAgentContract()
	raw, err := os.ReadFile("agent_service_schema.json")
	if err != nil {
		t.Fatalf("read committed schema: %v", err)
	}
	var existing map[string]any
	if err := json.Unmarshal(raw, &existing); err != nil {
		t.Fatalf("decode committed schema: %v", err)
	}
	next, err := json.Marshal(current)
	if err != nil {
		t.Fatalf("encode current contract: %v", err)
	}
	var merged map[string]any
	if err := json.Unmarshal(next, &merged); err != nil {
		t.Fatalf("decode current contract: %v", err)
	}
	if schema, ok := existing["$schema"]; ok {
		merged["$schema"] = schema
	}
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		t.Fatalf("encode merged schema: %v", err)
	}
	if err := os.WriteFile("agent_service_schema.json", append(out, '\n'), 0o644); err != nil { // #nosec G306 -- committed wire contract fixture, reviewed in the diff (CWE-276)
		t.Fatalf("write schema: %v", err)
	}
	t.Log("rewrote agent_service_schema.json")
}
