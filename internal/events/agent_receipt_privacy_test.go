// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAgentReceiptPrivacyPreservesSignedEvidenceAndClosedSchema(t *testing.T) {
	const eventType = "agent.job.receipt.reconciled"
	payload := map[string]any{"agent": "signed-agent", "job_id": 1, "kind": "endpoint.verify", "attempt": 1, "outcome": "failed", "current_state_applied": false,
		"receipt_statement": "agent=signed-agent\n", "receipt_signature": "public-signature", "receipt_signer_fingerprint": "public-fingerprint"}
	encode := func() []byte {
		t.Helper()
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := encode()
	if err := validateRegisteredPrivacyEventPayload(valid, eventType, 1); err != nil {
		t.Fatal(err)
	}
	if out, changed, err := applyRegisteredPrivacyEventPolicy(valid, "tenant", "unrelated-person", eventType, 1); err != nil || changed || !bytes.Equal(out, valid) {
		t.Fatalf("unrelated erasure changed signed evidence: %v %v", changed, err)
	}
	if _, changed, err := applyRegisteredPrivacyEventPolicy(valid, "tenant", "signed-agent", eventType, 1); err == nil || changed {
		t.Fatal("subject rewrite silently invalidated the agent signature")
	}
	payload["new_field"] = "undeclared"
	if err := validateRegisteredPrivacyEventPayload(encode(), eventType, 1); err == nil {
		t.Fatal("same-version schema expansion accepted")
	}
	delete(payload, "new_field")
	delete(payload, "receipt_signature")
	if err := validateRegisteredPrivacyEventPayload(encode(), eventType, 1); err == nil {
		t.Fatal("missing signature accepted")
	}
	if err := validateRegisteredPrivacyEventPayload(valid, eventType, 2); err == nil {
		t.Fatal("unregistered version accepted")
	}
}
