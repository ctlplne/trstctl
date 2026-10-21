// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/succession"
	_ "trstctl.com/trstctl/internal/succession/orchestrator"
)

// The finding policy is registered by this package; a pseudonymized finding
// must still decode with its free-text reason cleared.
func TestSuccessionFindingRewriteStillDecodes(t *testing.T) {
	const subject = "operator@example.test"
	event, err := succession.Encode(succession.FindingV1{
		IdentityID: "identity-a", TenantID: "tenant-a", Epoch: 1,
		Algorithm: "rsa", Reason: "reported by " + subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(
		event.Data, event.TenantID, subject, event.Type, event.SchemaVersion,
	)
	if err != nil || !changed || bytes.Contains(rewritten, []byte(subject)) {
		t.Fatalf("succession rewrite changed=%t err=%v data=%s", changed, err, rewritten)
	}
	decoded, err := succession.Decode(eventspec.Event{
		Type: event.Type, TenantID: event.TenantID, SchemaVersion: event.SchemaVersion, Data: rewritten,
	})
	if err != nil {
		t.Fatalf("rewritten succession finding no longer decodes: %v", err)
	}
	finding, ok := decoded.(succession.FindingV1)
	if !ok || finding.Reason != "" {
		t.Fatalf("succession finding rewrite = %#v", decoded)
	}
}
