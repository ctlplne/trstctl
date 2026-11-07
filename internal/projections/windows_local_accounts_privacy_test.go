// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"encoding/json"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
)

func TestWindowsLocalAccountSourcesHaveClosedActorPrivacyA268(t *testing.T) {
	intent, err := hostaccounts.NewInventoryIntent("33333333-3333-4333-8333-333333333333", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	const subject = "local-account-operator@example.test"
	value := projections.WindowsLocalAccountScanQueued{Intent: intent, Actor: subject, At: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(raw, intent.TenantID, subject, projections.EventWindowsLocalAccountScanQueued, 1)
	var after projections.WindowsLocalAccountScanQueued
	if err != nil || !changed || json.Unmarshal(rewritten, &after) != nil || after.Actor == subject || after.Intent != value.Intent || !after.At.Equal(value.At) {
		t.Fatal("actor privacy changed exact host read authority or retained the actor", err)
	}
	for _, kind := range []string{projections.EventWindowsLocalAccountScanQueued, projections.EventWindowsLocalAccountScanObserved, projections.EventWindowsLocalAccountScanFailed} {
		if !events.HasPrivacyEventPolicy(kind, 1) {
			t.Fatal("native inventory source has no privacy policy", kind)
		}
		if _, _, err := events.PseudonymizeEventDataForSubject([]byte(`{"unregistered_subject_path":"local-account-operator@example.test"}`), intent.TenantID, subject, kind, 1); err == nil {
			t.Fatal("source accepted undeclared actor data", kind)
		}
		if events.HasPrivacyEventPolicy(kind, 2) {
			t.Fatal("unknown source version was registered without a concrete shape", kind)
		}
	}
}
