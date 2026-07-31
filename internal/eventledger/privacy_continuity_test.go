// SPDX-License-Identifier: MPL-2.0

package eventledger

import (
	"slices"
	"testing"
)

func TestF79EraseSubjectIncludesCommandAndSystemContinuityEvents(t *testing.T) {
	eventTypes, ok := EventTypesForFeatureAction("F79", "erase_subject")
	if !ok {
		t.Fatal("F79/erase_subject is absent from the event ledger")
	}
	for _, required := range []string{
		EventPrivacySubjectErased,
		EventHistoryTenantDataRewriteContinuity,
	} {
		if !slices.Contains(eventTypes, required) {
			t.Errorf("F79/erase_subject event types = %v; missing %q", eventTypes, required)
		}
	}
}
