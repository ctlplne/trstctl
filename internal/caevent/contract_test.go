// SPDX-License-Identifier: BUSL-1.1

package caevent

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/eventspec"
)

func TestCADependencyEventVersionsFailClosed(t *testing.T) {
	cases := []struct {
		eventType string
		versions  []int
	}{
		{EventCAIssuedCertificate, []int{0, 1, 2, 3}},
		{EventCAEndEntityIssued, []int{0, 1, 2, 3}},
		{EventCAAuthorityImported, []int{0, 1, 2}},
		{EventCAIntermediateCreated, []int{0, 1, 2}},
		{EventCAAuthorityRekeyed, []int{0, 1}},
		{EventCAIntermediateCSRIssued, []int{0, 1}},
		{EventCACrossSigned, []int{0, 1}},
	}
	for _, tc := range cases {
		if !IsDependencyEvent(tc.eventType) {
			t.Errorf("%s absent from signer CA dependency family", tc.eventType)
		}
		for version := 0; version <= 4; version++ {
			event := eventspec.Event{Type: tc.eventType, SchemaVersion: version, Sequence: 42}
			err := ValidateSchemaVersion(event)
			allowed := false
			for _, accepted := range tc.versions {
				allowed = allowed || accepted == version
			}
			if allowed && err != nil {
				t.Errorf("%s v%d rejected: %v", tc.eventType, version, err)
			}
			if !allowed && !errors.Is(err, ErrUnknownSchemaVersion) {
				t.Errorf("%s v%d: got %v, want unknown schema", tc.eventType, version, err)
			}
		}
	}
	if IsDependencyEvent("unrelated.created") {
		t.Fatal("unrelated event can add a CA dependent")
	}
}

func TestHistoricalCAInventoryIDsAreByteStable(t *testing.T) {
	event := eventspec.Event{TenantID: "11111111-1111-4111-8111-111111111111", ID: "mint-17"}
	if got, want := LegacyManagedCAInventoryID(event), "23f9147b-04e0-53f2-a106-04943c29731c"; got != want {
		t.Fatalf("managed legacy inventory ID = %s, want %s", got, want)
	}
	if got, want := SecretPKIInventoryID(event), "5f7b35b1-11ba-591d-8710-fa42b5eae2ec"; got != want {
		t.Fatalf("secret PKI inventory ID = %s, want %s", got, want)
	}
}
