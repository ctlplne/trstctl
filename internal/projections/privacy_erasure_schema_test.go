// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestPrivacySubjectErasedSchemaVersionsAreExplicit(t *testing.T) {
	for _, version := range []int{1, PrivacySubjectErasedEventSchemaVersion} {
		if err := ValidateSchemaVersion(events.Event{
			Type: EventPrivacySubjectErased, SchemaVersion: version,
		}); err != nil {
			t.Fatalf("privacy.subject.erased v%d: %v", version, err)
		}
	}
	if err := ValidateSchemaVersion(events.Event{
		Type:          EventPrivacySubjectErased,
		SchemaVersion: PrivacySubjectErasedEventSchemaVersion + 1,
	}); !errors.Is(err, ErrUnknownSchemaVersion) {
		t.Fatalf("future privacy.subject.erased schema error = %v, want ErrUnknownSchemaVersion", err)
	}
}
