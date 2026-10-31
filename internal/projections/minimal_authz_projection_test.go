// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestMinimalAuthorizationAuditHasExplicitVersionRegistration(t *testing.T) {
	for _, version := range []int{0, 1, eventprivacy.MinimalAuthzSchemaVersion} {
		if err := projections.ValidateSchemaVersion(events.Event{Type: eventprivacy.EventAuthorizationDecision, SchemaVersion: version}); err != nil {
			t.Fatal(err)
		}
	}
	if err := projections.ValidateSchemaVersion(events.Event{Type: eventprivacy.EventAuthorizationDecision, SchemaVersion: 3}); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatal("unknown authorization audit schema was silently accepted")
	}
}
