// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestHistoryTenantDataRewriteContinuitySchemaIsPinnedToV1(t *testing.T) {
	event := events.Event{
		Type:          projections.EventHistoryTenantDataRewriteContinuity,
		SchemaVersion: 1,
	}
	if err := projections.ValidateSchemaVersion(event); err != nil {
		t.Fatalf("continuity schema v1 rejected: %v", err)
	}
	event.SchemaVersion = 2
	if err := projections.ValidateSchemaVersion(event); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("continuity schema v2 error = %v, want ErrUnknownSchemaVersion", err)
	}
}

func TestAuditArchivedSchemaRejectsLegacyNonGlobalCheckpointCoordinates(t *testing.T) {
	event := events.Event{
		Type:          audit.EventTypeArchived,
		SchemaVersion: audit.ArchivedEventSchemaVersion,
	}
	if err := projections.ValidateSchemaVersion(event); err != nil {
		t.Fatalf("audit.archived v%d rejected: %v", audit.ArchivedEventSchemaVersion, err)
	}
	event.SchemaVersion = 1
	if err := projections.ValidateSchemaVersion(event); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("legacy audit.archived v1 error = %v, want ErrUnknownSchemaVersion", err)
	}
}
