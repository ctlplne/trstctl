// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestAuditArchivedSchemaVersionFailsClosed(t *testing.T) {
	known := events.Event{
		Type: audit.EventTypeArchived, SchemaVersion: audit.ArchivedEventSchemaVersion,
	}
	if err := projections.ValidateSchemaVersion(known); err != nil {
		t.Fatalf("audit.archived v%d: %v", audit.ArchivedEventSchemaVersion, err)
	}
	legacy := events.Event{Type: audit.EventTypeArchived, SchemaVersion: 1}
	if err := projections.ValidateSchemaVersion(legacy); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("audit.archived v1 error = %v, want ErrUnknownSchemaVersion", err)
	}
}
