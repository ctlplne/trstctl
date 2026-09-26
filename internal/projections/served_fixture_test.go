// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// openRegisteredTenantLog supplies a real tenant lifecycle before server.Build
// projects it. An API token alone does not provision an active tenant. Keep
// openLog empty for projection tests that exercise their own event histories.
func openRegisteredTenantLog(t *testing.T) *events.Log {
	t.Helper()
	log := openLog(t)
	if _, err := log.Append(t.Context(), events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: time.Now().UTC(), Data: tenantRegistered("Acme"),
	}); err != nil {
		t.Fatalf("append serving tenant registration: %v", err)
	}
	return log
}
