// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
)

// OrdinaryCoreEvent identifies the tenant-scoped core events whose read model
// can be staged before publication and confined to one tenant during replay.
// Key custody, tenant lifecycle, and audit authority use separate admission.
func OrdinaryCoreEvent(event events.Event) bool {
	if _, err := uuid.Parse(event.TenantID); err != nil {
		return false
	}
	return !events.SealedBearingEvent(event) &&
		CoreEventTypeKnown(event.Type) &&
		!events.RequiresExclusiveKeyStateAdmission(event.Type) &&
		event.Type != audit.EventTypeArchived &&
		event.Type != EventTenantRegistered &&
		event.Type != EventTenantOffboarded &&
		event.Type != EventTenantEventProtectionRequested &&
		event.Type != EventTenantEventProtectionActivated &&
		event.Type != EventTenantEventProtectionHoldsCleared &&
		event.Type != EventTenantEventProtectionDestroyed
}
