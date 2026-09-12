// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/store"
)

// Retrying an append whose SQL projection rolled back is still the same failed
// renewal. A later renewal has a new lifecycle version and gets a new event.
func renewalFailureEventID(tenantID, identityID string, version uint64) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf(
		"renewal-failure-event\x00%s\x00%s\x00%d", tenantID, identityID, version,
	))).String()
}

// The identity lock supplies the owner and name at the failed transition. The
// alert deliberately omits raw CA/agent errors and credential material. Its v3
// side-effect bytes are retained in the event, including the receiver identity,
// so crash recovery never rebuilds an alert from mutable inventory.
func renewalFailureNotification(identity store.Identity, eventID string) ([]byte, error) {
	return json.Marshal(notify.Alert{
		Kind: notify.KindRenewalFailed, TenantID: identity.TenantID,
		OperationID: "renewal-failure:" + eventID,
		IdentityID:  identity.ID, Subject: identity.Name, OwnerID: identity.OwnerID,
		Severity: notify.AlertSeverityWarning,
		Detail:   "A renewal attempt failed. Check this identity's rotation history and retry status; a retry may still be queued. Verify the current listener certificate and its expiry. Identity: " + identity.ID,
	})
}

// Older failure events had no notification. The optional v3 side-effect record
// is the authority to send one; changing today's transition registry must not
// create alerts for historical failures during boot or privacy reconstruction.
func retainedLifecycleSideEffectFor(payload transitionPayload) (string, bool) {
	if payload.From == StateRenewing && payload.To == StateRenewalFailed && payload.SideEffect == nil {
		return "", false
	}
	return sideEffectFor(payload.From, payload.To)
}
