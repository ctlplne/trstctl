// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

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
func renewalFailureNotification(identity store.Identity, eventID string, evidence store.RenewalFailureContext) ([]byte, error) {
	alert := notify.Alert{
		Kind: notify.KindRenewalFailed, TenantID: identity.TenantID,
		OperationID: "renewal-failure:" + eventID,
		IdentityID:  identity.ID, Subject: identity.Name, OwnerID: identity.OwnerID,
		Severity:  notify.AlertSeverityWarning,
		Detail:    "A renewal attempt failed. Check this identity's rotation history and retry status; a retry may still be queued. Open /identities?identity=" + identity.ID + ". Verify the current listener certificate and its expiry.",
		OwnerName: evidence.OwnerName, OwnerEmail: evidence.OwnerEmail,
		CertificateID: evidence.CertificateID, Serial: evidence.Serial,
		CertificateFingerprint: evidence.Fingerprint, DeploymentReceiptID: evidence.ReceiptID,
		DeploymentRecordedAt: evidence.RecordedAt,
	}
	if evidence.RecordedAt != nil {
		alert.Detail += " Last completed deployment or rollback recorded at " + evidence.RecordedAt.UTC().Format(time.RFC3339) + ", fingerprint " + evidence.Fingerprint + "."
		if evidence.NotAfter != nil {
			alert.NotAfter = *evidence.NotAfter
			alert.Detail += " That certificate expires at " + evidence.NotAfter.UTC().Format(time.RFC3339) + "."
		}
		alert.Detail += " This is historical evidence, not a current listener check."
	}
	return json.Marshal(alert)
}

// A duplicate append returns the first retained event. After a SQL rollback,
// owner/inventory observations may have changed; only those alert bytes may
// differ. Keep all command and side-effect bindings exact, including unknown
// fields, and deliver the original event's snapshot. Do not read all history on
// every failure or relax the collision check for other lifecycle transitions.
func sameRenewalFailureWithRetainedAlert(expected, retained []byte, tenantID, identityID, eventID string) bool {
	var a, b map[string]any
	if json.Unmarshal(expected, &a) != nil || json.Unmarshal(retained, &b) != nil {
		return false
	}
	ax, ok := a["side_effect"].(map[string]any)
	if !ok {
		return false
	}
	bx, ok := b["side_effect"].(map[string]any)
	if !ok {
		return false
	}
	encoded, ok := bx["payload"].(string)
	if !ok {
		return false
	}
	var payload []byte
	raw, _ := json.Marshal(encoded)
	if json.Unmarshal(raw, &payload) != nil {
		return false
	}
	var alert notify.Alert
	if json.Unmarshal(payload, &alert) != nil || alert.TenantID != tenantID || alert.IdentityID != identityID ||
		alert.Kind != notify.KindRenewalFailed || alert.OperationID != "renewal-failure:"+eventID {
		return false
	}
	ax["payload"] = bx["payload"]
	return reflect.DeepEqual(a, b)
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
