// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/eventspec"
)

const EventHoldClearance = "tenant.event_protection.holds_cleared"

// HoldClearance contains only public coordinates for ONE immutable offboard
// cut. Admission must independently prove retained holds clear before first
// publication. This syntax alone grants no key removal or completed erasure.
type HoldClearance struct {
	Request eventprotect.DestructionRequest `json:"request"`
	// RetentionFloorUntil and RetentionFloorSeconds record the operator's
	// audit retention floor (OD-11) when it kept the tenant's key past the
	// tenant's own retention window: the key was kept until this time, the
	// floor after the offboard. Absent when the tenant's window was longer.
	RetentionFloorUntil   *time.Time `json:"retention_floor_until,omitempty"`
	RetentionFloorSeconds int64      `json:"retention_floor_seconds,omitempty"`
}

func HoldClearanceEventID(request eventprotect.DestructionRequest) string {
	return request.OperationID + ":holds-cleared"
}

func ParseHoldClearance(event eventspec.Event) (HoldClearance, error) {
	return parseHoldClearance(event, true)
}

func parseHoldClearance(event eventspec.Event, retained bool) (HoldClearance, error) {
	var body HoldClearance
	if event.Type != EventHoldClearance || event.SchemaVersion != 1 || event.Actor != nil || event.Protection != nil || event.SensitiveErased || decodeControl(event.Data, &body) != nil || body.Request.Validate() != nil {
		return HoldClearance{}, ErrSource
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil || tenant.String() != body.Request.Ref.TenantID || event.ID != HoldClearanceEventID(body.Request) || event.Time.Before(body.Request.OffboardedAt) || (retained && (event.Sequence == 0 || event.Sequence <= body.Request.OffboardSequence)) {
		return HoldClearance{}, ErrSource
	}
	if (body.RetentionFloorUntil == nil) != (body.RetentionFloorSeconds == 0) {
		return HoldClearance{}, ErrSource
	}
	if body.RetentionFloorUntil != nil {
		until := *body.RetentionFloorUntil
		if body.RetentionFloorSeconds < 0 || !until.Equal(body.Request.OffboardedAt.Add(time.Duration(body.RetentionFloorSeconds)*time.Second)) ||
			!until.After(body.Request.NotBefore) || (retained && event.Time.Before(until)) {
			return HoldClearance{}, ErrSource
		}
	}
	return body, nil
}
