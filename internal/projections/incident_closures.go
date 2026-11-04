// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventIncidentClosed is an incident closed in trstctl (P13).
const EventIncidentClosed = "incident.execution.closed"

// IncidentClosed is the payload of incident.execution.closed.
type IncidentClosed struct {
	IncidentID string `json:"incident_id"`
	Resolution string `json:"resolution"`
	ClosedBy   string `json:"closed_by"`
	ServiceNow bool   `json:"servicenow,omitempty"`
}

func init() {
	knownSchemaVersions[EventIncidentClosed] = map[int]bool{1: true}
}

func (p *Projector) applyIncidentClosedTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventIncidentClosed {
		return false, nil
	}
	var c IncidentClosed
	if err := json.Unmarshal(e.Data, &c); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if c.IncidentID == "" || c.Resolution == "" || c.ClosedBy == "" {
		return true, errors.New("projections: an incident closure needs the incident, a resolution and who closed it")
	}
	return true, p.store.ApplyIncidentClosedTx(ctx, tx, e.TenantID, store.IncidentClosure{IncidentID: c.IncidentID,
		Resolution: c.Resolution, ClosedBy: c.ClosedBy, ServiceNow: c.ServiceNow, ClosedAt: e.Time}, e.Sequence)
}

func addIncidentClosedPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	policies[privacyEventPolicyKey{EventIncidentClosed, 1}] = privacyRules(
		privacyRule("/incident_id", events.PrivacyFieldOpaqueExact), privacyRule("/resolution", events.PrivacyFieldFreeTextClear),
		privacyRule("/closed_by", events.PrivacyFieldIdentityExact), privacyRule("/servicenow", events.PrivacyFieldOpaqueExact))
}

func addIncidentClosedPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventIncidentClosed, 1}] = privacyPayloadShape[IncidentClosed]()
}
