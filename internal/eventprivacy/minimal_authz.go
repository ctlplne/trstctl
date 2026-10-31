// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

const EventAuthorizationDecision = "authz.decision"
const MinimalAuthzSchemaVersion = 2

// MinimalAuthzDecision records the outcome and compiled permission vocabulary.
// It deliberately omits actor, roles, request path, target, reason and payload.
// Omission is explicit; this record grants no permission or tenant service.
type MinimalAuthzDecision struct {
	Permission     string `json:"permission"`
	Decision       string `json:"decision"`
	DetailsOmitted string `json:"details_omitted"`
}

// Version 2 keeps this closed historical vocabulary even if roles change.
// Extend it deliberately; never delete a formerly admitted permission string.
var minimalAuthzPermissions = map[string]bool{
	"access:approve":       true,
	"access:read":          true,
	"access:role.assign":   true,
	"access:targets.write": true,
	"access:write":         true,
	"agents:heartbeat":     true,
	"agents:job.complete":  true,
	"agents:job.poll":      true,
	"agents:job.report":    true,
	"agents:read":          true,
	"agents:relay.grant":   true,
	"agents:write":         true,
	"approvals:review":     true,
	"audit:archive.read":   true,
	"audit:read":           true,
	"audit:write":          true,
	"capabilities:read":    true,
	"certs:issue":          true,
	"certs:read":           true,
	"certs:request":        true,
	"certs:write":          true,
	"connectors:read":      true,
	"connectors:write":     true,
	"discovery:read":       true,
	"discovery:write":      true,
	"egress:private":       true,
	"graph:read":           true,
	"identities:read":      true,
	"identities:write":     true,
	"incidents:game-day":   true,
	"incidents:read":       true,
	"incidents:write":      true,
	"issuers:read":         true,
	"issuers:write":        true,
	"keys:approve":         true,
	"keys:read":            true,
	"keys:write":           true,
	"lifecycle:read":       true,
	"nhi:read":             true,
	"notifications:read":   true,
	"notifications:write":  true,
	"owners:read":          true,
	"owners:write":         true,
	"policy:read":          true,
	"policy:write":         true,
	"privacy:read":         true,
	"privacy:write":        true,
	"profiles:read":        true,
	"profiles:write":       true,
	"risk:read":            true,
	"secrets:read":         true,
	"secrets:write":        true,
}

func minimalAuthzState(life Lifetime) string {
	if life.Request == nil {
		return ""
	}
	if life.Offboard != nil {
		return "tenant_offboarded"
	}
	if life.Request != nil && life.Activation == nil {
		return "key_preparing"
	}
	return ""
}

func ParseMinimalAuthzDecision(event events.Event) (MinimalAuthzDecision, error) {
	var body MinimalAuthzDecision
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil || event.Type != EventAuthorizationDecision || event.SchemaVersion != MinimalAuthzSchemaVersion || event.Actor != nil || event.Protection != nil || event.SensitiveErased || decodeControl(event.Data, &body) != nil {
		return MinimalAuthzDecision{}, ErrSource
	}
	if !minimalAuthzPermissions[body.Permission] || (body.Decision != "allow" && body.Decision != "deny") || (body.DetailsOmitted != "key_preparing" && body.DetailsOmitted != "tenant_offboarded") {
		return MinimalAuthzDecision{}, ErrSource
	}
	return body, nil
}

// MinimalAuthzEvent selects the closed alternate schema only when source state
// requires it. Active tenants retain ordinary encrypted detailed decisions;
// legacy tenants retain their original behavior. No custody-error fallback.
func (policy SourcePolicy) MinimalAuthzEvent(ctx context.Context, tenant, permission, decision string) (events.Event, bool, error) {
	life, err := policy.LatestLifetime(ctx, tenant)
	if err != nil {
		return events.Event{}, false, err
	}
	state := minimalAuthzState(life)
	if state == "" {
		return events.Event{}, false, nil
	}
	wire, err := json.Marshal(MinimalAuthzDecision{Permission: permission, Decision: decision, DetailsOmitted: state})
	if err != nil {
		return events.Event{}, false, err
	}
	event := events.Event{TenantID: tenant, Type: EventAuthorizationDecision, SchemaVersion: MinimalAuthzSchemaVersion, Data: wire}
	if _, err := ParseMinimalAuthzDecision(event); err != nil {
		return events.Event{}, false, err
	}
	return event, true, nil
}

func (admission SourceAdmission) minimalAuthzDecision(event events.Event, life Lifetime) (events.EventProtectionDecision, error) {
	body, err := ParseMinimalAuthzDecision(event)
	if err != nil || body.DetailsOmitted != minimalAuthzState(life) {
		return events.EventProtectionDecision{}, ErrSource
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionPublicControl}, nil
}
