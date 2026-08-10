// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/events"
)

const (
	defaultProviderActivityLimit = 100
	maxProviderActivityLimit     = 250
)

// ProviderActivity is the deliberately narrow operator-visible evidence view
// of one immutable Provider authority event. It excludes command bindings and
// tenant snapshots: operators can see who changed authority and when without a
// history endpoint becoming a second way around break-glass data controls.
type ProviderActivity struct {
	Sequence      uint64    `json:"sequence"`
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	TenantID      string    `json:"tenant_id,omitempty"`
	OperatorID    string    `json:"operator_id,omitempty"`
	OperatorEmail string    `json:"operator_email,omitempty"`
	GrantID       string    `json:"grant_id,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	At            time.Time `json:"at"`
}

// ActivitySource reads the authority evidence view from immutable history.
// The Service applies current delegation scope before any item is served.
type ActivitySource interface {
	ProviderActivity(context.Context) ([]ProviderActivity, error)
}

type eventLogActivitySource struct {
	log *events.Log
}

// NewEventLogActivitySource derives Provider activity from the same append-only
// history that owns the relational authority views. It creates no parallel
// audit table and cannot drift from state.
func NewEventLogActivitySource(log *events.Log) ActivitySource {
	return eventLogActivitySource{log: log}
}

func (s eventLogActivitySource) ProviderActivity(ctx context.Context) ([]ProviderActivity, error) {
	if s.log == nil {
		return nil, errors.New("provider: activity event log is not configured")
	}
	out := []ProviderActivity{}
	err := s.log.Replay(ctx, 0, func(event events.Event) error {
		if !providerActivityEvent(event.Type) {
			return nil
		}
		audit := decodeProviderAudit(event)
		tenantID := audit.TenantID
		if tenantID == "" {
			tenantID = event.TenantID
		}
		typ := audit.Type
		if typ == "" {
			typ = event.Type
		}
		at := audit.At
		if at.IsZero() {
			at = event.Time
		}
		out = append(out, ProviderActivity{
			Sequence: event.Sequence, EventID: event.ID, Type: typ, TenantID: tenantID,
			OperatorID: audit.OperatorID, OperatorEmail: audit.OperatorEmail,
			GrantID: audit.GrantID, Subject: audit.Subject, Reason: audit.Reason, At: at.UTC(),
		})
		return nil
	})
	return out, err
}

func decodeProviderAudit(event events.Event) AuditEvent {
	var authority AuthorityEvent
	if json.Unmarshal(event.Data, &authority) == nil && authority.Audit.Type != "" {
		return authority.Audit
	}
	// Before Provider authority became a single result event, its best-effort
	// audit append stored AuditEvent directly. Keep that historical evidence
	// visible during upgrades without treating it as rebuildable state.
	var legacy AuditEvent
	_ = json.Unmarshal(event.Data, &legacy)
	return legacy
}

func providerActivityEvent(typ string) bool {
	return providerAuthorityEvent(typ) || typ == "provider.isolation.drill"
}
