// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Closing an incident (P13). The closure is recorded once; when the operator
// names the approved ServiceNow binding, the same tenant transaction queues one
// resolution of the ServiceNow incident its response dispatch opened, found by
// the incident's correlation ID.

// DestinationITSMServiceNowClose resolves a ServiceNow incident for a closed
// trstctl incident.
const DestinationITSMServiceNowClose = "itsm.servicenow.close"

// ErrIncidentAlreadyClosed refuses a second, different closure.
var ErrIncidentAlreadyClosed = errors.New("orchestrator: the incident is already closed")

// ServiceNowCloseRequest is metadata and references only, like ticket creation.
type ServiceNowCloseRequest struct {
	IncidentID           string   `json:"incident_id"`
	InstanceURL          string   `json:"instance_url"`
	Table                string   `json:"table"`
	TokenRef             string   `json:"token_ref"`
	CorrelationID        string   `json:"correlation_id"`
	CloseNotes           string   `json:"close_notes"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

// IncidentCorrelationID is the correlation a trstctl incident's ServiceNow
// tickets carry.
func IncidentCorrelationID(incidentID string) string { return "trstctl:incident:" + incidentID }

// ServiceNowCloseKey is the outbox key of an incident's resolution.
func ServiceNowCloseKey(incidentID string) string { return "servicenow-close:" + incidentID }

// CloseIncident records an incident's closure and, with close set, queues the
// ServiceNow resolution in the same transaction. Closing it again the same way
// changes nothing; closing it again differently is refused.
func (o *Orchestrator) CloseIncident(ctx context.Context, tenantID string, closed projections.IncidentClosed, close *ServiceNowCloseRequest) error {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return errors.New("incident closure is not configured")
	}
	closed.ServiceNow = close != nil
	raw, err := json.Marshal(closed)
	if err != nil {
		return err
	}
	var payload []byte
	if close != nil {
		if close.IncidentID != closed.IncidentID || close.CorrelationID != IncidentCorrelationID(closed.IncidentID) {
			return errors.New("orchestrator: the ServiceNow resolution names another incident")
		}
		if payload, err = json.Marshal(close); err != nil {
			return err
		}
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("incident-closed\x00"+tenantID+"\x00"+closed.IncidentID)).String()
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, id)
		if err != nil {
			return err
		}
		if found {
			var prior projections.IncidentClosed
			if json.Unmarshal(canonical.Data, &prior) != nil || prior != closed {
				return ErrIncidentAlreadyClosed
			}
		} else {
			canonical, err = o.log.Append(ctx, events.Event{ID: id, TenantID: tenantID, Type: projections.EventIncidentClosed, Data: raw})
			if err != nil {
				return err
			}
		}
		if canonical.ID != id || canonical.Type != projections.EventIncidentClosed || canonical.TenantID != tenantID {
			return fmt.Errorf("%w: incident closure changed", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		if close == nil {
			return nil
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationITSMServiceNowClose,
			IdempotencyKey: ServiceNowCloseKey(closed.IncidentID), Payload: payload})
		return err
	})
}
