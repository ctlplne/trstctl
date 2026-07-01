package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

const (
	// EventITSMTicketRequested records a served operator request to open an ITSM
	// ticket for a credential workflow. The event is the durable audit fact; the
	// outbox row is the external ServiceNow Table API side effect (AN-2 + AN-6).
	EventITSMTicketRequested = "itsm.ticket.requested"
	// DestinationITSMServiceNow is the first-party outbox destination for ServiceNow
	// Table API ticket creation.
	DestinationITSMServiceNow = "itsm.servicenow"
)

// ServiceNowTicketRequest is metadata/reference-only. The bearer token is named
// by TokenRef and resolved by the outbox worker immediately before egress; it is
// never stored in the event log or outbox payload.
type ServiceNowTicketRequest struct {
	ID                   string   `json:"id"`
	InstanceURL          string   `json:"instance_url"`
	Table                string   `json:"table"`
	TokenRef             string   `json:"token_ref"`
	ShortDescription     string   `json:"short_description"`
	Description          string   `json:"description,omitempty"`
	Category             string   `json:"category,omitempty"`
	Urgency              string   `json:"urgency,omitempty"`
	Impact               string   `json:"impact,omitempty"`
	CorrelationID        string   `json:"correlation_id,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	RequestedBy          string   `json:"requested_by,omitempty"`
}

// ITSMTicketQueued is the API-facing receipt for a ticket request whose external
// call has been durably queued.
type ITSMTicketQueued struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Provider       string    `json:"provider"`
	Destination    string    `json:"destination"`
	Table          string    `json:"table"`
	Status         string    `json:"status"`
	OutboxID       int64     `json:"outbox_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	CreatedAt      time.Time `json:"created_at"`
}

// NormalizeServiceNowTable returns the supported ServiceNow table name. An empty
// table means the standard incident table.
func NormalizeServiceNowTable(table string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(table)) {
	case "", "incident":
		return "incident", true
	case "change_request":
		return "change_request", true
	case "sc_task":
		return "sc_task", true
	default:
		return "", false
	}
}

// RequestServiceNowTicket records the ticket request as an immutable event and
// enqueues the ServiceNow call in the same tenant-scoped transaction. A crash
// after append but before enqueue is healed by ReconcileOutbox, keyed by event ID.
func (o *Orchestrator) RequestServiceNowTicket(ctx context.Context, tenantID string, in ServiceNowTicketRequest) (ITSMTicketQueued, error) {
	table, ok := NormalizeServiceNowTable(in.Table)
	if !ok {
		return ITSMTicketQueued{}, fmt.Errorf("orchestrator: unsupported ServiceNow table %q", in.Table)
	}
	req := ServiceNowTicketRequest{
		ID:                   strings.TrimSpace(in.ID),
		InstanceURL:          strings.TrimSpace(in.InstanceURL),
		Table:                table,
		TokenRef:             strings.TrimSpace(in.TokenRef),
		ShortDescription:     strings.TrimSpace(in.ShortDescription),
		Description:          strings.TrimSpace(in.Description),
		Category:             strings.TrimSpace(in.Category),
		Urgency:              strings.TrimSpace(in.Urgency),
		Impact:               strings.TrimSpace(in.Impact),
		CorrelationID:        strings.TrimSpace(in.CorrelationID),
		AllowPrivateEndpoint: in.AllowPrivateEndpoint,
		PrivateEgressCIDRs:   cleanStringList(in.PrivateEgressCIDRs),
		RequestedBy:          strings.TrimSpace(in.RequestedBy),
	}
	if req.ID == "" {
		req.ID = uuid.NewString()
	}
	if req.CorrelationID == "" {
		req.CorrelationID = req.ID
	}
	if req.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			req.RequestedBy = actor.Subject
		}
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return ITSMTicketQueued{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: EventITSMTicketRequested, TenantID: tenantID, Data: payload})
	if err != nil {
		return ITSMTicketQueued{}, err
	}
	var outboxID int64
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID:       tenantID,
			Destination:    DestinationITSMServiceNow,
			IdempotencyKey: ev.ID,
			Payload:        payload,
		}); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT id
			   FROM outbox
			  WHERE tenant_id = $1
			    AND idempotency_key = $2`,
			tenantID, ev.ID).Scan(&outboxID)
	}); err != nil {
		return ITSMTicketQueued{}, err
	}
	return ITSMTicketQueued{
		ID: req.ID, TenantID: tenantID, Provider: "servicenow",
		Destination: DestinationITSMServiceNow, Table: req.Table, Status: "queued",
		OutboxID: outboxID, IdempotencyKey: ev.ID, CreatedAt: ev.Time,
	}, nil
}
