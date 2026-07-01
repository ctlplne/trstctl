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
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
)

const (
	DestinationResponseSplunk = "response.splunk"
	DestinationResponseJira   = "response.jira"
)

type ResponseIntegrationDispatch struct {
	ID               string                           `json:"id"`
	IncidentID       string                           `json:"incident_id,omitempty"`
	RemediationRunID string                           `json:"remediation_run_id,omitempty"`
	Title            string                           `json:"title"`
	Summary          string                           `json:"summary,omitempty"`
	Severity         string                           `json:"severity,omitempty"`
	CorrelationID    string                           `json:"correlation_id,omitempty"`
	EvidenceRefs     []string                         `json:"evidence_refs,omitempty"`
	Destinations     []ResponseIntegrationDestination `json:"destinations"`
	RequestedBy      string                           `json:"requested_by,omitempty"`
}

type ResponseIntegrationDestination struct {
	ID                   string   `json:"id,omitempty"`
	Provider             string   `json:"provider"`
	EndpointURL          string   `json:"endpoint_url,omitempty"`
	InstanceURL          string   `json:"instance_url,omitempty"`
	TokenRef             string   `json:"token_ref,omitempty"`
	ProjectKey           string   `json:"project_key,omitempty"`
	IssueType            string   `json:"issue_type,omitempty"`
	Table                string   `json:"table,omitempty"`
	Channel              string   `json:"channel,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type ResponseIntegrationPayload struct {
	DispatchID           string   `json:"dispatch_id"`
	TenantID             string   `json:"tenant_id"`
	Provider             string   `json:"provider"`
	EndpointURL          string   `json:"endpoint_url,omitempty"`
	TokenRef             string   `json:"token_ref,omitempty"`
	ProjectKey           string   `json:"project_key,omitempty"`
	IssueType            string   `json:"issue_type,omitempty"`
	Title                string   `json:"title"`
	Summary              string   `json:"summary,omitempty"`
	Severity             string   `json:"severity,omitempty"`
	CorrelationID        string   `json:"correlation_id,omitempty"`
	IncidentID           string   `json:"incident_id,omitempty"`
	RemediationRunID     string   `json:"remediation_run_id,omitempty"`
	EvidenceRefs         []string `json:"evidence_refs,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
}

type ResponseIntegrationQueued struct {
	ID             string                                 `json:"id"`
	TenantID       string                                 `json:"tenant_id"`
	Status         string                                 `json:"status"`
	IdempotencyKey string                                 `json:"idempotency_key"`
	CreatedAt      time.Time                              `json:"created_at"`
	Destinations   []ResponseIntegrationQueuedDestination `json:"destinations"`
}

type ResponseIntegrationQueuedDestination struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	Destination    string `json:"destination"`
	Status         string `json:"status"`
	OutboxID       int64  `json:"outbox_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

func NormalizeResponseIntegrationProvider(provider string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "splunk", "splunk-hec", "hec":
		return "splunk", true
	case "jira", "jira-cloud", "jira-software":
		return "jira", true
	case "slack":
		return "slack", true
	case "servicenow", "service-now", "snow":
		return "servicenow", true
	default:
		return "", false
	}
}

func (o *Orchestrator) DispatchResponseIntegrations(ctx context.Context, tenantID string, in ResponseIntegrationDispatch) (ResponseIntegrationQueued, error) {
	if o.outbox == nil {
		return ResponseIntegrationQueued{}, fmt.Errorf("orchestrator: response integration outbox is not configured")
	}
	req := normalizeResponseIntegrationDispatch(ctx, in)
	if len(req.Destinations) == 0 {
		return ResponseIntegrationQueued{}, fmt.Errorf("orchestrator: at least one response integration destination is required")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return ResponseIntegrationQueued{}, err
	}
	ev, err := o.log.Append(ctx, events.Event{Type: projections.EventResponseIntegrationDispatched, TenantID: tenantID, Data: payload})
	if err != nil {
		return ResponseIntegrationQueued{}, err
	}
	queued := ResponseIntegrationQueued{
		ID: req.ID, TenantID: tenantID, Status: "queued",
		IdempotencyKey: ev.ID, CreatedAt: ev.Time,
		Destinations: make([]ResponseIntegrationQueuedDestination, 0, len(req.Destinations)),
	}
	if err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		for _, dst := range req.Destinations {
			outboxDestination, body, err := responseIntegrationOutboxPayload(tenantID, req, dst)
			if err != nil {
				return err
			}
			key := ev.ID + ":" + dst.ID
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID:       tenantID,
				Destination:    outboxDestination,
				IdempotencyKey: key,
				Payload:        body,
			}); err != nil {
				return err
			}
			var outboxID int64
			if err := tx.QueryRow(ctx,
				`SELECT id
				   FROM outbox
				  WHERE tenant_id = $1
				    AND idempotency_key = $2`,
				tenantID, key).Scan(&outboxID); err != nil {
				return err
			}
			queued.Destinations = append(queued.Destinations, ResponseIntegrationQueuedDestination{
				ID: dst.ID, Provider: dst.Provider, Destination: outboxDestination,
				Status: "queued", OutboxID: outboxID, IdempotencyKey: key,
			})
		}
		return nil
	}); err != nil {
		return ResponseIntegrationQueued{}, err
	}
	return queued, nil
}

func normalizeResponseIntegrationDispatch(ctx context.Context, in ResponseIntegrationDispatch) ResponseIntegrationDispatch {
	out := ResponseIntegrationDispatch{
		ID:               strings.TrimSpace(in.ID),
		IncidentID:       strings.TrimSpace(in.IncidentID),
		RemediationRunID: strings.TrimSpace(in.RemediationRunID),
		Title:            strings.TrimSpace(in.Title),
		Summary:          strings.TrimSpace(in.Summary),
		Severity:         strings.ToLower(strings.TrimSpace(in.Severity)),
		CorrelationID:    strings.TrimSpace(in.CorrelationID),
		EvidenceRefs:     cleanStringList(in.EvidenceRefs),
		Destinations:     make([]ResponseIntegrationDestination, 0, len(in.Destinations)),
		RequestedBy:      strings.TrimSpace(in.RequestedBy),
	}
	if out.ID == "" {
		out.ID = uuid.NewString()
	}
	if out.CorrelationID == "" {
		out.CorrelationID = out.ID
	}
	if out.Severity == "" {
		out.Severity = notify.AlertSeverityWarning
	}
	if out.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			out.RequestedBy = actor.Subject
		}
	}
	for i, dst := range in.Destinations {
		provider, ok := NormalizeResponseIntegrationProvider(dst.Provider)
		if !ok {
			provider = strings.ToLower(strings.TrimSpace(dst.Provider))
		}
		id := strings.TrimSpace(dst.ID)
		if id == "" {
			id = fmt.Sprintf("%s-%d", provider, i+1)
		}
		out.Destinations = append(out.Destinations, ResponseIntegrationDestination{
			ID: id, Provider: provider, EndpointURL: strings.TrimSpace(dst.EndpointURL),
			InstanceURL: strings.TrimSpace(dst.InstanceURL), TokenRef: strings.TrimSpace(dst.TokenRef),
			ProjectKey: strings.TrimSpace(dst.ProjectKey), IssueType: strings.TrimSpace(dst.IssueType),
			Table: strings.TrimSpace(dst.Table), Channel: strings.TrimSpace(dst.Channel),
			AllowPrivateEndpoint: dst.AllowPrivateEndpoint,
			PrivateEgressCIDRs:   cleanStringList(dst.PrivateEgressCIDRs),
		})
	}
	return out
}

func responseIntegrationOutboxPayload(tenantID string, req ResponseIntegrationDispatch, dst ResponseIntegrationDestination) (string, []byte, error) {
	switch dst.Provider {
	case "splunk":
		return marshalResponseDestination(DestinationResponseSplunk, tenantID, req, dst)
	case "jira":
		return marshalResponseDestination(DestinationResponseJira, tenantID, req, dst)
	case "slack":
		body, err := json.Marshal(notify.Alert{
			Kind: notify.KindResponseIntegration, TenantID: tenantID, Subject: req.Title,
			Detail: req.Summary, Severity: req.Severity, RoutingPolicyID: dst.Channel,
		})
		return notify.DestinationResponse, body, err
	case "servicenow":
		table, ok := NormalizeServiceNowTable(dst.Table)
		if !ok {
			return "", nil, fmt.Errorf("orchestrator: unsupported ServiceNow table %q", dst.Table)
		}
		body, err := json.Marshal(ServiceNowTicketRequest{
			ID: req.ID + "-servicenow", InstanceURL: dst.InstanceURL, Table: table, TokenRef: dst.TokenRef,
			ShortDescription: req.Title, Description: req.Summary, Category: "security",
			Urgency: serviceNowPriority(req.Severity), Impact: serviceNowPriority(req.Severity),
			CorrelationID: req.CorrelationID, AllowPrivateEndpoint: dst.AllowPrivateEndpoint,
			PrivateEgressCIDRs: dst.PrivateEgressCIDRs,
			RequestedBy:        req.RequestedBy,
		})
		return DestinationITSMServiceNow, body, err
	default:
		return "", nil, fmt.Errorf("orchestrator: unsupported response integration provider %q", dst.Provider)
	}
}

func marshalResponseDestination(destination, tenantID string, req ResponseIntegrationDispatch, dst ResponseIntegrationDestination) (string, []byte, error) {
	body, err := json.Marshal(ResponseIntegrationPayload{
		DispatchID: req.ID, TenantID: tenantID, Provider: dst.Provider, EndpointURL: dst.EndpointURL,
		TokenRef: dst.TokenRef, ProjectKey: dst.ProjectKey, IssueType: dst.IssueType,
		Title: req.Title, Summary: req.Summary, Severity: req.Severity, CorrelationID: req.CorrelationID,
		IncidentID: req.IncidentID, RemediationRunID: req.RemediationRunID, EvidenceRefs: req.EvidenceRefs,
		AllowPrivateEndpoint: dst.AllowPrivateEndpoint, PrivateEgressCIDRs: dst.PrivateEgressCIDRs,
	})
	return destination, body, err
}

func serviceNowPriority(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "1"
	case "warning":
		return "2"
	default:
		return "3"
	}
}

func cleanStringList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
