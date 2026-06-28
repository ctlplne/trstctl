package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

type serviceNowTicketRequest struct {
	InstanceURL          string `json:"instance_url"`
	Table                string `json:"table"`
	TokenRef             string `json:"token_ref"`
	ShortDescription     string `json:"short_description"`
	Description          string `json:"description"`
	Category             string `json:"category"`
	Urgency              string `json:"urgency"`
	Impact               string `json:"impact"`
	CorrelationID        string `json:"correlation_id"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
}

type itsmTicketResponse struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	Provider       string `json:"provider"`
	Destination    string `json:"destination"`
	Table          string `json:"table"`
	Status         string `json:"status"`
	OutboxID       int64  `json:"outbox_id"`
	IdempotencyKey string `json:"idempotency_key"`
	CreatedAt      string `json:"created_at"`
}

//trstctl:mutation
func (a *API) createServiceNowTicket(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var raw json.RawMessage
		if err := decodeJSON(r, &raw); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return 0, nil, errStatus(http.StatusBadRequest, "request body must be a JSON object")
		}
		if containsInlineSecret(obj) {
			return 0, nil, errStatus(http.StatusBadRequest, "request may contain credential references, not inline secret values")
		}
		var req serviceNowTicketRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid ServiceNow ticket request")
		}
		table, ok := orchestrator.NormalizeServiceNowTable(req.Table)
		if !ok {
			return 0, nil, errStatus(http.StatusBadRequest, "table must be incident, change_request, or sc_task")
		}
		if strings.TrimSpace(req.InstanceURL) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "instance_url is required")
		}
		if _, err := url.ParseRequestURI(strings.TrimSpace(req.InstanceURL)); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "instance_url must be an absolute URL")
		}
		if strings.TrimSpace(req.TokenRef) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "token_ref is required")
		}
		if strings.TrimSpace(req.ShortDescription) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "short_description is required")
		}
		queued, err := a.orch.RequestServiceNowTicket(ctx, tenantID, orchestrator.ServiceNowTicketRequest{
			InstanceURL:          req.InstanceURL,
			Table:                table,
			TokenRef:             req.TokenRef,
			ShortDescription:     req.ShortDescription,
			Description:          req.Description,
			Category:             req.Category,
			Urgency:              req.Urgency,
			Impact:               req.Impact,
			CorrelationID:        req.CorrelationID,
			AllowPrivateEndpoint: req.AllowPrivateEndpoint,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, toITSMTicketResponse(queued), nil
	})
}

func toITSMTicketResponse(q orchestrator.ITSMTicketQueued) itsmTicketResponse {
	return itsmTicketResponse{
		ID: q.ID, TenantID: q.TenantID, Provider: q.Provider, Destination: q.Destination,
		Table: q.Table, Status: q.Status, OutboxID: q.OutboxID, IdempotencyKey: q.IdempotencyKey,
		CreatedAt: q.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}
