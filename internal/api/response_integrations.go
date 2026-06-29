package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

type responseIntegrationDispatchRequest struct {
	IncidentID       string                                  `json:"incident_id"`
	RemediationRunID string                                  `json:"remediation_run_id"`
	Title            string                                  `json:"title"`
	Summary          string                                  `json:"summary"`
	Severity         string                                  `json:"severity"`
	CorrelationID    string                                  `json:"correlation_id"`
	EvidenceRefs     []string                                `json:"evidence_refs"`
	Destinations     []responseIntegrationDestinationRequest `json:"destinations"`
}

type responseIntegrationDestinationRequest struct {
	ID                   string `json:"id"`
	Provider             string `json:"provider"`
	EndpointURL          string `json:"endpoint_url"`
	InstanceURL          string `json:"instance_url"`
	TokenRef             string `json:"token_ref"`
	ProjectKey           string `json:"project_key"`
	IssueType            string `json:"issue_type"`
	Table                string `json:"table"`
	Channel              string `json:"channel"`
	AllowPrivateEndpoint bool   `json:"allow_private_endpoint"`
}

type responseIntegrationDispatchResponse struct {
	ID             string                                         `json:"id"`
	TenantID       string                                         `json:"tenant_id"`
	Status         string                                         `json:"status"`
	IdempotencyKey string                                         `json:"idempotency_key"`
	CreatedAt      string                                         `json:"created_at"`
	Destinations   []responseIntegrationQueuedDestinationResponse `json:"destinations"`
}

type responseIntegrationQueuedDestinationResponse struct {
	ID             string `json:"id"`
	Provider       string `json:"provider"`
	Destination    string `json:"destination"`
	Status         string `json:"status"`
	OutboxID       int64  `json:"outbox_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

//trstctl:mutation
func (a *API) dispatchResponseIntegrations(w http.ResponseWriter, r *http.Request) {
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
		var req responseIntegrationDispatchRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "invalid response integration dispatch request")
		}
		cmd, err := responseIntegrationDispatchCommand(req)
		if err != nil {
			return 0, nil, err
		}
		queued, err := a.orch.DispatchResponseIntegrations(ctx, tenantID, cmd)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, toResponseIntegrationDispatchResponse(queued), nil
	})
}

func responseIntegrationDispatchCommand(req responseIntegrationDispatchRequest) (orchestrator.ResponseIntegrationDispatch, error) {
	title := strings.TrimSpace(req.Title)
	if title == "" {
		return orchestrator.ResponseIntegrationDispatch{}, errStatus(http.StatusBadRequest, "title is required")
	}
	if len(req.Destinations) == 0 {
		return orchestrator.ResponseIntegrationDispatch{}, errStatus(http.StatusBadRequest, "at least one destination is required")
	}
	out := orchestrator.ResponseIntegrationDispatch{
		IncidentID: strings.TrimSpace(req.IncidentID), RemediationRunID: strings.TrimSpace(req.RemediationRunID),
		Title: title, Summary: strings.TrimSpace(req.Summary), Severity: strings.TrimSpace(req.Severity),
		CorrelationID: strings.TrimSpace(req.CorrelationID), EvidenceRefs: cleanAPIStringList(req.EvidenceRefs),
		Destinations: make([]orchestrator.ResponseIntegrationDestination, 0, len(req.Destinations)),
	}
	for i, raw := range req.Destinations {
		dst, err := responseIntegrationDestinationCommand(i, raw)
		if err != nil {
			return orchestrator.ResponseIntegrationDispatch{}, err
		}
		out.Destinations = append(out.Destinations, dst)
	}
	return out, nil
}

func responseIntegrationDestinationCommand(index int, raw responseIntegrationDestinationRequest) (orchestrator.ResponseIntegrationDestination, error) {
	provider, ok := orchestrator.NormalizeResponseIntegrationProvider(raw.Provider)
	if !ok {
		return orchestrator.ResponseIntegrationDestination{}, errStatus(http.StatusBadRequest, "destination provider must be splunk, jira, slack, or servicenow")
	}
	dst := orchestrator.ResponseIntegrationDestination{
		ID: strings.TrimSpace(raw.ID), Provider: provider, EndpointURL: strings.TrimSpace(raw.EndpointURL),
		InstanceURL: strings.TrimSpace(raw.InstanceURL), TokenRef: strings.TrimSpace(raw.TokenRef),
		ProjectKey: strings.TrimSpace(raw.ProjectKey), IssueType: strings.TrimSpace(raw.IssueType),
		Table: strings.TrimSpace(raw.Table), Channel: strings.TrimSpace(raw.Channel),
		AllowPrivateEndpoint: raw.AllowPrivateEndpoint,
	}
	if dst.ID == "" {
		dst.ID = provider + "-" + strconvI(index+1)
	}
	switch provider {
	case "splunk":
		if err := requireAbsoluteURL(dst.EndpointURL, "splunk endpoint_url"); err != nil {
			return orchestrator.ResponseIntegrationDestination{}, err
		}
		if dst.TokenRef == "" {
			return orchestrator.ResponseIntegrationDestination{}, errStatus(http.StatusBadRequest, "splunk token_ref is required")
		}
	case "jira":
		if err := requireAbsoluteURL(dst.EndpointURL, "jira endpoint_url"); err != nil {
			return orchestrator.ResponseIntegrationDestination{}, err
		}
		if dst.TokenRef == "" {
			return orchestrator.ResponseIntegrationDestination{}, errStatus(http.StatusBadRequest, "jira token_ref is required")
		}
		if dst.ProjectKey == "" {
			return orchestrator.ResponseIntegrationDestination{}, errStatus(http.StatusBadRequest, "jira project_key is required")
		}
		if dst.IssueType == "" {
			dst.IssueType = "Task"
		}
	case "servicenow":
		if err := requireAbsoluteURL(dst.InstanceURL, "servicenow instance_url"); err != nil {
			return orchestrator.ResponseIntegrationDestination{}, err
		}
		if dst.TokenRef == "" {
			return orchestrator.ResponseIntegrationDestination{}, errStatus(http.StatusBadRequest, "servicenow token_ref is required")
		}
		table, ok := orchestrator.NormalizeServiceNowTable(dst.Table)
		if !ok {
			return orchestrator.ResponseIntegrationDestination{}, errStatus(http.StatusBadRequest, "servicenow table must be incident, change_request, or sc_task")
		}
		dst.Table = table
	case "slack":
	}
	return dst, nil
}

func requireAbsoluteURL(value, label string) error {
	if strings.TrimSpace(value) == "" {
		return errStatus(http.StatusBadRequest, label+" is required")
	}
	if _, err := url.ParseRequestURI(value); err != nil {
		return errStatus(http.StatusBadRequest, label+" must be an absolute URL")
	}
	return nil
}

func cleanAPIStringList(in []string) []string {
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

func toResponseIntegrationDispatchResponse(q orchestrator.ResponseIntegrationQueued) responseIntegrationDispatchResponse {
	resp := responseIntegrationDispatchResponse{
		ID: q.ID, TenantID: q.TenantID, Status: q.Status, IdempotencyKey: q.IdempotencyKey,
		CreatedAt:    q.CreatedAt.UTC().Format(time.RFC3339Nano),
		Destinations: make([]responseIntegrationQueuedDestinationResponse, 0, len(q.Destinations)),
	}
	for _, dst := range q.Destinations {
		resp.Destinations = append(resp.Destinations, responseIntegrationQueuedDestinationResponse{
			ID: dst.ID, Provider: dst.Provider, Destination: dst.Destination, Status: dst.Status,
			OutboxID: dst.OutboxID, IdempotencyKey: dst.IdempotencyKey,
		})
	}
	return resp
}

func strconvI(n int) string {
	return strconv.FormatInt(int64(n), 10)
}
