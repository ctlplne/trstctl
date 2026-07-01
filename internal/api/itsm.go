package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
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

// ServiceNowBinding is an operator-approved ServiceNow egress binding. API callers
// can submit ticket content, but they cannot choose a new destination URL or
// credential reference at request time.
type ServiceNowBinding struct {
	InstanceURL          string   `json:"instance_url"`
	TokenRef             string   `json:"token_ref"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
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
		binding, err := a.approvedServiceNowBinding(req)
		if err != nil {
			return 0, nil, err
		}
		req.InstanceURL = binding.InstanceURL
		req.TokenRef = binding.TokenRef
		req.AllowPrivateEndpoint = binding.AllowPrivateEndpoint
		if req.AllowPrivateEndpoint {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
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
			PrivateEgressCIDRs:   append([]string(nil), binding.PrivateEgressCIDRs...),
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, toITSMTicketResponse(queued), nil
	})
}

func (a *API) approvedServiceNowBinding(req serviceNowTicketRequest) (ServiceNowBinding, error) {
	if len(a.serviceNowBindings) == 0 {
		return ServiceNowBinding{}, errStatus(http.StatusServiceUnavailable, "ServiceNow ITSM integration is not configured")
	}
	instanceURL, err := normalizeServiceNowInstanceURL(req.InstanceURL)
	if err != nil {
		return ServiceNowBinding{}, errStatus(http.StatusBadRequest, "instance_url must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	tokenRef := strings.TrimSpace(req.TokenRef)
	for _, raw := range a.serviceNowBindings {
		allowedURL, err := normalizeServiceNowInstanceURL(raw.InstanceURL)
		if err != nil {
			continue
		}
		if instanceURL == allowedURL &&
			tokenRef == strings.TrimSpace(raw.TokenRef) &&
			req.AllowPrivateEndpoint == raw.AllowPrivateEndpoint {
			privateCIDRs := cleanAPIStringList(raw.PrivateEgressCIDRs)
			if raw.AllowPrivateEndpoint {
				if len(privateCIDRs) == 0 {
					return ServiceNowBinding{}, errStatus(http.StatusServiceUnavailable, "operator-approved private ServiceNow binding has no private_egress_cidrs grant")
				}
				if err := validatePrivateEgressCIDRs(privateCIDRs); err != nil {
					return ServiceNowBinding{}, errStatus(http.StatusServiceUnavailable, err.Error())
				}
			}
			return ServiceNowBinding{
				InstanceURL:          allowedURL,
				TokenRef:             tokenRef,
				AllowPrivateEndpoint: raw.AllowPrivateEndpoint,
				PrivateEgressCIDRs:   privateCIDRs,
			}, nil
		}
	}
	return ServiceNowBinding{}, errStatus(http.StatusBadRequest, "instance_url, token_ref, and allow_private_endpoint must match an operator-approved ServiceNow binding")
}

func normalizeServiceNowInstanceURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errStatus(http.StatusBadRequest, "instance_url must use http or https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errStatus(http.StatusBadRequest, "instance_url must be an absolute URL without credentials, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func (a *API) requirePrivateEgressPermission(ctx context.Context, tenantID string) error {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok {
		return errStatus(http.StatusUnauthorized, "missing authenticated principal")
	}
	target := authz.Scope{TenantID: tenantID}
	if !principal.Can(authz.PrivateEgress, target) {
		return errStatus(http.StatusForbidden, "forbidden: requires "+string(authz.PrivateEgress))
	}
	return nil
}

func toITSMTicketResponse(q orchestrator.ITSMTicketQueued) itsmTicketResponse {
	return itsmTicketResponse{
		ID: q.ID, TenantID: q.TenantID, Provider: q.Provider, Destination: q.Destination,
		Table: q.Table, Status: q.Status, OutboxID: q.OutboxID, IdempotencyKey: q.IdempotencyKey,
		CreatedAt: q.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}
