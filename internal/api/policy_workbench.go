package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/policy"
)

const policyDryRunEventType = "policy.dry_run.evaluated"

type policyDryRunRequest struct {
	Kind       string         `json:"kind,omitempty"`
	Module     string         `json:"module,omitempty"`
	Input      map[string]any `json:"input,omitempty"`
	TraceLimit int            `json:"trace_limit,omitempty"`
}

type policyDryRunResponse struct {
	policy.DryRunResult
	InputSummary   policyDryRunInputSummary `json:"input_summary"`
	AuditEvent     string                   `json:"audit_event"`
	IdempotencyKey string                   `json:"idempotency_key"`
}

type policyDryRunInputSummary struct {
	Action     string `json:"action,omitempty"`
	Permission string `json:"permission,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Actor      string `json:"actor,omitempty"`
	TenantID   string `json:"tenant_id"`
}

//trstctl:mutation
func (a *API) dryRunPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.log == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "policy workbench event log is not configured")
		}
		principal, ok := a.principalFor(r)
		if !ok {
			return 0, nil, errStatus(http.StatusUnauthorized, "missing authenticated principal")
		}
		var req policyDryRunRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		input := normalizePolicyDryRunInput(req.Input, tenantID, principal.Subject)
		result, err := policy.DryRun(ctx, policy.DryRunConfig{
			Kind:       policy.DryRunKind(strings.TrimSpace(req.Kind)),
			Module:     req.Module,
			Input:      input,
			TraceLimit: req.TraceLimit,
		})
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		summary := summarizePolicyDryRunInput(input, tenantID)
		payload, err := json.Marshal(struct {
			Kind         policy.DryRunKind        `json:"kind"`
			Valid        bool                     `json:"valid"`
			ModuleSHA256 string                   `json:"module_sha256"`
			Allow        bool                     `json:"allow"`
			Deny         bool                     `json:"deny"`
			Reason       string                   `json:"reason,omitempty"`
			Error        string                   `json:"error,omitempty"`
			InputSummary policyDryRunInputSummary `json:"input_summary"`
			Idempotency  string                   `json:"idempotency_key"`
		}{
			Kind:         result.Kind,
			Valid:        result.Valid,
			ModuleSHA256: result.ModuleSHA256,
			Allow:        result.Allow,
			Deny:         result.Deny,
			Reason:       result.Reason,
			Error:        result.Error,
			InputSummary: summary,
			Idempotency:  idempotencyKey,
		})
		if err != nil {
			return 0, nil, err
		}
		if _, err := a.log.Append(ctx, events.Event{Type: policyDryRunEventType, TenantID: tenantID, Data: payload}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, policyDryRunResponse{
			DryRunResult:   result,
			InputSummary:   summary,
			AuditEvent:     policyDryRunEventType,
			IdempotencyKey: idempotencyKey,
		}, nil
	})
}

func normalizePolicyDryRunInput(in map[string]any, tenantID, actor string) map[string]any {
	out := policy.CloneInputMap(in)
	out["tenant_id"] = tenantID
	if _, ok := out["actor"].(string); !ok || strings.TrimSpace(actorString(out["actor"])) == "" {
		out["actor"] = actor
	}
	return out
}

func summarizePolicyDryRunInput(in map[string]any, tenantID string) policyDryRunInputSummary {
	return policyDryRunInputSummary{
		Action:     actorString(in["action"]),
		Permission: actorString(in["permission"]),
		Profile:    actorString(in["profile"]),
		Subject:    actorString(in["subject"]),
		Actor:      actorString(in["actor"]),
		TenantID:   tenantID,
	}
}

func actorString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
