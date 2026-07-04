// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type mdmSCEPPolicyRequest struct {
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	SCEPProfile      string          `json:"scep_profile"`
	SCEPEndpoint     string          `json:"scep_endpoint"`
	ExpectedAudience string          `json:"expected_audience,omitempty"`
	ChallengeMode    string          `json:"challenge_mode,omitempty"`
	TrustAnchorRefs  json.RawMessage `json:"trust_anchor_refs,omitempty"`
	ProfileGuidance  json.RawMessage `json:"profile_guidance,omitempty"`
	Enabled          *bool           `json:"enabled,omitempty"`
}

type mdmSCEPPolicyResponse struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	SCEPProfile      string          `json:"scep_profile"`
	SCEPEndpoint     string          `json:"scep_endpoint"`
	ExpectedAudience string          `json:"expected_audience,omitempty"`
	ChallengeMode    string          `json:"challenge_mode"`
	TrustAnchorRefs  json.RawMessage `json:"trust_anchor_refs"`
	ProfileGuidance  json.RawMessage `json:"profile_guidance"`
	Enabled          bool            `json:"enabled"`
	RotationVersion  int             `json:"rotation_version"`
	LastRotatedAt    string          `json:"last_rotated_at,omitempty"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

type mdmSCEPPolicyListResponse struct {
	Items []mdmSCEPPolicyResponse `json:"items"`
}

type mdmSCEPTelemetryResponse struct {
	Allowed            int    `json:"allowed"`
	Denied             int    `json:"denied"`
	ReplayRejected     int    `json:"replay_rejected"`
	LastFailureReason  string `json:"last_failure_reason,omitempty"`
	LastTransactionID  string `json:"last_transaction_id,omitempty"`
	LastEventTimestamp string `json:"last_event_timestamp,omitempty"`
}

type mdmSCEPStatusResponse struct {
	RuntimeGate string                   `json:"runtime_gate"`
	RuntimeNote string                   `json:"runtime_note"`
	Telemetry   mdmSCEPTelemetryResponse `json:"telemetry"`
	Policies    []mdmSCEPPolicyResponse  `json:"policies"`
}

type mdmSCEPChallengeRotatedResponse struct {
	Policy mdmSCEPPolicyResponse `json:"policy"`
}

//trstctl:mutation
func (a *API) createMDMSCEPPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeMDMSCEPPolicyRequest(r)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.emitMDMSCEPPolicy(ctx, tenantID, id, req, 1); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetMDMSCEPPolicy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toMDMSCEPPolicyResponse(rec), nil
	})
}

func (a *API) listMDMSCEPPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	recs, err := a.store.ListMDMSCEPPolicies(r.Context(), tenantID)
	if err != nil {
		a.writeMDMSCEPError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, mdmSCEPPolicyListResponse{Items: toMDMSCEPPolicyResponses(recs)})
}

func (a *API) getMDMSCEPPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rec, err := a.store.GetMDMSCEPPolicy(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeMDMSCEPError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toMDMSCEPPolicyResponse(rec))
}

//trstctl:mutation
func (a *API) updateMDMSCEPPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		existing, err := a.store.GetMDMSCEPPolicy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		req, err := decodeMDMSCEPPolicyRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if err := a.emitMDMSCEPPolicy(ctx, tenantID, id, req, existing.RotationVersion); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetMDMSCEPPolicy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toMDMSCEPPolicyResponse(rec), nil
	})
}

//trstctl:mutation
func (a *API) deleteMDMSCEPPolicy(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetMDMSCEPPolicy(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.MDMSCEPPolicyDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectMDMSCEP(ctx, tenantID, projections.EventMDMSCEPPolicyDeleted, payload); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) rotateMDMSCEPChallenge(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		existing, err := a.store.GetMDMSCEPPolicy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		nextVersion := existing.RotationVersion + 1
		payload, err := json.Marshal(projections.MDMSCEPChallengeRotated{ID: id, RotationVersion: nextVersion})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectMDMSCEP(ctx, tenantID, projections.EventMDMSCEPChallengeRotated, payload); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetMDMSCEPPolicy(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, mdmSCEPChallengeRotatedResponse{Policy: toMDMSCEPPolicyResponse(rec)}, nil
	})
}

func (a *API) getMDMSCEPStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	recs, err := a.store.ListMDMSCEPPolicies(r.Context(), tenantID)
	if err != nil {
		a.writeMDMSCEPError(w, err)
		return
	}
	telemetry, err := a.mdmSCEPTelemetry(r.Context(), tenantID)
	if err != nil {
		a.writeMDMSCEPError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, mdmSCEPStatusResponse{
		RuntimeGate: "served_scep_intune_validator_policy_driven",
		RuntimeNote: "The SCEP endpoint resolves enabled MDM SCEP policy trust_anchor_refs from the served secret store at challenge-validation time; protocols.scep.intune_challenge remains a static bootstrap/fallback path.",
		Telemetry:   telemetry,
		Policies:    toMDMSCEPPolicyResponses(recs),
	})
}

func (a *API) emitMDMSCEPPolicy(ctx context.Context, tenantID, id string, req mdmSCEPPolicyRequest, rotationVersion int) error {
	payload, err := json.Marshal(projections.MDMSCEPPolicyUpserted{
		ID: id, Name: req.Name, Provider: req.Provider, SCEPProfile: req.SCEPProfile,
		SCEPEndpoint: req.SCEPEndpoint, ExpectedAudience: req.ExpectedAudience,
		ChallengeMode: req.ChallengeMode, TrustAnchorRefs: req.TrustAnchorRefs,
		ProfileGuidance: req.ProfileGuidance, Enabled: *req.Enabled, RotationVersion: rotationVersion,
	})
	if err != nil {
		return err
	}
	return a.appendAndProjectMDMSCEP(ctx, tenantID, projections.EventMDMSCEPPolicyUpserted, payload)
}

func (a *API) appendAndProjectMDMSCEP(ctx context.Context, tenantID, eventType string, payload []byte) error {
	if a.store == nil || a.log == nil {
		return errStatus(http.StatusServiceUnavailable, "MDM SCEP policy management is not configured")
	}
	ev, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	return projections.New(a.store).Apply(ctx, ev)
}

func decodeMDMSCEPPolicyRequest(r *http.Request) (mdmSCEPPolicyRequest, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return mdmSCEPPolicyRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return mdmSCEPPolicyRequest{}, errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return mdmSCEPPolicyRequest{}, errStatus(http.StatusBadRequest, "MDM SCEP policies accept reference fields, not inline secret values")
	}
	var req mdmSCEPPolicyRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return mdmSCEPPolicyRequest{}, errStatus(http.StatusBadRequest, "invalid MDM SCEP policy request")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.TrimSpace(req.Provider)
	req.SCEPProfile = strings.TrimSpace(req.SCEPProfile)
	req.SCEPEndpoint = strings.TrimSpace(req.SCEPEndpoint)
	req.ExpectedAudience = strings.TrimSpace(req.ExpectedAudience)
	req.ChallengeMode = strings.TrimSpace(req.ChallengeMode)
	if req.Name == "" || req.Provider == "" || req.SCEPProfile == "" || req.SCEPEndpoint == "" {
		return mdmSCEPPolicyRequest{}, errStatus(http.StatusBadRequest, "name, provider, scep_profile, and scep_endpoint are required")
	}
	switch req.Provider {
	case "intune", "jamf":
	default:
		return mdmSCEPPolicyRequest{}, errStatus(http.StatusBadRequest, "provider must be intune or jamf")
	}
	if req.ChallengeMode == "" {
		req.ChallengeMode = "intune-jws"
	}
	switch req.ChallengeMode {
	case "intune-jws", "hmac-dynamic":
	default:
		return mdmSCEPPolicyRequest{}, errStatus(http.StatusBadRequest, "challenge_mode must be intune-jws or hmac-dynamic")
	}
	if req.Enabled == nil {
		on := true
		req.Enabled = &on
	}
	refs, err := normalizeJSONObject(req.TrustAnchorRefs, "trust_anchor_refs")
	if err != nil {
		return mdmSCEPPolicyRequest{}, err
	}
	if err := validateReferenceObject(refs, "trust_anchor_refs"); err != nil {
		return mdmSCEPPolicyRequest{}, err
	}
	req.TrustAnchorRefs = refs
	guidance, err := normalizeJSONObject(req.ProfileGuidance, "profile_guidance")
	if err != nil {
		return mdmSCEPPolicyRequest{}, err
	}
	if string(guidance) == "{}" {
		guidance = defaultMDMSCEPProfileGuidance(req)
	}
	req.ProfileGuidance = guidance
	return req, nil
}

func normalizeJSONObject(raw json.RawMessage, field string) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, errStatus(http.StatusBadRequest, field+" must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return nil, errStatus(http.StatusBadRequest, field+" must not contain inline secret-shaped fields")
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func validateReferenceObject(raw json.RawMessage, field string) error {
	var refs map[string]string
	if err := json.Unmarshal(raw, &refs); err != nil {
		return errStatus(http.StatusBadRequest, field+" values must be strings")
	}
	for key, value := range refs {
		k := strings.ToLower(strings.TrimSpace(key))
		if !strings.Contains(k, "ref") {
			return errStatus(http.StatusBadRequest, field+" keys must be reference fields")
		}
		if strings.TrimSpace(value) == "" {
			return errStatus(http.StatusBadRequest, field+" values must be non-empty references")
		}
	}
	return nil
}

func defaultMDMSCEPProfileGuidance(req mdmSCEPPolicyRequest) json.RawMessage {
	body, _ := json.Marshal(map[string]any{
		"platform":                  req.Provider,
		"scep_url":                  req.SCEPEndpoint,
		"profile":                   req.SCEPProfile,
		"challenge_source":          req.ChallengeMode,
		"subject_name_format":       "CN={{DeviceName}}",
		"renewal_threshold_percent": 20,
		"key_usage":                 []string{"digital_signature", "key_encipherment"},
	})
	return json.RawMessage(body)
}

func toMDMSCEPPolicyResponses(recs []store.MDMSCEPPolicy) []mdmSCEPPolicyResponse {
	items := make([]mdmSCEPPolicyResponse, 0, len(recs))
	for _, rec := range recs {
		items = append(items, toMDMSCEPPolicyResponse(rec))
	}
	return items
}

func toMDMSCEPPolicyResponse(rec store.MDMSCEPPolicy) mdmSCEPPolicyResponse {
	refs := rec.TrustAnchorRefs
	if len(refs) == 0 {
		refs = json.RawMessage(`{}`)
	}
	guidance := rec.ProfileGuidance
	if len(guidance) == 0 {
		guidance = json.RawMessage(`{}`)
	}
	out := mdmSCEPPolicyResponse{
		ID: rec.ID, TenantID: rec.TenantID, Name: rec.Name, Provider: rec.Provider,
		SCEPProfile: rec.SCEPProfile, SCEPEndpoint: rec.SCEPEndpoint, ExpectedAudience: rec.ExpectedAudience,
		ChallengeMode: rec.ChallengeMode, TrustAnchorRefs: refs, ProfileGuidance: guidance,
		Enabled: rec.Enabled, RotationVersion: rec.RotationVersion,
		CreatedAt: rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if rec.LastRotatedAt != nil {
		out.LastRotatedAt = rec.LastRotatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return out
}

func (a *API) mdmSCEPTelemetry(ctx context.Context, tenantID string) (mdmSCEPTelemetryResponse, error) {
	var out mdmSCEPTelemetryResponse
	if a.log == nil {
		return out, nil
	}
	err := a.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		switch ev.Type {
		case "mdm.intune_scep_challenge":
			var payload struct {
				Decision      string `json:"decision"`
				Reason        string `json:"reason"`
				TransactionID string `json:"transaction_id"`
			}
			_ = json.Unmarshal(ev.Data, &payload)
			if payload.Decision == "allow" {
				out.Allowed++
			} else {
				out.Denied++
				out.LastFailureReason = payload.Reason
			}
			out.LastTransactionID = payload.TransactionID
			out.LastEventTimestamp = ev.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
		case "mdm.intune_scep_challenge.replay_rejected":
			out.ReplayRejected++
			out.Denied++
			var payload struct {
				Reason        string `json:"reason"`
				TransactionID string `json:"transaction_id"`
			}
			_ = json.Unmarshal(ev.Data, &payload)
			out.LastFailureReason = payload.Reason
			out.LastTransactionID = payload.TransactionID
			out.LastEventTimestamp = ev.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		return nil
	})
	return out, err
}

func (a *API) writeMDMSCEPError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrMDMSCEPPolicyNotFound) {
		a.writeError(w, errStatus(http.StatusNotFound, "MDM SCEP policy not found"))
		return
	}
	a.writeError(w, err)
}
