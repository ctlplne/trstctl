// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A233: a tenant opts in to crypto-shredding of its sensitive event fields.
// The request names the tenant's current registration (its key lifetime) and
// a retention window the operator chooses; trstctl never picks a legal window.
// Enabling appends one control event; a bounded worker creates the per-tenant
// key and records its activation, and only that independently read key makes
// the status "active". Offboarding later destroys the key after the retention
// window with a signed destruction record. No route here destroys a key.

const maxEventProtectionRetention = 10 * 365 * 24 * time.Hour

// Event-protection states the tenant route reports.
const (
	EventProtectionNotEnabled = "not_enabled"
	EventProtectionPreparing  = "preparing"
	EventProtectionActive     = "active"
)

var (
	// ErrEventProtectionInvalid is a malformed request (400).
	ErrEventProtectionInvalid = errors.New("event protection request is invalid")
	// ErrEventProtectionConflict is a request the tenant's retained source
	// refuses: a stale registration, a different policy for the same lifetime,
	// or a deployment without a key directory (409).
	ErrEventProtectionConflict = errors.New("event protection request conflicts with the tenant's retained source")
	// ErrEventProtectionUnavailable means the current key could not be read
	// back independently (503). Its public detail is fixed: no custody path,
	// handle or private diagnostic leaves the server.
	ErrEventProtectionUnavailable = errors.New("event protection key custody is unavailable")
)

// EventProtectionRequest is the opt-in a preview reviews and an enable applies.
type EventProtectionRequest struct {
	RegistrationIdentity string `json:"registration_identity"`
	Retention            string `json:"retention"`
}

// EventProtectionStatus is derived from the retained source and current key
// custody, never from a SQL flag.
type EventProtectionStatus struct {
	State                string     `json:"state"`
	RegistrationIdentity string     `json:"registration_identity"`
	CustodyConfigured    bool       `json:"custody_configured"`
	OperationID          string     `json:"operation_id,omitempty"`
	Retention            string     `json:"retention,omitempty"`
	RequestedAt          *time.Time `json:"requested_at,omitempty"`
	ActivatedAt          *time.Time `json:"activated_at,omitempty"`
	LegacyEventsReadable bool       `json:"legacy_events_readable"`
	NextStep             string     `json:"next_step"`
}

// EventProtectionPlan follows the shared effect-free preview contract.
type EventProtectionPlan struct {
	Capability             string                 `json:"capability"`
	Operation              string                 `json:"operation"`
	Ready                  bool                   `json:"ready"`
	EffectFree             bool                   `json:"effect_free"`
	RequestFingerprint     string                 `json:"request_fingerprint"`
	RequiredPermission     string                 `json:"required_permission"`
	NormalizedRequest      EventProtectionRequest `json:"normalized_request"`
	OperationID            string                 `json:"operation_id"`
	CustodyConfigured      bool                   `json:"custody_configured"`
	Blockers               []string               `json:"blockers"`
	Warnings               []string               `json:"warnings"`
	PreviewWrites          []string               `json:"preview_writes"`
	PreviewExternalEffects []string               `json:"preview_external_effects"`
	ExecuteWrites          []string               `json:"execute_writes"`
	ExecuteExternalEffects []string               `json:"execute_external_effects"`
	RecoverySteps          []string               `json:"recovery_steps"`
	VerificationSteps      []string               `json:"verification_steps"`
}

// EventProtectionAccepted answers an enable: the request is retained and the
// key is being prepared. Status turns "active" only after key readback.
type EventProtectionAccepted struct {
	OperationID          string `json:"operation_id"`
	RegistrationIdentity string `json:"registration_identity"`
	Retention            string `json:"retention"`
	State                string `json:"state"`
}

// EventProtectionService reads and applies the opt-in. The server implements
// it over the retained event source, the orchestrator and key custody.
type EventProtectionService interface {
	Status(ctx context.Context, tenantID string) (EventProtectionStatus, error)
	Preview(ctx context.Context, tenantID string, req EventProtectionRequest) (EventProtectionPlan, error)
	Request(ctx context.Context, tenantID string, req EventProtectionRequest) (EventProtectionAccepted, error)
}

// WithEventProtection serves the tenant event-protection routes.
func WithEventProtection(svc EventProtectionService) Option {
	return func(c *config) { c.eventProtection = svc }
}

// NormalizeEventProtectionRequest trims the request and checks its retention.
func NormalizeEventProtectionRequest(req EventProtectionRequest) (EventProtectionRequest, time.Duration, error) {
	req.RegistrationIdentity = strings.TrimSpace(req.RegistrationIdentity)
	req.Retention = strings.TrimSpace(req.Retention)
	if req.RegistrationIdentity == "" || len(req.RegistrationIdentity) > 512 {
		return EventProtectionRequest{}, 0, fmt.Errorf("%w: registration_identity is required (read it from the status route)", ErrEventProtectionInvalid)
	}
	retention, err := time.ParseDuration(req.Retention)
	if err != nil || retention <= 0 || retention > maxEventProtectionRetention {
		return EventProtectionRequest{}, 0, fmt.Errorf("%w: retention must be a positive duration of at most %s, such as 720h", ErrEventProtectionInvalid, maxEventProtectionRetention)
	}
	req.Retention = retention.String()
	return req, retention, nil
}

func (a *API) getEventProtection(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.eventProtection == nil {
		a.writeProblem(w, problem.New(http.StatusNotFound, "event protection is not served by this deployment"))
		return
	}
	status, err := a.eventProtection.Status(r.Context(), tenantID)
	if err != nil {
		a.writeEventProtectionError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, status)
}

func (a *API) previewEventProtection(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.eventProtection == nil {
		a.writeProblem(w, problem.New(http.StatusNotFound, "event protection is not served by this deployment"))
		return
	}
	var req EventProtectionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	plan, err := a.eventProtection.Preview(r.Context(), tenantID, req)
	if err != nil {
		a.writeEventProtectionError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) requestEventProtection(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if a.eventProtection == nil {
		a.writeProblem(w, problem.New(http.StatusNotFound, "event protection is not served by this deployment"))
		return
	}
	var req EventProtectionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req, _, err := NormalizeEventProtectionRequest(req)
	if err != nil {
		a.writeEventProtectionError(w, err)
		return
	}
	binding, err := eventProtectionRequestBinding(r, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		accepted, err := a.eventProtection.Request(ctx, tenantID, req)
		if err != nil {
			return 0, nil, eventProtectionHTTPError(err)
		}
		return http.StatusAccepted, accepted, nil
	})
}

// eventProtectionRequestBinding keeps one Idempotency-Key from replaying an
// accepted opt-in for another caller, route or policy.
func eventProtectionRequestBinding(r *http.Request, req EventProtectionRequest) (string, error) {
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		return "", err
	}
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	material, err := json.Marshal(struct {
		Domain      string                 `json:"domain"`
		Principal   string                 `json:"principal"`
		Method      string                 `json:"method"`
		EscapedPath string                 `json:"escaped_path"`
		Command     EventProtectionRequest `json:"command"`
	}{Domain: "trstctl.event-protection-request.v1", Principal: principal, Method: r.Method, EscapedPath: escapedPath, Command: req})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}

func eventProtectionHTTPError(err error) error {
	switch {
	case errors.Is(err, ErrEventProtectionInvalid):
		return errWithStatus(http.StatusBadRequest, err)
	case errors.Is(err, ErrEventProtectionConflict):
		return errWithStatus(http.StatusConflict, err)
	case errors.Is(err, ErrEventProtectionUnavailable):
		// Fixed public detail: the cause stays in server logs.
		return errStatus(http.StatusServiceUnavailable, ErrEventProtectionUnavailable.Error())
	}
	return err
}

func (a *API) writeEventProtectionError(w http.ResponseWriter, err error) {
	a.writeError(w, eventProtectionHTTPError(err))
}
