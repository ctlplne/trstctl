package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/attest"
)

var (
	ErrSSHWorkflowUnavailable = errors.New("api: ssh workflow is not enabled")
	ErrSSHWorkflowInvalid     = errors.New("api: invalid ssh workflow request")
	ErrSSHWorkflowRejected    = errors.New("api: ssh workflow rejected")
)

// SSHWorkflowService is the tenant-scoped product surface that stitches the SSH
// journey together: discovery creates source/run records, this service records
// rollout evidence, issues attestation-gated SSH certs, publishes KRL revocation
// status, and records host retirement.
type SSHWorkflowService interface {
	SSHStatus(ctx context.Context, tenantID string) (SSHStatus, error)
	RecordSSHTrustRollout(ctx context.Context, tenantID, idempotencyKey string, req SSHTrustRolloutRequest) (SSHTrustRollout, error)
	IssueAttestedSSHUserCert(ctx context.Context, tenantID, idempotencyKey string, req SSHAttestedUserCertRequest) (SSHAttestedUserCert, error)
	RevokeSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req SSHRevokeCertificateRequest) (SSHStatus, error)
	RetireSSHHost(ctx context.Context, tenantID, idempotencyKey string, req SSHHostRetireRequest) (SSHHostRetirement, error)
}

// WithSSHWorkflow wires the served SSH-at-scale workflow API. Without it, routes
// fail closed with 503.
func WithSSHWorkflow(svc SSHWorkflowService) Option {
	return func(c *config) { c.sshWorkflow = svc }
}

type SSHStatus struct {
	Served       bool     `json:"served"`
	TenantID     string   `json:"tenant_id"`
	AuthorityKey string   `json:"authority_key,omitempty"`
	KRLVersion   uint64   `json:"krl_version"`
	RevokedCount int      `json:"revoked_count"`
	Attestors    []string `json:"attestors,omitempty"`
}

type SSHTrustRolloutRequest struct {
	SourceID               string   `json:"source_id"`
	TargetHosts            []string `json:"target_hosts"`
	CandidateCAFingerprint string   `json:"candidate_ca_fingerprint"`
	ReloadCommand          string   `json:"reload_command"`
	HealthCommand          string   `json:"health_command"`
	RollbackPlan           string   `json:"rollback_plan"`
	Status                 string   `json:"status"`
	Confirmed              bool     `json:"confirmed"`
}

type SSHTrustRollout struct {
	ID                     string    `json:"id"`
	TenantID               string    `json:"tenant_id"`
	SourceID               string    `json:"source_id"`
	TargetHosts            []string  `json:"target_hosts"`
	CandidateCAFingerprint string    `json:"candidate_ca_fingerprint"`
	ReloadCommand          string    `json:"reload_command"`
	HealthCommand          string    `json:"health_command"`
	RollbackPlan           string    `json:"rollback_plan"`
	Status                 string    `json:"status"`
	Confirmed              bool      `json:"confirmed"`
	RecordedAt             time.Time `json:"recorded_at"`
}

type SSHAttestedUserCertRequest struct {
	Method          string   `json:"method"`
	Payload         []byte   `json:"-"`
	PayloadBase64   string   `json:"payload_base64"`
	PublicKey       string   `json:"public_key"`
	KeyID           string   `json:"key_id,omitempty"`
	TTLSeconds      int64    `json:"ttl_seconds,omitempty"`
	Approver        string   `json:"approver"`
	Principals      []string `json:"principals,omitempty"`
	SourceAddresses []string `json:"source_addresses,omitempty"`
	ForceCommand    string   `json:"force_command,omitempty"`
}

type SSHAttestedUserCert struct {
	Certificate     string             `json:"certificate"`
	Serial          uint64             `json:"serial"`
	KeyID           string             `json:"key_id"`
	Subject         string             `json:"subject"`
	Principals      []string           `json:"principals"`
	ValidBefore     string             `json:"valid_before"`
	Approver        string             `json:"approver"`
	SourceAddresses []string           `json:"source_addresses,omitempty"`
	ForceCommand    string             `json:"force_command,omitempty"`
	Attestation     attest.Attestation `json:"attestation"`
}

type SSHRevokeCertificateRequest struct {
	Serial uint64 `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type SSHHostRetireRequest struct {
	Host       string `json:"host"`
	SourceID   string `json:"source_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	IdentityID string `json:"identity_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type SSHHostRetirement struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Host       string    `json:"host"`
	SourceID   string    `json:"source_id,omitempty"`
	RunID      string    `json:"run_id,omitempty"`
	IdentityID string    `json:"identity_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Status     string    `json:"status"`
	RecordedAt time.Time `json:"recorded_at"`
}

func (a *API) getSSHStatus(w http.ResponseWriter, r *http.Request) {
	if a.sshWorkflow == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "ssh workflow is not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	status, err := a.sshWorkflow.SSHStatus(r.Context(), tenantID)
	if err != nil {
		if a.writeSSHWorkflowError(w, err) {
			return
		}
		a.writeProblem(w, problem.New(http.StatusInternalServerError, err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, status)
}

//trstctl:mutation
func (a *API) recordSSHTrustRollout(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshWorkflow == nil {
			return 0, nil, ErrSSHWorkflowUnavailable
		}
		var req SSHTrustRolloutRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		out, err := a.sshWorkflow.RecordSSHTrustRollout(ctx, tenantID, idempotencyKey, req)
		return http.StatusCreated, out, err
	})
}

//trstctl:mutation
func (a *API) issueAttestedSSHUserCert(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshWorkflow == nil {
			return 0, nil, ErrSSHWorkflowUnavailable
		}
		var req SSHAttestedUserCertRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PayloadBase64))
		if err != nil || len(payload) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
		}
		req.Payload = payload
		out, err := a.sshWorkflow.IssueAttestedSSHUserCert(ctx, tenantID, idempotencyKey, req)
		return http.StatusCreated, out, err
	})
}

//trstctl:mutation
func (a *API) revokeSSHCertificate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshWorkflow == nil {
			return 0, nil, ErrSSHWorkflowUnavailable
		}
		var req SSHRevokeCertificateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		out, err := a.sshWorkflow.RevokeSSHCertificate(ctx, tenantID, idempotencyKey, req)
		return http.StatusOK, out, err
	})
}

//trstctl:mutation
func (a *API) retireSSHHost(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshWorkflow == nil {
			return 0, nil, ErrSSHWorkflowUnavailable
		}
		var req SSHHostRetireRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		out, err := a.sshWorkflow.RetireSSHHost(ctx, tenantID, idempotencyKey, req)
		return http.StatusOK, out, err
	})
}

func (a *API) writeSSHWorkflowError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrSSHWorkflowUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "ssh workflow is not enabled"))
	case errors.Is(err, ErrSSHWorkflowInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrSSHWorkflowInvalid.Error()+": ")))
	case errors.Is(err, ErrSSHWorkflowRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrSSHWorkflowRejected.Error()+": ")))
	default:
		return false
	}
	return true
}
