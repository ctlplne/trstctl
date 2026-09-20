// SPDX-License-Identifier: BUSL-1.1

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
	"trstctl.com/trstctl/internal/crypto/secret"
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
	PreviewSSHCertificate(ctx context.Context, tenantID string, req SSHCertificateRequest) (SSHCertificatePreview, error)
	IssueSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req SSHCertificateRequest) (SSHCertificate, error)
	PreviewAttestedSSHUserCert(ctx context.Context, tenantID string, req SSHAttestedUserCertRequest) (SSHAttestedUserCertPreview, error)
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
	PublicKey       string   `json:"public_key"`
	KeyID           string   `json:"key_id,omitempty"`
	TTLSeconds      int64    `json:"ttl_seconds,omitempty"`
	Approver        string   `json:"approver"`
	Principals      []string `json:"principals,omitempty"`
	SourceAddresses []string `json:"source_addresses,omitempty"`
	ForceCommand    string   `json:"force_command,omitempty"`
}

// sshAttestedUserCertJSON keeps bearer proof bytes in wipeable buffers at the
// HTTP boundary. PublicKey is public OpenSSH material; the matching private key
// never enters this process.
type sshAttestedUserCertJSON struct {
	Method          string          `json:"method"`
	PayloadBase64   secretJSONBytes `json:"payload_base64"`
	PublicKey       string          `json:"public_key"`
	KeyID           string          `json:"key_id,omitempty"`
	TTLSeconds      int64           `json:"ttl_seconds,omitempty"`
	Approver        string          `json:"approver"`
	Principals      []string        `json:"principals,omitempty"`
	SourceAddresses []string        `json:"source_addresses,omitempty"`
	ForceCommand    string          `json:"force_command,omitempty"`
}

func (r *sshAttestedUserCertJSON) wipeSecrets() {
	r.PayloadBase64.wipe()
	r.PayloadBase64 = nil
}

func sshAttestedUserCertRequestFromJSON(req sshAttestedUserCertJSON) (SSHAttestedUserCertRequest, error) {
	defer req.PayloadBase64.wipe()
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(req.PayloadBase64)))
	n, err := base64.StdEncoding.Decode(payload, req.PayloadBase64)
	if err != nil || n == 0 {
		secret.Wipe(payload)
		return SSHAttestedUserCertRequest{}, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
	}
	return SSHAttestedUserCertRequest{
		Method: strings.TrimSpace(req.Method), Payload: payload[:n], PublicKey: req.PublicKey,
		KeyID: req.KeyID, TTLSeconds: req.TTLSeconds, Approver: req.Approver,
		Principals: append([]string(nil), req.Principals...), SourceAddresses: append([]string(nil), req.SourceAddresses...),
		ForceCommand: req.ForceCommand,
	}, nil
}

// SSHAttestedUserCertPreview is the exact, effect-free F45 plan. Proof
// verification remains execution-only because a verifier may consume one-time
// evidence or emit audit records.
type SSHAttestedUserCertPreview struct {
	Capability               string   `json:"capability"`
	Ready                    bool     `json:"ready"`
	EffectFree               bool     `json:"effect_free"`
	Method                   string   `json:"method"`
	SupportedMethods         []string `json:"supported_methods"`
	KeyID                    string   `json:"key_id"`
	Approver                 string   `json:"approver"`
	Principals               []string `json:"principals"`
	SourceAddresses          []string `json:"source_addresses"`
	ForceCommand             string   `json:"force_command"`
	RequestedTTLSeconds      int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds      int64    `json:"effective_ttl_seconds"`
	TTLDefaulted             bool     `json:"ttl_defaulted"`
	TTLClamped               bool     `json:"ttl_clamped"`
	PublicKeyType            string   `json:"public_key_type"`
	PublicKeyFingerprint     string   `json:"public_key_fingerprint"`
	AuthorityFingerprint     string   `json:"authority_fingerprint"`
	RequiredPermission       string   `json:"required_permission"`
	AttestationVerification  string   `json:"attestation_verification"`
	PayloadSHA256            string   `json:"payload_sha256"`
	PreviewWrites            []string `json:"preview_writes"`
	PreviewExternalEffects   []string `json:"preview_external_effects"`
	PreviewSignerCalls       []string `json:"preview_signer_calls"`
	ExecutionWrites          []string `json:"execution_writes"`
	ExecutionExternalEffects []string `json:"execution_external_effects"`
	ExecutionSignerCalls     []string `json:"execution_signer_calls"`
	Blockers                 []string `json:"blockers"`
	RecoverySteps            []string `json:"recovery_steps"`
	DataHandling             []string `json:"data_handling"`
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

// SSHCertificateRequest asks the tenant SSH CA for a host or user certificate.
// PublicKey is public material in OpenSSH authorized_keys form; a private key is
// never accepted by this API.
type SSHCertificateRequest struct {
	CertificateType string            `json:"certificate_type"`
	PublicKey       string            `json:"public_key"`
	KeyID           string            `json:"key_id"`
	Principals      []string          `json:"principals"`
	TTLSeconds      int64             `json:"ttl_seconds,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
}

// SSHCertificatePreview is the normalized, effect-free plan used by the UI and
// CLI before issuance. It explicitly separates what preview did from what a
// later issuance will do so an operator never has to infer side effects.
type SSHCertificatePreview struct {
	Capability              string            `json:"capability"`
	Ready                   bool              `json:"ready"`
	EffectFree              bool              `json:"effect_free"`
	CertificateType         string            `json:"certificate_type"`
	KeyID                   string            `json:"key_id"`
	Principals              []string          `json:"principals"`
	RequestedTTLSeconds     int64             `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds     int64             `json:"effective_ttl_seconds"`
	TTLDefaulted            bool              `json:"ttl_defaulted"`
	TTLClamped              bool              `json:"ttl_clamped"`
	PublicKeyType           string            `json:"public_key_type"`
	PublicKeyFingerprint    string            `json:"public_key_fingerprint"`
	AuthorityFingerprint    string            `json:"authority_fingerprint"`
	CriticalOptions         map[string]string `json:"critical_options"`
	Extensions              map[string]string `json:"extensions"`
	PreviewWrites           []string          `json:"preview_writes"`
	PreviewExternalEffects  []string          `json:"preview_external_effects"`
	PreviewSignerCalls      []string          `json:"preview_signer_calls"`
	IssuanceWrites          []string          `json:"issuance_writes"`
	IssuanceExternalEffects []string          `json:"issuance_external_effects"`
	IssuanceSignerCalls     []string          `json:"issuance_signer_calls"`
	Blockers                []string          `json:"blockers"`
	RecoverySteps           []string          `json:"recovery_steps"`
	SecretDataHandling      []string          `json:"secret_data_handling"`
}

// SSHCertificate is public certificate material returned after one signer call.
type SSHCertificate struct {
	Certificate          string            `json:"certificate"`
	CertificateType      string            `json:"certificate_type"`
	Serial               uint64            `json:"serial"`
	KeyID                string            `json:"key_id"`
	Principals           []string          `json:"principals"`
	ValidBefore          string            `json:"valid_before"`
	CriticalOptions      map[string]string `json:"critical_options"`
	Extensions           map[string]string `json:"extensions"`
	AuthorityFingerprint string            `json:"authority_fingerprint"`
	KRLVersion           uint64            `json:"krl_version"`
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

func (a *API) previewSSHCertificate(w http.ResponseWriter, r *http.Request) {
	if a.sshWorkflow == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "ssh workflow is not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	var req SSHCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, err.Error()))
		return
	}
	preview, err := a.sshWorkflow.PreviewSSHCertificate(r.Context(), tenantID, req)
	if err != nil {
		if a.writeSSHWorkflowError(w, err) {
			return
		}
		a.writeProblem(w, problem.New(http.StatusInternalServerError, err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

//trstctl:mutation
func (a *API) issueSSHCertificate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshWorkflow == nil {
			return 0, nil, ErrSSHWorkflowUnavailable
		}
		var req SSHCertificateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		out, err := a.sshWorkflow.IssueSSHCertificate(ctx, tenantID, idempotencyKey, req)
		return http.StatusCreated, out, err
	})
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

// previewAttestedSSHUserCert reads tenant trust and normalizes the exact request
// without verifying proof, writing state, emitting audit evidence, or calling the
// signer. Verification remains part of the explicit mutation because proofs may
// be one-time credentials.
func (a *API) previewAttestedSSHUserCert(w http.ResponseWriter, r *http.Request) {
	if a.sshWorkflow == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "ssh workflow is not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	var wire sshAttestedUserCertJSON
	defer wire.wipeSecrets()
	if err := decodeJSON(r, &wire); err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, err.Error()))
		return
	}
	req, err := sshAttestedUserCertRequestFromJSON(wire)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(req.Payload)
	preview, err := a.sshWorkflow.PreviewAttestedSSHUserCert(r.Context(), tenantID, req)
	if err != nil {
		if a.writeSSHWorkflowError(w, err) {
			return
		}
		a.writeProblem(w, problem.New(http.StatusInternalServerError, err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

//trstctl:mutation
func (a *API) issueAttestedSSHUserCert(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.sshWorkflow == nil {
			return 0, nil, ErrSSHWorkflowUnavailable
		}
		var wire sshAttestedUserCertJSON
		defer wire.wipeSecrets()
		if err := decodeJSON(r, &wire); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req, err := sshAttestedUserCertRequestFromJSON(wire)
		if err != nil {
			return 0, nil, err
		}
		defer secret.Wipe(req.Payload)
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
		detail := strings.TrimPrefix(err.Error(), ErrSSHWorkflowUnavailable.Error()+": ")
		if detail == "" || detail == err.Error() {
			detail = "ssh workflow is temporarily unavailable"
		}
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, detail))
	case errors.Is(err, ErrSSHWorkflowInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrSSHWorkflowInvalid.Error()+": ")))
	case errors.Is(err, ErrSSHWorkflowRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrSSHWorkflowRejected.Error()+": ")))
	default:
		return false
	}
	return true
}
