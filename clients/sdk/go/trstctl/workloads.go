// SPDX-License-Identifier: MPL-2.0

package trstctl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Attestation is the public, verified metadata returned after a workload proof
// succeeds. It never contains the raw proof.
type Attestation struct {
	ID         string         `json:"id"`
	Method     string         `json:"method"`
	Subject    string         `json:"subject"`
	Selectors  []string       `json:"selectors"`
	VerifiedAt string         `json:"verified_at"`
	Claims     map[string]any `json:"claims,omitempty"`
}

// BrokerAgentIdentityRequest asks the agent broker to review or issue one
// short-lived identity. Payload and TaskEnvelope are decoded bytes; encoding/json
// emits the OpenAPI payload_base64/task_envelope_base64 wire fields. The SDK
// copies and wipes its encoded buffers and never modifies the caller's slices.
type BrokerAgentIdentityRequest struct {
	AgentID      string   `json:"agent_id"`
	Method       string   `json:"method"`
	Payload      []byte   `json:"payload_base64"`
	PublicKeyPEM string   `json:"public_key_pem"`
	Scopes       []string `json:"scopes"`
	TaskEnvelope []byte   `json:"task_envelope_base64,omitempty"`
	TTLSeconds   int64    `json:"ttl_seconds,omitempty"`
}

// BrokerAgentIdentity is a completed agent-broker issuance response. SPIFFEID
// is nil when the server cannot safely read the exact canonical URI from the
// issued certificate; callers must never substitute Subject for it.
type BrokerAgentIdentity struct {
	AgentID            string      `json:"agent_id"`
	NodeID             string      `json:"node_id"`
	Subject            string      `json:"subject"`
	CredentialID       string      `json:"credential_id"`
	CertificateID      string      `json:"certificate_id"`
	CertificatePEM     string      `json:"certificate_pem"`
	Scopes             []string    `json:"scopes"`
	NotAfter           string      `json:"not_after"`
	Attestation        Attestation `json:"attestation"`
	SPIFFEID           *string     `json:"spiffe_id,omitempty"`
	TaskEnvelopeDigest string      `json:"task_envelope_digest,omitempty"`
}

// WorkloadIssuancePreview contains the fields shared by the effect-free broker,
// attested-SVID and ephemeral previews.
type WorkloadIssuancePreview struct {
	Capability              string   `json:"capability"`
	Ready                   bool     `json:"ready"`
	EffectFree              bool     `json:"effect_free"`
	Method                  string   `json:"method"`
	Requester               string   `json:"requester"`
	TrustDomain             string   `json:"trust_domain"`
	SupportedMethods        []string `json:"supported_methods"`
	RequestedTTLSeconds     int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds     int64    `json:"effective_ttl_seconds"`
	DefaultTTLSeconds       int64    `json:"default_ttl_seconds"`
	MaxTTLSeconds           int64    `json:"max_ttl_seconds"`
	TTLDefaulted            bool     `json:"ttl_defaulted"`
	TTLClamped              bool     `json:"ttl_clamped"`
	AttestationVerification string   `json:"attestation_verification"`
	PayloadSHA256           string   `json:"payload_sha256"`
	PublicKeySHA256         string   `json:"public_key_sha256"`
	PreviewWrites           []string `json:"preview_writes"`
	PreviewExternalEffects  []string `json:"preview_external_effects"`
	PreviewSignerCalls      []string `json:"preview_signer_calls"`
	Steps                   []string `json:"steps"`
	Blockers                []string `json:"blockers"`
	RecoverySteps           []string `json:"recovery_steps"`
	DataHandling            []string `json:"data_handling"`
}

// BrokerAgentIdentityPreview is the effect-free review of an exact broker
// request. Ready means configured, not proof-verified or policy-authorized.
type BrokerAgentIdentityPreview struct {
	WorkloadIssuancePreview
	RequiredPermission       string   `json:"required_permission"`
	ExecutionWrites          []string `json:"execution_writes"`
	ExecutionExternalEffects []string `json:"execution_external_effects"`
	ExecutionSignerCalls     []string `json:"execution_signer_calls"`
	AgentID                  string   `json:"agent_id"`
	Scopes                   []string `json:"scopes"`
	PolicyEvaluation         string   `json:"policy_evaluation"`
	TaskEnvelopeVerification string   `json:"task_envelope_verification"`
	TaskEnvelopeSHA256       string   `json:"task_envelope_sha256"`
}

// BrokerIssuanceFacts are immutable original-issuance facts retained with a
// broker certificate. A nil *BrokerIssuanceFacts means the metadata is
// unavailable; current owner data must not be used to invent it.
type BrokerIssuanceFacts struct {
	AgentID             string   `json:"agent_id"`
	Subject             string   `json:"subject"`
	Method              string   `json:"method"`
	OwnerID             string   `json:"owner_id"`
	Scopes              []string `json:"scopes"`
	RequestedTTLSeconds int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds int64    `json:"effective_ttl_seconds"`
	TaskEnvelopeDigest  string   `json:"task_envelope_digest,omitempty"`
}

// BrokerAgentIdentityHistory is one durable broker-issued certificate record.
// It intentionally omits certificate bodies, raw proofs, task contents, and
// internal recovery bindings.
type BrokerAgentIdentityHistory struct {
	CertificateID      string               `json:"certificate_id"`
	Fingerprint        string               `json:"fingerprint"`
	CertificateSubject string               `json:"certificate_subject"`
	Serial             string               `json:"serial"`
	RecordedAt         string               `json:"recorded_at"`
	LifecycleStatus    string               `json:"lifecycle_status"`
	State              string               `json:"state"`
	StateReason        string               `json:"state_reason"`
	MetadataState      string               `json:"metadata_state"`
	GeneratedAt        string               `json:"generated_at"`
	ProjectionState    string               `json:"projection_state"`
	CurrentOwnerID     string               `json:"current_owner_id,omitempty"`
	NotBefore          string               `json:"not_before,omitempty"`
	NotAfter           string               `json:"not_after,omitempty"`
	SPIFFEID           *string              `json:"spiffe_id,omitempty"`
	Issuance           *BrokerIssuanceFacts `json:"issuance,omitempty"`
}

// BrokerAgentIdentityHistoryList is a newest-first durable broker history page.
type BrokerAgentIdentityHistoryList struct {
	Items           []BrokerAgentIdentityHistory `json:"items"`
	NextCursor      string                       `json:"next_cursor"`
	GeneratedAt     string                       `json:"generated_at"`
	ProjectionState string                       `json:"projection_state"`
	HistoryScope    string                       `json:"history_scope"`
}

// BrokerAgentIdentityListOptions are the exact server filters for durable
// broker history. Query is a literal, case-insensitive search, not a regex.
type BrokerAgentIdentityListOptions struct {
	Limit  int
	Cursor string
	Query  string
	Method string
	State  string
}

func (o BrokerAgentIdentityListOptions) query() url.Values {
	q := url.Values{}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Cursor != "" {
		q.Set("cursor", o.Cursor)
	}
	if o.Query != "" {
		q.Set("q", o.Query)
	}
	if o.Method != "" {
		q.Set("method", o.Method)
	}
	if o.State != "" {
		q.Set("state", o.State)
	}
	return q
}

// AttestedSVIDRequest asks trstctl to review or issue an X.509-SVID after
// workload attestation. Payload is decoded proof bytes; the private key never
// belongs in this request.
type AttestedSVIDRequest struct {
	Method       string `json:"method"`
	Payload      []byte `json:"payload_base64"`
	PublicKeyPEM string `json:"public_key_pem"`
	TTLSeconds   int64  `json:"ttl_seconds,omitempty"`
}

// AttestedSVID is a completed direct attested issuance.
type AttestedSVID struct {
	CertificatePEM string      `json:"certificate_pem"`
	CredentialID   string      `json:"credential_id"`
	Subject        string      `json:"subject"`
	NotAfter       string      `json:"not_after"`
	Attestation    Attestation `json:"attestation"`
	SPIFFEID       *string     `json:"spiffe_id,omitempty"`
}

// AttestedSVIDPreview reviews exact inputs without verifying the proof, writing
// state, or calling the signer.
type AttestedSVIDPreview struct {
	WorkloadIssuancePreview
	RequiredPermission       string   `json:"required_permission"`
	ExecutionWrites          []string `json:"execution_writes"`
	ExecutionExternalEffects []string `json:"execution_external_effects"`
	ExecutionSignerCalls     []string `json:"execution_signer_calls"`
}

// EphemeralCredentialRequest opens or completes an approval-gated JIT
// credential request. Payload is decoded proof bytes and remains caller-owned.
type EphemeralCredentialRequest struct {
	RequestID    string `json:"request_id"`
	Method       string `json:"method"`
	Payload      []byte `json:"payload_base64"`
	PublicKeyPEM string `json:"public_key_pem"`
	TTLSeconds   int64  `json:"ttl_seconds,omitempty"`
}

// EphemeralCredential is either awaiting approval (HTTP 202) or issued (HTTP
// 201). The SDK rejects a server response whose HTTP status and State disagree.
type EphemeralCredential struct {
	State             string      `json:"state"`
	RequestID         string      `json:"request_id"`
	ApprovalRequestID string      `json:"approval_request_id"`
	IntentDigest      string      `json:"intent_digest"`
	Subject           string      `json:"subject"`
	RequiredApprovals int         `json:"required_approvals"`
	Approvals         int         `json:"approvals"`
	ExpiresAt         string      `json:"expires_at"`
	Attestation       Attestation `json:"attestation"`
	CertificatePEM    string      `json:"certificate_pem,omitempty"`
	CredentialID      string      `json:"credential_id,omitempty"`
	CertificateID     string      `json:"certificate_id,omitempty"`
	NotAfter          string      `json:"not_after,omitempty"`
	SPIFFEID          *string     `json:"spiffe_id,omitempty"`
}

// IsPending reports whether this response is waiting for independent approval.
func (c EphemeralCredential) IsPending() bool { return c.State == "awaiting_approval" }

// IsIssued reports whether this response contains a completed credential.
func (c EphemeralCredential) IsIssued() bool { return c.State == "issued" }

// EphemeralCredentialPreview is the effect-free review of the exact JIT
// request and its dual-control policy.
type EphemeralCredentialPreview struct {
	WorkloadIssuancePreview
	RequestID                 string   `json:"request_id"`
	ApprovalRequired          bool     `json:"approval_required"`
	RequiredApprovals         int      `json:"required_approvals"`
	ApprovalTTLSeconds        int64    `json:"approval_ttl_seconds"`
	RequestPermission         string   `json:"request_permission"`
	ApprovalPermission        string   `json:"approval_permission"`
	SubmissionWrites          []string `json:"submission_writes"`
	SubmissionExternalEffects []string `json:"submission_external_effects"`
	SubmissionSignerCalls     []string `json:"submission_signer_calls"`
	IssuanceWrites            []string `json:"issuance_writes"`
	IssuanceExternalEffects   []string `json:"issuance_external_effects"`
	IssuanceSignerCalls       []string `json:"issuance_signer_calls"`
}

// EphemeralApprovalRequest binds an independent approval to the genuine queue
// request ID and its exact server-issued intent digest.
type EphemeralApprovalRequest struct {
	Action       string `json:"action"`
	RequestID    string `json:"request_id"`
	IntentDigest string `json:"intent_digest"`
}

// EphemeralApproval is the durable approval state returned by the server.
type EphemeralApproval struct {
	ID                string `json:"id"`
	IntentDigest      string `json:"intent_digest"`
	Resource          string `json:"resource"`
	Action            string `json:"action"`
	Approver          string `json:"approver"`
	Approvals         int    `json:"approvals"`
	ApprovalCount     int    `json:"approval_count"`
	RequiredApprovals int    `json:"required_approvals"`
	Status            string `json:"status"`
}

// PreviewBrokerAgentIdentity reviews exact broker inputs without reserving an
// idempotency key, consuming proof, evaluating policy, or signing.
func (c *Client) PreviewBrokerAgentIdentity(ctx context.Context, req BrokerAgentIdentityRequest) (*BrokerAgentIdentityPreview, error) {
	var out BrokerAgentIdentityPreview
	_, err := c.doStatus(ctx, http.MethodPost, "/api/v1/broker/agent-identities/preview", previewRequest(req), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueBrokerAgentIdentity issues a broker identity with an SDK-generated
// idempotency key. Use IssueBrokerAgentIdentityKeyed when a process restart must
// replay the same logical operation.
func (c *Client) IssueBrokerAgentIdentity(ctx context.Context, req BrokerAgentIdentityRequest) (*BrokerAgentIdentity, error) {
	return c.issueBrokerAgentIdentity(ctx, req, "")
}

// IssueBrokerAgentIdentityKeyed uses the caller's stable idempotency key
// verbatim across retries and process boundaries.
func (c *Client) IssueBrokerAgentIdentityKeyed(ctx context.Context, req BrokerAgentIdentityRequest, idempotencyKey string) (*BrokerAgentIdentity, error) {
	if err := requireIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	return c.issueBrokerAgentIdentity(ctx, req, idempotencyKey)
}

func (c *Client) issueBrokerAgentIdentity(ctx context.Context, req BrokerAgentIdentityRequest, key string) (*BrokerAgentIdentity, error) {
	var out BrokerAgentIdentity
	_, err := c.doStatus(ctx, http.MethodPost, "/api/v1/broker/agent-identities", mutationRequest(req, key, http.StatusCreated), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListBrokerAgentIdentities returns one durable history page, including the
// server's projection freshness and history-scope disclosures.
func (c *Client) ListBrokerAgentIdentities(ctx context.Context, opts BrokerAgentIdentityListOptions) (*BrokerAgentIdentityHistoryList, error) {
	var out BrokerAgentIdentityHistoryList
	_, err := c.doStatus(ctx, http.MethodGet, "/api/v1/broker/agent-identities", requestOptions{
		query: opts.query(), expectedStatuses: []int{http.StatusOK}, requireBody: true,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// BrokerAgentIdentities iterates durable broker history while preserving every
// filter. Per-page projection metadata remains available from the List method.
func (c *Client) BrokerAgentIdentities(opts BrokerAgentIdentityListOptions) *Iterator[BrokerAgentIdentityHistory] {
	return newIterator(ListOptions{Limit: opts.Limit, Cursor: opts.Cursor}, func(ctx context.Context, pageOpts ListOptions) (*Page[BrokerAgentIdentityHistory], error) {
		requestOpts := opts
		requestOpts.Limit = pageOpts.Limit
		requestOpts.Cursor = pageOpts.Cursor
		page, err := c.ListBrokerAgentIdentities(ctx, requestOpts)
		if err != nil {
			return nil, err
		}
		return &Page[BrokerAgentIdentityHistory]{Items: page.Items, NextCursor: page.NextCursor}, nil
	})
}

// GetBrokerAgentIdentity reads one durable broker certificate record. A nil
// SPIFFEID remains nil; the SDK never fabricates it from Subject.
func (c *Client) GetBrokerAgentIdentity(ctx context.Context, id string) (*BrokerAgentIdentityHistory, error) {
	var out BrokerAgentIdentityHistory
	path := "/api/v1/broker/agent-identities/" + url.PathEscape(id)
	_, err := c.doStatus(ctx, http.MethodGet, path, requestOptions{
		expectedStatuses: []int{http.StatusOK}, requireBody: true,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewAttestedSVID reviews exact attested issuance inputs without consuming
// the proof, reserving an idempotency key, writing state, or calling the signer.
func (c *Client) PreviewAttestedSVID(ctx context.Context, req AttestedSVIDRequest) (*AttestedSVIDPreview, error) {
	var out AttestedSVIDPreview
	_, err := c.doStatus(ctx, http.MethodPost, "/api/v1/workloads/attested-issuance/preview", previewRequest(req), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueAttestedSVID issues with an SDK-generated idempotency key.
func (c *Client) IssueAttestedSVID(ctx context.Context, req AttestedSVIDRequest) (*AttestedSVID, error) {
	return c.issueAttestedSVID(ctx, req, "")
}

// IssueAttestedSVIDKeyed issues with a caller-supplied stable key.
func (c *Client) IssueAttestedSVIDKeyed(ctx context.Context, req AttestedSVIDRequest, idempotencyKey string) (*AttestedSVID, error) {
	if err := requireIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	return c.issueAttestedSVID(ctx, req, idempotencyKey)
}

func (c *Client) issueAttestedSVID(ctx context.Context, req AttestedSVIDRequest, key string) (*AttestedSVID, error) {
	var out AttestedSVID
	_, err := c.doStatus(ctx, http.MethodPost, "/api/v1/workloads/attested-issuance", mutationRequest(req, key, http.StatusCreated), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewEphemeralCredential reviews the JIT request and dual-control rule
// without consuming proof or creating the approval request.
func (c *Client) PreviewEphemeralCredential(ctx context.Context, req EphemeralCredentialRequest) (*EphemeralCredentialPreview, error) {
	var out EphemeralCredentialPreview
	_, err := c.doStatus(ctx, http.MethodPost, "/api/v1/ephemeral/preview", previewRequest(req), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueEphemeralCredential opens or completes a JIT request with an
// SDK-generated idempotency key.
func (c *Client) IssueEphemeralCredential(ctx context.Context, req EphemeralCredentialRequest) (*EphemeralCredential, error) {
	return c.issueEphemeralCredential(ctx, req, "")
}

// IssueEphemeralCredentialKeyed opens or completes a JIT request with the
// caller's stable idempotency key.
func (c *Client) IssueEphemeralCredentialKeyed(ctx context.Context, req EphemeralCredentialRequest, idempotencyKey string) (*EphemeralCredential, error) {
	if err := requireIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	return c.issueEphemeralCredential(ctx, req, idempotencyKey)
}

func (c *Client) issueEphemeralCredential(ctx context.Context, req EphemeralCredentialRequest, key string) (*EphemeralCredential, error) {
	const path = "/api/v1/ephemeral"
	expected := []int{http.StatusCreated, http.StatusAccepted}
	var out EphemeralCredential
	status, err := c.doStatus(ctx, http.MethodPost, path, mutationRequest(req, key, expected...), &out)
	if err != nil {
		return nil, err
	}
	wantState := "issued"
	if status == http.StatusAccepted {
		wantState = "awaiting_approval"
	}
	if out.State != wantState {
		return nil, responseContractError(http.MethodPost, path, status, expected,
			fmt.Sprintf("response state does not match HTTP status; expected %q", wantState))
	}
	return &out, nil
}

// ApproveEphemeralCredential records an independent approval with an
// SDK-generated idempotency key.
func (c *Client) ApproveEphemeralCredential(ctx context.Context, approvalRequestID string, req EphemeralApprovalRequest) (*EphemeralApproval, error) {
	return c.approveEphemeralCredential(ctx, approvalRequestID, req, "")
}

// ApproveEphemeralCredentialKeyed records an independent approval with the
// caller's stable idempotency key.
func (c *Client) ApproveEphemeralCredentialKeyed(ctx context.Context, approvalRequestID string, req EphemeralApprovalRequest, idempotencyKey string) (*EphemeralApproval, error) {
	if err := requireIdempotencyKey(idempotencyKey); err != nil {
		return nil, err
	}
	return c.approveEphemeralCredential(ctx, approvalRequestID, req, idempotencyKey)
}

func (c *Client) approveEphemeralCredential(ctx context.Context, approvalRequestID string, req EphemeralApprovalRequest, key string) (*EphemeralApproval, error) {
	var out EphemeralApproval
	path := "/api/v1/ephemeral/" + url.PathEscape(approvalRequestID) + "/approvals"
	_, err := c.doStatus(ctx, http.MethodPost, path, mutationRequest(req, key, http.StatusOK), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func previewRequest(body any) requestOptions {
	return requestOptions{
		body: body, omitIdempotency: true, effectFree: true,
		expectedStatuses: []int{http.StatusOK}, requireBody: true,
		sensitive: true, noRedirect: true,
	}
}

func mutationRequest(body any, idempotencyKey string, expectedStatuses ...int) requestOptions {
	return requestOptions{
		body: body, idempotencyKey: idempotencyKey,
		expectedStatuses: expectedStatuses, requireBody: true,
		sensitive: true, noRedirect: true,
	}
}

func requireIdempotencyKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("trstctl: caller-supplied Idempotency-Key is empty")
	}
	return nil
}
