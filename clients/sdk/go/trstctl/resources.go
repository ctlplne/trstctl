// SPDX-License-Identifier: MPL-2.0

package trstctl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// The structs below mirror the component schemas in the served OpenAPI contract
// (clients/sdk/openapi.json). Field names use the JSON wire names exactly as the
// API emits them, so a struct here decodes a server response without manual
// remapping. They are intentionally a curated subset focused on the
// getting-started owner/create/list flow plus the lifecycle transition; the
// pinning test (internal/api.TestSDKSpecPinnedToGolden) and `make sdk` keep this
// file honest as the contract evolves — regenerate when the golden changes.

// Owner is a credential owner (a workload, service, team, or user).
type Owner struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Kind      string `json:"kind"` // user | team | workload | service
	Name      string `json:"name"`
	Email     string `json:"email,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// OwnerRequest is the body for creating an owner.
type OwnerRequest struct {
	Kind  string `json:"kind"` // user | team | workload | service (required)
	Name  string `json:"name"` // required
	Email string `json:"email,omitempty"`
}

// Identity is a managed credential identity (certificate, key, secret, …) in its
// lifecycle.
type Identity struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id,omitempty"`
	Kind       string         `json:"kind"` // x509_certificate | ssh_certificate | ssh_key | secret | api_key | workload_identity
	Name       string         `json:"name"`
	OwnerID    string         `json:"owner_id"`
	IssuerID   string         `json:"issuer_id,omitempty"`
	Status     string         `json:"status"`
	NotBefore  string         `json:"not_before,omitempty"`
	NotAfter   string         `json:"not_after,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	CreatedAt  string         `json:"created_at,omitempty"`
}

// IdentityRequest is the body for creating an identity.
type IdentityRequest struct {
	Kind       string         `json:"kind"`     // required
	Name       string         `json:"name"`     // required
	OwnerID    string         `json:"owner_id"` // required
	IssuerID   string         `json:"issuer_id,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// TransitionRequest moves an identity to a new lifecycle state.
type TransitionRequest struct {
	To     string `json:"to"` // issued | deployed | renewing | revoked | retired (required)
	Reason string `json:"reason,omitempty"`
}

// KeyCompromisePlan is an effect-free review of exact CA records and one
// currently served host leaf. The caller must copy its bindings into the
// execution request; the server checks them again before queuing work.
type KeyCompromisePlan struct {
	Capability      string `json:"capability"`
	Ready           bool   `json:"ready"`
	EffectFree      bool   `json:"effect_free"`
	IdentityID      string `json:"identity_id"`
	ExpectedVersion uint64 `json:"expected_version"`
	Target          struct {
		TargetID            string `json:"target_id"`
		TargetName          string `json:"target_name"`
		TargetRevision      string `json:"target_revision"`
		Connector           string `json:"connector"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
		RequiredAgentID     string `json:"required_agent_id"`
	} `json:"target"`
	Certificates []struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
		Serial      string `json:"serial"`
		Authority   string `json:"authority"`
	} `json:"certificates"`
	PreviewFingerprint  string   `json:"preview_fingerprint"`
	RequiredPermissions []string `json:"required_permissions"`
	ExecutionEffects    []string `json:"execution_effects"`
	VerificationSteps   []string `json:"verification_steps"`
}

// KeyCompromiseExecutionRequest carries every exact binding from a ready plan.
type KeyCompromiseExecutionRequest struct {
	TargetID            string `json:"target_id"`
	TargetRevision      string `json:"target_revision"`
	TargetName          string `json:"target_name"`
	Connector           string `json:"connector"`
	IdentityID          string `json:"identity_id"`
	ExpectedFingerprint string `json:"expected_fingerprint"`
	RequiredAgentID     string `json:"required_agent_id"`
	ExpectedVersion     uint64 `json:"expected_version"`
	PreviewFingerprint  string `json:"preview_fingerprint"`
}

// KeyCompromiseResult reports the CA job and host receipt independently.
// A delivered CA command still needs signed revocation and client proof.
type KeyCompromiseResult struct {
	Identity   Identity `json:"identity"`
	Revocation struct {
		ID          int64  `json:"id"`
		Destination string `json:"destination"`
		Status      string `json:"status"`
		Attempts    int    `json:"attempts"`
		LastError   string `json:"last_error,omitempty"`
		DeliveredAt string `json:"delivered_at,omitempty"`
	} `json:"revocation"`
	Containment struct {
		ID          string `json:"id"`
		OutboxID    int64  `json:"outbox_id"`
		IdentityID  string `json:"identity_id"`
		Destination string `json:"destination"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
		Detail      string `json:"detail,omitempty"`
	} `json:"containment"`
}

// Certificate is an issued/discovered X.509 certificate in inventory.
type Certificate struct {
	ID                 string   `json:"id"`
	TenantID           string   `json:"tenant_id"`
	Subject            string   `json:"subject"`
	Fingerprint        string   `json:"fingerprint"`
	Status             string   `json:"status"` // active | superseded | revoked
	Serial             string   `json:"serial,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	KeyAlgorithm       string   `json:"key_algorithm,omitempty"`
	SANs               []string `json:"sans,omitempty"`
	Source             string   `json:"source,omitempty"`
	DeploymentLocation string   `json:"deployment_location,omitempty"`
	OwnerID            string   `json:"owner_id,omitempty"`
	NotBefore          string   `json:"not_before,omitempty"`
	NotAfter           string   `json:"not_after,omitempty"`
	RevokedAt          string   `json:"revoked_at,omitempty"`
	RevocationReason   string   `json:"revocation_reason,omitempty"`
	CreatedAt          string   `json:"created_at,omitempty"`
}

// Page is a single page of a cursor-paginated list. NextCursor is empty on the
// last page. It matches the served list envelope ({ "items": [...],
// "next_cursor": "..." }) used across the API.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// ListOptions are the common cursor-pagination knobs for List* calls.
type ListOptions struct {
	// Limit is items per page (server clamps to 1..100, default 20). Zero means
	// "let the server decide".
	Limit int
	// Cursor is an opaque cursor from a prior page's NextCursor.
	Cursor string
}

func (o ListOptions) query() url.Values {
	q := url.Values{}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Cursor != "" {
		q.Set("cursor", o.Cursor)
	}
	return q
}

// ---- Owners -----------------------------------------------------------------

// CreateOwner creates an owner (POST /api/v1/owners). A mutation, so it carries
// an Idempotency-Key (auto-generated unless you set one with CreateOwnerKeyed).
func (c *Client) CreateOwner(ctx context.Context, req OwnerRequest) (*Owner, error) {
	return c.createOwner(ctx, req, "")
}

// CreateOwnerKeyed is CreateOwner with a caller-supplied Idempotency-Key, so a
// retry of the same logical create is exactly-once even across process
// restarts.
func (c *Client) CreateOwnerKeyed(ctx context.Context, req OwnerRequest, idempotencyKey string) (*Owner, error) {
	return c.createOwner(ctx, req, idempotencyKey)
}

func (c *Client) createOwner(ctx context.Context, req OwnerRequest, key string) (*Owner, error) {
	var out Owner
	err := c.do(ctx, http.MethodPost, "/api/v1/owners", requestOptions{body: req, idempotencyKey: key}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOwners returns one page of owners (GET /api/v1/owners).
func (c *Client) ListOwners(ctx context.Context, opts ListOptions) (*Page[Owner], error) {
	var out Page[Owner]
	err := c.do(ctx, http.MethodGet, "/api/v1/owners", requestOptions{query: opts.query()}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Owners returns an Iterator that pages through every owner.
func (c *Client) Owners(opts ListOptions) *Iterator[Owner] {
	return newIterator(opts, func(ctx context.Context, o ListOptions) (*Page[Owner], error) {
		return c.ListOwners(ctx, o)
	})
}

// ---- Identities -------------------------------------------------------------

// CreateIdentity creates an identity (POST /api/v1/identities). Carries an
// Idempotency-Key (AN-5).
func (c *Client) CreateIdentity(ctx context.Context, req IdentityRequest) (*Identity, error) {
	return c.createIdentity(ctx, req, "")
}

// CreateIdentityKeyed is CreateIdentity with a caller-supplied Idempotency-Key.
func (c *Client) CreateIdentityKeyed(ctx context.Context, req IdentityRequest, idempotencyKey string) (*Identity, error) {
	return c.createIdentity(ctx, req, idempotencyKey)
}

func (c *Client) createIdentity(ctx context.Context, req IdentityRequest, key string) (*Identity, error) {
	var out Identity
	err := c.do(ctx, http.MethodPost, "/api/v1/identities", requestOptions{body: req, idempotencyKey: key}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetIdentity fetches one identity by id (GET /api/v1/identities/{id}).
func (c *Client) GetIdentity(ctx context.Context, id string) (*Identity, error) {
	var out Identity
	err := c.do(ctx, http.MethodGet, "/api/v1/identities/"+url.PathEscape(id), requestOptions{}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListIdentities returns one page of identities (GET /api/v1/identities).
func (c *Client) ListIdentities(ctx context.Context, opts ListOptions) (*Page[Identity], error) {
	var out Page[Identity]
	err := c.do(ctx, http.MethodGet, "/api/v1/identities", requestOptions{query: opts.query()}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Identities returns an Iterator that pages through every identity.
func (c *Client) Identities(opts ListOptions) *Iterator[Identity] {
	return newIterator(opts, func(ctx context.Context, o ListOptions) (*Page[Identity], error) {
		return c.ListIdentities(ctx, o)
	})
}

// TransitionIdentity moves an identity to a new lifecycle state
// (POST /api/v1/identities/{id}/transitions). Carries an Idempotency-Key.
// Transitioning to "issued" drives the server's outbox to mint the certificate.
func (c *Client) TransitionIdentity(ctx context.Context, id, to, reason string) (*Identity, error) {
	return c.transitionIdentity(ctx, id, to, reason, "")
}

// TransitionIdentityKeyed is TransitionIdentity with a caller-supplied
// Idempotency-Key.
func (c *Client) TransitionIdentityKeyed(ctx context.Context, id, to, reason, idempotencyKey string) (*Identity, error) {
	return c.transitionIdentity(ctx, id, to, reason, idempotencyKey)
}

func (c *Client) transitionIdentity(ctx context.Context, id, to, reason, key string) (*Identity, error) {
	var out Identity
	body := TransitionRequest{To: to, Reason: reason}
	err := c.do(ctx, http.MethodPost, "/api/v1/identities/"+url.PathEscape(id)+"/transitions",
		requestOptions{body: body, idempotencyKey: key}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewKeyCompromise reviews both receiver effects without creating work.
func (c *Client) PreviewKeyCompromise(ctx context.Context, identityID, targetID string) (*KeyCompromisePlan, error) {
	var out KeyCompromisePlan
	err := c.do(ctx, http.MethodPost, "/api/v1/identities/"+url.PathEscape(identityID)+"/compromise/preview",
		requestOptions{body: map[string]string{"target_id": targetID}}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ExecuteKeyCompromise queues one reviewed compound command under a caller-
// stable key. Its result is acceptance, not a claim that either receiver ran.
func (c *Client) ExecuteKeyCompromise(ctx context.Context, identityID string,
	reviewed KeyCompromiseExecutionRequest, key string) (*KeyCompromiseResult, error) {
	if key == "" {
		return nil, errors.New("trstctl: key compromise requires a caller-stable Idempotency-Key")
	}
	var out KeyCompromiseResult
	err := c.do(ctx, http.MethodPost, "/api/v1/identities/"+url.PathEscape(identityID)+"/compromise",
		requestOptions{body: reviewed, idempotencyKey: key}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// KeyCompromiseStatus reads both receiver outcomes by the original key.
func (c *Client) KeyCompromiseStatus(ctx context.Context, identityID, key string) (*KeyCompromiseResult, error) {
	var out KeyCompromiseResult
	q := url.Values{"request_key": {key}}
	err := c.do(ctx, http.MethodGet, "/api/v1/identities/"+url.PathEscape(identityID)+"/compromise?"+q.Encode(),
		requestOptions{}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Certificates -----------------------------------------------------------

// CertificateListOptions extends ListOptions with the certificate-specific
// expiring_before filter.
type CertificateListOptions struct {
	ListOptions
	// ExpiringBefore (RFC3339) returns only certificates expiring before this
	// time. Empty means no filter.
	ExpiringBefore string
}

func (o CertificateListOptions) query() url.Values {
	q := o.ListOptions.query()
	if o.ExpiringBefore != "" {
		q.Set("expiring_before", o.ExpiringBefore)
	}
	return q
}

// ListCertificates returns one page of certificates from inventory
// (GET /api/v1/certificates).
func (c *Client) ListCertificates(ctx context.Context, opts CertificateListOptions) (*Page[Certificate], error) {
	var out Page[Certificate]
	err := c.do(ctx, http.MethodGet, "/api/v1/certificates", requestOptions{query: opts.query()}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Certificates returns an Iterator that pages through every certificate.
func (c *Client) Certificates(opts CertificateListOptions) *Iterator[Certificate] {
	// The certificate filter (ExpiringBefore) must be carried on every page, so
	// the iterator advances only the cursor and re-applies the filter.
	return &Iterator[Certificate]{
		opts: opts.ListOptions,
		fetch: func(ctx context.Context, o ListOptions) (*Page[Certificate], error) {
			return c.ListCertificates(ctx, CertificateListOptions{ListOptions: o, ExpiringBefore: opts.ExpiringBefore})
		},
	}
}

// ---- Convenience: getting-started one-call issuance -------------------------

// IssueFirstCertificate runs the documented getting-started flow as one call:
// it creates a workload owner named name, creates an x509_certificate identity
// owned by it, and transitions that identity to "issued" (which drives the
// server's outbox to mint the certificate). It returns the issued identity.
//
// Each step is a mutation and carries its own Idempotency-Key, so a transient
// failure that the SDK retries cannot create duplicate owners/identities.
func (c *Client) IssueFirstCertificate(ctx context.Context, name string) (*Identity, error) {
	owner, err := c.CreateOwner(ctx, OwnerRequest{Kind: "workload", Name: name})
	if err != nil {
		return nil, err
	}
	ident, err := c.CreateIdentity(ctx, IdentityRequest{
		Kind:    "x509_certificate",
		Name:    name,
		OwnerID: owner.ID,
	})
	if err != nil {
		return nil, err
	}
	return c.TransitionIdentity(ctx, ident.ID, "issued", "first issuance via Go SDK")
}
