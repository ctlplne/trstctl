package trstctl

import (
	"context"
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
