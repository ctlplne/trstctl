// SPDX-License-Identifier: BUSL-1.1

// Package enroll is the control-plane side of agent enrollment (F3/F15, sprint
// S5.1): it issues one-time bootstrap tokens, signs agents' CSRs into short-lived
// mTLS client certificates, and serves the mutual-TLS transport credentials.
// Agents generate their keys locally and submit only CSRs, so private keys never
// reach the control plane. All signing routes through the internal/crypto/mtls
// boundary (AN-3); in production the CA key is custodied by the signer (AN-4).
//
// Bootstrap tokens are bound to the authorizing tenant at mint and redeemed
// single-use through a durable, tenant-scoped TokenStore (WIRE-003): a token
// survives a control-plane restart, is redeemable on any instance, and can be
// redeemed at most once across the whole deployment. The issued certificate is
// stamped with the authorizing tenant's SPIFFE SAN (AN-1) so the mTLS consumer
// derives the tenant from the certificate, never from the (attacker-chosen) CSR
// subject or a request header.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenancy"
)

// ErrBadToken is returned when a bootstrap token is unknown, expired, or already
// used. It is deliberately coarse so a caller cannot distinguish those cases.
var ErrBadToken = errors.New("enroll: invalid, expired, or already-used bootstrap token")

// DefaultTokenTTL is how long a freshly minted bootstrap token is redeemable. A
// bootstrap token is meant to be used promptly during provisioning, so the window
// is short.
const DefaultTokenTTL = 1 * time.Hour

// MintedToken is a stored bootstrap token bound to its authorizing tenant. Only
// the token's hash is persisted; the raw secret is returned once at mint.
type MintedToken struct {
	TokenHash       string
	TenantID        string
	AllowedIdentity string
	// Roles is the capability grant this token carries into the issued
	// certificate (epic A2): mtls.AgentRoleHost, mtls.AgentRoleNetwork, or both.
	// Empty means host-only. It is recorded at MINT — an operator's decision made
	// when they hand the token out — so redemption has nothing to negotiate.
	Roles     []string
	ExpiresAt time.Time
}

// RedeemedToken is what a TokenStore returns when a token is consumed: the
// authorizing tenant and any identity the token was pinned to.
type RedeemedToken struct {
	TenantID        string
	AllowedIdentity string
	// Roles is the capability grant recorded at mint. The CA stamps these into
	// the certificate; the agent never gets to name its own (epic A2).
	Roles []string
}

// TokenStore persists tenant-bound, single-use bootstrap tokens durably. The
// store package's *store.Store satisfies it (adapted in internal/server); tests
// and the standalone HTTP transport use the in-memory implementation below. Save
// records a minted token; Redeem atomically consumes it by hash and returns its
// tenant — and must reject a second redemption of the same token (single-use)
// across instances and restarts.
type TokenStore interface {
	Save(ctx context.Context, t MintedToken) error
	// Redeem consumes the token with tokenHash exactly once. It returns ErrBadToken
	// (recognizable via errors.Is) when the token is unknown, expired, or already
	// used.
	Redeem(ctx context.Context, tokenHash string) (RedeemedToken, error)
}

// CAIssuer is the agent CA an Authority signs through. It signs a CSR into a
// tenant-attributed client-certificate chain (PEM) and exposes its CA bundle (the
// trust anchor agents pin). Two implementations exist: the in-process *mtls.CA (the
// library/standalone default, whose key is regenerated per process) and a
// signer-custodied agent CA (WIRE-004), whose key lives in the isolated signer (AN-4)
// and is STABLE across restarts — so an agent's pinned CA does not change on a
// control-plane restart. The mTLS consumer derives the tenant from the certificate's
// SPIFFE SAN, never the CSR (WIRE-003/AN-1), which is why the issuer takes the tenant
// explicitly rather than reading it from the CSR.
type CAIssuer interface {
	// SignClientCSRWithTenant signs csrDER as a ClientAuth certificate valid for ttl,
	// stamped with tenantID's SPIFFE SAN (refusing an empty tenant). Returns leaf||CA
	// in PEM.
	// roles are the capability SANs to stamp alongside the identity (epic A2),
	// taken from the operator's grant and never from the CSR. Empty is host-only.
	SignClientCSRWithTenant(csrDER []byte, tenantID string, roles []string, ttl time.Duration) ([]byte, error)
	// BundlePEM is the CA certificate (PEM) agents pin and that anchors issued certs.
	BundlePEM() []byte
}

// Authority issues agent client certificates: it mints tenant-bound one-time
// bootstrap tokens, redeems them single-use through a durable TokenStore, and
// signs CSRs through its CA issuer — stamping the redeemed tenant into the issued
// certificate.
type Authority struct {
	tenantServiceCheck tenancy.ServiceCheck
	ca                 CAIssuer
	store              TokenStore
	ttl                time.Duration
}

// Option configures admission before the authority is served.
type Option func(*Authority)

// WithTenantServiceCheck gates both bootstrap and renewal signing against live
// tenant authority. A rejected bootstrap token remains consumed, like a CSR
// identity mismatch: the operator must mint a fresh token after recovery.
func WithTenantServiceCheck(check tenancy.ServiceCheck) Option {
	return func(a *Authority) { a.tenantServiceCheck = check }
}

// NewAuthority creates an enrollment authority with a fresh IN-PROCESS mTLS CA and a
// durable, tenant-scoped TokenStore. The store makes bootstrap tokens restart-safe,
// multi-instance-safe, and tenant-attributed (WIRE-003). The in-process CA key is
// regenerated per process; for a CA whose key is custodied in the signer and stable
// across restarts (WIRE-004), use NewAuthorityWithIssuer with the agent-channel CA.
func NewAuthority(commonName string, store TokenStore, options ...Option) (*Authority, error) {
	if store == nil {
		return nil, errors.New("enroll: a TokenStore is required")
	}
	ca, err := mtls.NewCA(commonName)
	if err != nil {
		return nil, err
	}
	a := &Authority{ca: ca, store: store, ttl: DefaultTokenTTL}
	for _, option := range options {
		if option != nil {
			option(a)
		}
	}
	return a, nil
}

// NewAuthorityWithIssuer creates an enrollment authority that signs through the given
// CAIssuer — used by the served control plane to bootstrap-enroll agents through the
// SAME signer-custodied agent CA the steady-state channel trusts (WIRE-004), so an
// agent's bootstrap certificate is accepted on the channel and survives a restart.
func NewAuthorityWithIssuer(ca CAIssuer, store TokenStore, options ...Option) (*Authority, error) {
	if store == nil {
		return nil, errors.New("enroll: a TokenStore is required")
	}
	if ca == nil {
		return nil, errors.New("enroll: a CA issuer is required")
	}
	a := &Authority{ca: ca, store: store, ttl: DefaultTokenTTL}
	for _, option := range options {
		if option != nil {
			option(a)
		}
	}
	return a, nil
}

// IssueBootstrapToken mints a one-time bootstrap token bound to tenantID (and,
// optionally, to allowedIdentity — the agent common name it may enroll as; empty
// means any). The raw token is returned once; only its hash is stored. A token
// minted here is durable and tenant-scoped, so it survives restarts, is
// redeemable on any instance, and yields a tenant-attributed certificate.
func (a *Authority) IssueBootstrapToken(
	ctx context.Context,
	tenantID, allowedIdentity string,
) ([]byte, error) {
	return a.IssueBootstrapTokenWithRoles(ctx, tenantID, allowedIdentity, nil)
}

// IssueBootstrapTokenWithRoles mints a bootstrap token that additionally carries a
// capability grant (epic A2). The roles are recorded with the token and stamped
// into the issued certificate by the CA, so what an agent may be asked to do is
// decided by the operator who minted the token — not by a flag the agent passes
// at startup, and not by anything it puts in its CSR.
//
// An unknown role is refused here rather than dropped silently: an operator who
// asked for a capability that does not exist should be told so, not handed a
// token that quietly grants less than they think.
func (a *Authority) IssueBootstrapTokenWithRoles(
	ctx context.Context,
	tenantID, allowedIdentity string,
	roles []string,
) ([]byte, error) {
	if tenantID == "" {
		return nil, errors.New("enroll: refusing to mint a bootstrap token without a tenant")
	}
	for _, role := range roles {
		if !mtls.ValidAgentRole(role) {
			return nil, fmt.Errorf("enroll: unknown agent role %q", role)
		}
	}
	granted := mtls.NormalizeAgentRoles(roles)
	b, err := crypto.RandomBytes(24)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(b)
	token := crypto.AppendBase64RawURL(nil, b)
	hash := bootstrapLookupHash(token)
	if err := a.store.Save(ctx, MintedToken{
		TokenHash:       hash,
		TenantID:        tenantID,
		AllowedIdentity: allowedIdentity,
		Roles:           granted,
		ExpiresAt:       time.Now().Add(a.ttl),
	}); err != nil {
		secret.Wipe(token)
		return nil, err
	}
	return token, nil
}

// EnrollBootstrap consumes a one-time token (single-use, via the durable store)
// and signs the agent's CSR into a client-certificate chain (PEM) stamped with
// the redeeming token's tenant (AN-1). The tenant comes from the token, never the
// CSR, so a token cannot mint a certificate attributed to a different tenant. When
// the token pins an allowed identity, a CSR whose common name or identity SANs
// differ is rejected.
func (a *Authority) EnrollBootstrap(ctx context.Context, token []byte, csrDER []byte) ([]byte, error) {
	hash := bootstrapLookupHash(token)
	redeemed, err := a.store.Redeem(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrBadToken) {
			return nil, ErrBadToken
		}
		return nil, err
	}
	if err := a.tenantServiceCheck.Check(ctx, redeemed.TenantID); err != nil {
		return nil, err
	}
	if redeemed.AllowedIdentity != "" {
		matches, err := mtls.CSRMatchesAllowedIdentity(csrDER, redeemed.AllowedIdentity)
		if err != nil {
			return nil, err
		}
		if !matches {
			return nil, ErrBadToken
		}
	}
	return a.ca.SignClientCSRWithTenant(csrDER, redeemed.TenantID, redeemed.Roles, mtls.ClientCertTTL)
}

// ErrUnauthenticatedRenewal is returned when a renewal arrives without a verified
// client certificate to authenticate the caller. Renewal mints a fresh client
// certificate, so an unauthenticated renewal would be an open cert-minting
// endpoint; the gate is enforced in code here, not by deployment topology
// (WIRE-006).
var ErrUnauthenticatedRenewal = errors.New("enroll: renewal requires a verified client certificate")

// EnrollRenewal signs a rotation CSR into a fresh client certificate chain. The
// caller MUST already be authenticated by its current mTLS client certificate:
// peerCertsDER is the verified peer chain (leaf first), as produced by the TLS
// stack's VerifiedChains. The renewed certificate is bound to the SAME tenant the
// existing certificate carries in its SPIFFE SAN (WIRE-003/AN-1) — never the
// (attacker-chosen) CSR subject — so a renewal cannot change tenant or escalate.
//
// This authentication is enforced in code, not by the deployment's TLS topology:
// the earlier version signed ANY CSR with no caller check, relying on a comment
// that "the deployment's mutual-TLS server" gated it — a control that did not exist
// in code (WIRE-006). A renewal with no verified peer certificate is now rejected
// with ErrUnauthenticatedRenewal regardless of how the handler is mounted.
func (a *Authority) EnrollRenewal(ctx context.Context, peerCertsDER [][]byte, csrDER []byte) ([]byte, error) {
	if len(peerCertsDER) == 0 || len(peerCertsDER[0]) == 0 {
		return nil, ErrUnauthenticatedRenewal
	}
	tenantID, err := mtls.TenantFromClientCert(peerCertsDER[0])
	if err != nil {
		// A verified client cert that carries no tenant SPIFFE SAN is not an agent
		// identity this CA issued; refuse rather than mint an unattributed cert.
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticatedRenewal, err)
	}
	if err := a.tenantServiceCheck.Check(ctx, tenantID); err != nil {
		return nil, err
	}
	// Roles are carried over from the certificate being renewed, never re-derived
	// and never taken from the CSR (epic A2). A renewal is a rotation of the same
	// identity: it cannot gain a capability, and — just as importantly — it cannot
	// lose one, which is what would happen if renewal signed with no roles at all.
	// Changing an agent's role is a re-enrollment, not a rotation.
	roles, err := mtls.AgentRolesFromClientCert(peerCertsDER[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticatedRenewal, err)
	}
	return a.ca.SignClientCSRWithTenant(csrDER, tenantID, roles, mtls.ClientCertTTL)
}

// CABundlePEM is the CA certificate (PEM) an agent trusts to verify the control
// plane and that anchors issued client certificates.
func (a *Authority) CABundlePEM() []byte { return a.ca.BundlePEM() }

// ServerCredentials returns mutual-TLS transport credentials for the in-process
// agent gRPC server, presenting a server certificate for dnsNames. It is only
// available when the authority uses the in-process *mtls.CA (the library/standalone
// path); for a signer-custodied agent CA (WIRE-004) the served channel mints its own
// server credentials through the crypto boundary (internal/server), so this returns an
// error rather than exposing the CA key. It is retained for the standalone transport.
func (a *Authority) ServerCredentials(dnsNames []string) (credentials.TransportCredentials, error) {
	ca, ok := a.ca.(*mtls.CA)
	if !ok {
		return nil, errors.New("enroll: ServerCredentials is only available for the in-process CA; the served channel builds its own credentials")
	}
	return ca.ServerCredentials(dnsNames, 24*time.Hour)
}

// bootstrapLookupHash returns the deterministic lookup hash of a raw bootstrap token
// (SHA-256 hex), computed through the crypto boundary (AN-3). Only the hash is
// stored, never the raw token.
func bootstrapLookupHash(token []byte) string {
	return crypto.SHA256Hex(token)
}

// MemoryTokenStore is an in-process TokenStore for the standalone HTTP enrollment
// transport and tests. It is durable only for the process lifetime — production
// uses the PostgreSQL-backed store (the WIRE-003 fix). It is concurrency-safe and
// enforces single-use, tenant binding, and expiry exactly like the durable store.
type MemoryTokenStore struct {
	mu     sync.Mutex
	tokens map[string]MintedToken
}

// NewMemoryTokenStore creates an empty in-memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{tokens: map[string]MintedToken{}}
}

// Save records a minted token.
func (m *MemoryTokenStore) Save(_ context.Context, t MintedToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.TokenHash] = t
	return nil
}

// Redeem consumes a token by hash exactly once, rejecting unknown, expired, or
// already-used tokens.
func (m *MemoryTokenStore) Redeem(
	_ context.Context,
	tokenHash string,
) (RedeemedToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[tokenHash]
	if !ok {
		return RedeemedToken{}, ErrBadToken
	}
	delete(m.tokens, tokenHash) // single-use: gone after first redemption
	if time.Now().After(t.ExpiresAt) {
		return RedeemedToken{}, ErrBadToken
	}
	return RedeemedToken{
		TenantID:        t.TenantID,
		AllowedIdentity: t.AllowedIdentity,
		Roles:           t.Roles,
	}, nil
}
