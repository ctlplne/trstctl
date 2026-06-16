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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
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
	ExpiresAt       time.Time
}

// RedeemedToken is what a TokenStore returns when a token is consumed: the
// authorizing tenant and any identity the token was pinned to.
type RedeemedToken struct {
	TenantID        string
	AllowedIdentity string
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
	SignClientCSRWithTenant(csrDER []byte, tenantID string, ttl time.Duration) ([]byte, error)
	// BundlePEM is the CA certificate (PEM) agents pin and that anchors issued certs.
	BundlePEM() []byte
}

// Authority issues agent client certificates: it mints tenant-bound one-time
// bootstrap tokens, redeems them single-use through a durable TokenStore, and
// signs CSRs through its CA issuer — stamping the redeemed tenant into the issued
// certificate.
type Authority struct {
	ca    CAIssuer
	store TokenStore
	ttl   time.Duration
}

// NewAuthority creates an enrollment authority with a fresh IN-PROCESS mTLS CA and a
// durable, tenant-scoped TokenStore. The store makes bootstrap tokens restart-safe,
// multi-instance-safe, and tenant-attributed (WIRE-003). The in-process CA key is
// regenerated per process; for a CA whose key is custodied in the signer and stable
// across restarts (WIRE-004), use NewAuthorityWithIssuer with the agent-channel CA.
func NewAuthority(commonName string, store TokenStore) (*Authority, error) {
	if store == nil {
		return nil, errors.New("enroll: a TokenStore is required")
	}
	ca, err := mtls.NewCA(commonName)
	if err != nil {
		return nil, err
	}
	return &Authority{ca: ca, store: store, ttl: DefaultTokenTTL}, nil
}

// NewAuthorityWithIssuer creates an enrollment authority that signs through the given
// CAIssuer — used by the served control plane to bootstrap-enroll agents through the
// SAME signer-custodied agent CA the steady-state channel trusts (WIRE-004), so an
// agent's bootstrap certificate is accepted on the channel and survives a restart.
func NewAuthorityWithIssuer(ca CAIssuer, store TokenStore) (*Authority, error) {
	if store == nil {
		return nil, errors.New("enroll: a TokenStore is required")
	}
	if ca == nil {
		return nil, errors.New("enroll: a CA issuer is required")
	}
	return &Authority{ca: ca, store: store, ttl: DefaultTokenTTL}, nil
}

// IssueBootstrapToken mints a one-time bootstrap token bound to tenantID (and,
// optionally, to allowedIdentity — the agent common name it may enroll as; empty
// means any). The raw token is returned once; only its hash is stored. A token
// minted here is durable and tenant-scoped, so it survives restarts, is
// redeemable on any instance, and yields a tenant-attributed certificate.
func (a *Authority) IssueBootstrapToken(ctx context.Context, tenantID, allowedIdentity string) (string, error) {
	if tenantID == "" {
		return "", errors.New("enroll: refusing to mint a bootstrap token without a tenant")
	}
	b, err := crypto.RandomBytes(24)
	if err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	hash, err := hashToken(token)
	if err != nil {
		return "", err
	}
	if err := a.store.Save(ctx, MintedToken{
		TokenHash:       hash,
		TenantID:        tenantID,
		AllowedIdentity: allowedIdentity,
		ExpiresAt:       time.Now().Add(a.ttl),
	}); err != nil {
		return "", err
	}
	return token, nil
}

// EnrollBootstrap consumes a one-time token (single-use, via the durable store)
// and signs the agent's CSR into a client-certificate chain (PEM) stamped with
// the redeeming token's tenant (AN-1). The tenant comes from the token, never the
// CSR, so a token cannot mint a certificate attributed to a different tenant. When
// the token pins an allowed identity, a CSR whose common name differs is rejected.
func (a *Authority) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	hash, err := hashToken(token)
	if err != nil {
		return nil, err
	}
	redeemed, err := a.store.Redeem(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrBadToken) {
			return nil, ErrBadToken
		}
		return nil, err
	}
	if redeemed.AllowedIdentity != "" {
		cn, err := mtls.CSRCommonName(csrDER)
		if err != nil {
			return nil, err
		}
		if cn != redeemed.AllowedIdentity {
			return nil, ErrBadToken
		}
	}
	return a.ca.SignClientCSRWithTenant(csrDER, redeemed.TenantID, mtls.ClientCertTTL)
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
func (a *Authority) EnrollRenewal(_ context.Context, peerCertsDER [][]byte, csrDER []byte) ([]byte, error) {
	if len(peerCertsDER) == 0 || len(peerCertsDER[0]) == 0 {
		return nil, ErrUnauthenticatedRenewal
	}
	tenantID, err := mtls.TenantFromClientCert(peerCertsDER[0])
	if err != nil {
		// A verified client cert that carries no tenant SPIFFE SAN is not an agent
		// identity this CA issued; refuse rather than mint an unattributed cert.
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticatedRenewal, err)
	}
	return a.ca.SignClientCSRWithTenant(csrDER, tenantID, mtls.ClientCertTTL)
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

// hashToken returns the deterministic lookup hash of a raw bootstrap token
// (SHA-256 hex), computed through the crypto boundary (AN-3). Only the hash is
// stored, never the raw token.
func hashToken(token string) (string, error) {
	sum, err := crypto.Digest(crypto.SHA256, []byte(token))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
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
func (m *MemoryTokenStore) Redeem(_ context.Context, tokenHash string) (RedeemedToken, error) {
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
	return RedeemedToken{TenantID: t.TenantID, AllowedIdentity: t.AllowedIdentity}, nil
}
