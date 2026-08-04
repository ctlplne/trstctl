// SPDX-License-Identifier: MPL-2.0

// Package spiffe implements the SPIFFE Workload API (S11.1): it issues
// SPIFFE-standard workload identities — X.509-SVIDs and JWT-SVIDs — to callers
// that match a registration entry's selectors, distributes the trust bundle, and
// supports rotation-before-expiry. It is SPIRE-compatible in shape: registration
// entries bind a SPIFFE ID to the selectors a workload must present, and a caller
// receives an SVID for every entry whose selectors it satisfies.
//
// Non-negotiables: issuance is audited (AN-2) and tenant-scoped (AN-1); SVIDs are
// signed through the AN-3 crypto boundary backed by the isolated signer (AN-4);
// the issuance path is bulkheaded (AN-7). Attestation (which gates *which*
// workload may receive an identity) is S11.2/S11.9 and layers on top of this.
package spiffe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

// ErrNoIdentity is returned when a caller's selectors match no registration
// entry: the Workload API issues nothing rather than guessing (fail-closed).
var ErrNoIdentity = errors.New("spiffe: no registered identity for caller selectors")

// Issuer is the seam between the Workload API and the CA / isolated signer. The
// Workload API decides *which* identities a caller may hold; the Issuer turns an
// authorized SPIFFE ID into a signed SVID through the crypto boundary.
type Issuer interface {
	SignX509SVID(ctx context.Context, spiffeID string, pubDER []byte, ttl time.Duration) (certDER []byte, err error)
	SignJWTSVID(ctx context.Context, spiffeID string, audience []string, ttl time.Duration) (token string, err error)
	X509Bundle(ctx context.Context) (caDER [][]byte, err error)
	JWTBundle(ctx context.Context) (crypto.JWKS, error)
}

// CAIssuer is the default Issuer: an X.509 CA mints X509-SVIDs and a JWT signing
// key mints JWT-SVIDs. Both are DigestSigners, so the private keys live in the
// isolated signer (AN-4) and never cross the boundary in the clear.
type CAIssuer struct {
	CACertDER []byte
	CASigner  crypto.DigestSigner
	JWTSigner crypto.DigestSigner
	JWTKeyID  string
}

// SignX509SVID implements Issuer.
func (c *CAIssuer) SignX509SVID(_ context.Context, spiffeID string, pubDER []byte, ttl time.Duration) ([]byte, error) {
	return crypto.SignSVID(c.CACertDER, c.CASigner, pubDER, spiffeID, ttl)
}

// SignJWTSVID implements Issuer.
func (c *CAIssuer) SignJWTSVID(_ context.Context, spiffeID string, audience []string, ttl time.Duration) (string, error) {
	if len(audience) == 0 {
		return "", fmt.Errorf("spiffe: JWT-SVID requires at least one audience")
	}
	now := time.Now()
	claims := map[string]any{
		"sub": spiffeID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	return crypto.SignJWT(c.JWTSigner, c.JWTKeyID, claims)
}

// X509Bundle implements Issuer.
func (c *CAIssuer) X509Bundle(context.Context) ([][]byte, error) {
	return [][]byte{c.CACertDER}, nil
}

// JWTBundle implements Issuer.
func (c *CAIssuer) JWTBundle(context.Context) (crypto.JWKS, error) {
	jwk, err := crypto.PublicJWK(c.JWTSigner.Public(), c.JWTKeyID)
	if err != nil {
		return crypto.JWKS{}, err
	}
	return crypto.JWKS{Keys: []crypto.JWK{jwk}}, nil
}

// RegistrationEntry binds a SPIFFE ID to the workload selectors that authorize
// it. A caller receives an SVID for the entry only if it presents *every*
// selector the entry requires (SPIRE semantics).
type RegistrationEntry struct {
	SPIFFEID  string
	Selectors []string
	X509TTL   time.Duration
	JWTTTL    time.Duration
	// ParentID scopes this entry to the node that may deliver it (epic B3).
	//
	// SPIRE's name for the same idea, and the same reason: once a host agent can
	// ask for SVIDs on a workload's behalf, "which selectors did you observe" is
	// a claim made by that agent, and an agent that could claim any selectors
	// could obtain any workload's identity in the trust domain. A compromise of
	// one host would become a compromise of every service.
	//
	// EMPTY MEANS NOT AGENT-DELIVERABLE — not "any agent". An entry an operator
	// has not scoped to a node stays reachable only on the control plane's own
	// socket, exactly as before this epic. That keeps every existing entry
	// working unchanged while making agent delivery something an operator turns
	// on per entry, and it means the failure direction of a forgotten field is a
	// refusal rather than a silent widening of who can impersonate a workload.
	ParentID string
}

// Config configures a Workload API Server.
type Config struct {
	Issuer   Issuer
	TenantID string
	// TrustDomain is the SPIFFE trust domain (e.g. "example.org") this server's
	// SVIDs and bundle belong to. It labels the bundle map in the gRPC Workload API
	// X509Bundles response. Optional for the library FetchX509SVIDs path.
	TrustDomain    string
	Entries        []RegistrationEntry
	DefaultX509TTL time.Duration
	DefaultJWTTTL  time.Duration
	Pool           *bulkhead.Pool    // AN-7; nil runs inline
	Audit          auditsink.Auditor // AN-2; nil = no-op
	Graph          *graph.Graph      // F21; nil = not mapped
}

// Server is the SPIFFE Workload API.
type Server struct {
	cfg Config
}

// New validates the configuration and constructs a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == nil {
		return nil, fmt.Errorf("spiffe: Issuer is required")
	}
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("spiffe: TenantID is required (AN-1)")
	}
	if cfg.DefaultX509TTL <= 0 {
		cfg.DefaultX509TTL = time.Hour
	}
	if cfg.DefaultJWTTTL <= 0 {
		cfg.DefaultJWTTTL = 5 * time.Minute
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	for i := range cfg.Entries {
		if _, err := crypto.ParseSPIFFEID(cfg.Entries[i].SPIFFEID); err != nil {
			return nil, fmt.Errorf("spiffe: entry %d: %w", i, err)
		}
	}
	return &Server{cfg: cfg}, nil
}

// X509SVID is an issued X.509-SVID with its trust bundle.
type X509SVID struct {
	SPIFFEID  string
	CertChain [][]byte // leaf DER first
	Bundle    [][]byte // trust-domain CA DER
	ExpiresAt time.Time
}

// JWTSVID is an issued JWT-SVID.
type JWTSVID struct {
	SPIFFEID  string
	Token     string
	ExpiresAt time.Time
}

// FetchX509SVIDs issues an X.509-SVID for every registration entry whose
// selectors the caller satisfies, over the caller's public key (PKIX DER).
func (s *Server) FetchX509SVIDs(ctx context.Context, pubDER []byte, selectors []string) ([]X509SVID, error) {
	return s.fetchX509(ctx, "", pubDER, selectors)
}

func (s *Server) fetchX509(ctx context.Context, parentID string, pubDER []byte, selectors []string) ([]X509SVID, error) {
	var out []X509SVID
	err := s.run(func() error {
		entries := s.matchedForParent(selectors, parentID)
		if len(entries) == 0 {
			return ErrNoIdentity
		}
		bundle, err := s.cfg.Issuer.X509Bundle(ctx)
		if err != nil {
			return err
		}
		for _, e := range entries {
			ttl := e.X509TTL
			if ttl <= 0 {
				ttl = s.cfg.DefaultX509TTL
			}
			certDER, err := s.cfg.Issuer.SignX509SVID(ctx, e.SPIFFEID, pubDER, ttl)
			if err != nil {
				return fmt.Errorf("spiffe: sign X509-SVID %s: %w", e.SPIFFEID, err)
			}
			_, notAfter, err := crypto.CertValidity(certDER)
			if err != nil {
				return err
			}
			out = append(out, X509SVID{SPIFFEID: e.SPIFFEID, CertChain: [][]byte{certDER}, Bundle: bundle, ExpiresAt: notAfter})
			s.recordIssued(ctx, "x509", e.SPIFFEID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FetchX509SVIDsForNode issues X.509-SVIDs on behalf of a workload attested by a
// host agent (epic B3).
//
// Identical to FetchX509SVIDs except that the entries it will consider are the
// ones scoped to THIS node. That difference is the whole security story of
// moving the Workload API onto hosts: the selectors arrive as an agent's claim
// about a process it inspected, and a claim is only as good as the bound on what
// it can unlock. Scoping to the node bounds it — a compromised agent can
// impersonate the workloads on its own machine, which it could do anyway by
// reading their memory, and nothing else in the trust domain.
//
// nodeID must be the agent's own authenticated identity, taken from the
// certificate it presented on the channel, never from anything in the request.
func (s *Server) FetchX509SVIDsForNode(ctx context.Context, nodeID string, pubDER []byte, selectors []string) ([]X509SVID, error) {
	if strings.TrimSpace(nodeID) == "" {
		// An empty node would select the unscoped entries — the ones reserved
		// for the control plane's own socket — so a caller that failed to
		// identify its node must be refused rather than defaulted.
		return nil, ErrNoIdentity
	}
	return s.fetchX509(ctx, nodeID, pubDER, selectors)
}

// FetchJWTSVIDsForNode is FetchJWTSVIDs scoped to a delivering node (epic B3).
func (s *Server) FetchJWTSVIDsForNode(ctx context.Context, nodeID string, audience, selectors []string) ([]JWTSVID, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, ErrNoIdentity
	}
	return s.fetchJWT(ctx, nodeID, audience, selectors)
}

// FetchJWTSVIDs issues a JWT-SVID (bound to the given audience) for every entry
// whose selectors the caller satisfies.
func (s *Server) FetchJWTSVIDs(ctx context.Context, audience, selectors []string) ([]JWTSVID, error) {
	return s.fetchJWT(ctx, "", audience, selectors)
}

func (s *Server) fetchJWT(ctx context.Context, parentID string, audience, selectors []string) ([]JWTSVID, error) {
	if len(audience) == 0 {
		return nil, fmt.Errorf("spiffe: audience required for JWT-SVID")
	}
	var out []JWTSVID
	err := s.run(func() error {
		entries := s.matchedForParent(selectors, parentID)
		if len(entries) == 0 {
			return ErrNoIdentity
		}
		for _, e := range entries {
			ttl := e.JWTTTL
			if ttl <= 0 {
				ttl = s.cfg.DefaultJWTTTL
			}
			tok, err := s.cfg.Issuer.SignJWTSVID(ctx, e.SPIFFEID, audience, ttl)
			if err != nil {
				return fmt.Errorf("spiffe: sign JWT-SVID %s: %w", e.SPIFFEID, err)
			}
			out = append(out, JWTSVID{SPIFFEID: e.SPIFFEID, Token: tok, ExpiresAt: time.Now().Add(ttl)})
			s.recordIssued(ctx, "jwt", e.SPIFFEID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FetchX509Bundle returns the trust-domain CA bundle (DER).
func (s *Server) FetchX509Bundle(ctx context.Context) ([][]byte, error) {
	return s.cfg.Issuer.X509Bundle(ctx)
}

// FetchJWTBundle returns the JWT trust bundle as a JWKS.
func (s *Server) FetchJWTBundle(ctx context.Context) (crypto.JWKS, error) {
	return s.cfg.Issuer.JWTBundle(ctx)
}

// matchedForParent is matched() scoped to a delivering node (epic B3).
//
// parentID is the SPIFFE ID of the agent asking on a workload's behalf, or ""
// when the control plane's own socket is asking. The two cases are deliberately
// not symmetric:
//
//   - "" (the local socket) sees entries with NO ParentID. It is the pre-B3
//     behaviour, unchanged, and it cannot reach node-scoped entries because it
//     is not that node.
//   - a real parentID sees only entries scoped to exactly that node. It cannot
//     reach unscoped entries, because an unscoped entry has not been authorized
//     for delivery by any agent at all.
//
// So neither caller is a superset of the other, and an entry is reachable by
// exactly one path. That is what makes the migration observable: an operator
// moves an entry by setting ParentID, and the entry stops being served locally
// at the same moment it starts being served on the host.
func (s *Server) matchedForParent(selectors []string, parentID string) []RegistrationEntry {
	have := make(map[string]bool, len(selectors))
	for _, sel := range selectors {
		have[sel] = true
	}
	var out []RegistrationEntry
	for _, e := range s.cfg.Entries {
		if len(e.Selectors) == 0 {
			continue
		}
		if e.ParentID != parentID {
			continue
		}
		ok := true
		for _, need := range e.Selectors {
			if !have[need] {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, e)
		}
	}
	return out
}

func (s *Server) recordIssued(ctx context.Context, kind, spiffeID string) {
	_ = auditsink.Emit(ctx, s.cfg.Audit, nil, "spiffe.svid.issued", s.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"type":%q,"spiffe_id":%q}`, kind, spiffeID)))
	if s.cfg.Graph != nil {
		s.cfg.Graph.AddNode(graph.Node{
			ID:   spiffeID,
			Kind: graph.KindWorkload,
			Name: spiffeID,
			Attrs: map[string]string{
				"tenant_id": s.cfg.TenantID,
				"svid":      kind,
			},
		})
	}
}

func (s *Server) run(fn func() error) error {
	if s.cfg.Pool == nil {
		return fn()
	}
	errc := make(chan error, 1)
	if err := s.cfg.Pool.Submit(func() { errc <- fn() }); err != nil {
		return err
	}
	return <-errc
}

// NeedsRotation reports whether an X509-SVID should be rotated at time now: like
// SPIRE, trstctl rotates once a SVID has passed `fraction` of its lifetime
// (default 0.5 when fraction is out of (0,1)). This is the rotate-before-expiry
// policy a Workload API client applies to the streamed SVID.
func NeedsRotation(svid X509SVID, now time.Time, fraction float64) (bool, error) {
	if len(svid.CertChain) == 0 {
		return false, fmt.Errorf("spiffe: empty SVID chain")
	}
	nb, na, err := crypto.CertValidity(svid.CertChain[0])
	if err != nil {
		return false, err
	}
	if fraction <= 0 || fraction >= 1 {
		fraction = 0.5
	}
	threshold := nb.Add(time.Duration(float64(na.Sub(nb)) * fraction))
	return !now.Before(threshold), nil
}
