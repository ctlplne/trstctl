// Package ephemeral implements attestation-gated, short-TTL credential issuance
// (S11.9, F25): high-churn automated workloads exchange a valid attestation for a
// sub-hour, self-expiring certificate instead of holding a static credential.
// Issuance is refused without a valid attestation; the attestation is bound to the
// issuance it justified; revocation is by expiry (no CRL/OCSP round-trip).
//
// Non-negotiables: every issuance is audited (AN-2) and tenant-scoped (AN-1),
// carries an idempotency key so a retried request never mints twice (AN-5), and
// runs under a bounded worker pool so a burst cannot exhaust the system (AN-7).
package ephemeral

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
)

// SignFunc mints a short-TTL credential for an attested identity over pubDER. It
// is the seam to the SPIFFE/X.509 issuer, which signs through the crypto boundary
// and the isolated signer (AN-3/AN-4).
type SignFunc func(ctx context.Context, att attest.Attestation, pubDER []byte, ttl time.Duration) (certDER []byte, err error)

// Idempotencer records an idempotency key with its result; a replay returns the
// original result rather than executing again (AN-5). orchestrator.Idempotency
// satisfies this; MemoryIdempotencer is the single-node/test implementation.
type Idempotencer interface {
	Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error)
}

// TTLPolicy sets the credential lifetime per workload class (attestation method),
// clamped to Max.
type TTLPolicy struct {
	Default  time.Duration
	ByMethod map[string]time.Duration
	Max      time.Duration
}

// For returns the TTL for an attestation method, clamped to Max.
func (p TTLPolicy) For(method string) time.Duration {
	ttl := p.Default
	if d, ok := p.ByMethod[method]; ok {
		ttl = d
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if p.Max > 0 && ttl > p.Max {
		ttl = p.Max
	}
	return ttl
}

// Config configures an Issuer.
type Config struct {
	TenantID string
	Verifier *attest.Verifier // gates which workload may receive a credential
	Sign     SignFunc
	Policy   TTLPolicy
	Idem     Idempotencer      // AN-5; required
	Pool     *bulkhead.Pool    // AN-7; nil runs inline
	Audit    auditsink.Auditor // AN-2; nil = no-op
}

// Issuer mints attestation-gated short-TTL credentials.
type Issuer struct {
	cfg Config
}

// New validates configuration and constructs an Issuer.
func New(cfg Config) (*Issuer, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("ephemeral: TenantID required (AN-1)")
	}
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("ephemeral: Verifier required (attestation gate)")
	}
	if cfg.Sign == nil {
		return nil, fmt.Errorf("ephemeral: Sign func required")
	}
	if cfg.Idem == nil {
		return nil, fmt.Errorf("ephemeral: Idempotencer required (AN-5)")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Issuer{cfg: cfg}, nil
}

// Request is an attestation-gated issuance request.
type Request struct {
	Method         string // attestation method (e.g. "k8s_sat")
	Payload        []byte // the attestation proof
	PublicKeyDER   []byte // the workload public key to certify (PKIX)
	IdempotencyKey string // AN-5
}

// Result is an issued short-TTL credential.
type Result struct {
	CertDER      []byte             `json:"cert_der"`
	CredentialID string             `json:"credential_id"`
	Subject      string             `json:"subject"`
	NotAfter     time.Time          `json:"not_after"`
	Attestation  attest.Attestation `json:"attestation"`
}

// Issue verifies the attestation (the gate), mints a short-TTL credential bound
// to it, and returns it. Without a valid attestation it returns an error and
// mints nothing. A replay of the same idempotency key returns the original result.
func (i *Issuer) Issue(ctx context.Context, req Request) (Result, error) {
	if req.IdempotencyKey == "" {
		return Result{}, fmt.Errorf("ephemeral: Idempotency-Key required (AN-5)")
	}
	if len(req.PublicKeyDER) == 0 {
		return Result{}, fmt.Errorf("ephemeral: public key required")
	}
	var out Result
	err := i.run(func() error {
		raw, err := i.cfg.Idem.Do(ctx, i.cfg.TenantID, req.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
			att, err := i.cfg.Verifier.Verify(ctx, req.Method, req.Payload) // the gate
			if err != nil {
				return nil, fmt.Errorf("ephemeral: refused — %w", err)
			}
			ttl := i.cfg.Policy.For(req.Method)
			certDER, err := i.cfg.Sign(ctx, att, req.PublicKeyDER, ttl)
			if err != nil {
				return nil, fmt.Errorf("ephemeral: sign: %w", err)
			}
			_, notAfter, err := crypto.CertValidity(certDER)
			if err != nil {
				return nil, err
			}
			credID := "cred:" + crypto.SHA256Hex(certDER)
			if err := i.cfg.Verifier.Bind(ctx, att, credID); err != nil {
				return nil, fmt.Errorf("ephemeral: bind attestation: %w", err)
			}
			res := Result{CertDER: certDER, CredentialID: credID, Subject: att.Subject, NotAfter: notAfter, Attestation: att}
			_ = auditsink.Emit(ctx, i.cfg.Audit, nil, "ephemeral.issued", i.cfg.TenantID,
				[]byte(fmt.Sprintf(`{"subject":%q,"method":%q,"ttl_seconds":%d,"not_after":%q}`,
					att.Subject, att.Method, int(ttl.Seconds()), notAfter.Format(time.RFC3339))))
			return json.Marshal(res)
		})
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return Result{}, err
	}
	return out, nil
}

func (i *Issuer) run(fn func() error) error {
	if i.cfg.Pool == nil {
		return fn()
	}
	errc := make(chan error, 1)
	if err := i.cfg.Pool.Submit(func() { errc <- fn() }); err != nil {
		return err
	}
	return <-errc
}

// ErrInProgress is returned when a concurrent request holds the same idempotency
// key (AN-5).
var ErrInProgress = errors.New("ephemeral: idempotent operation already in progress")

// MemoryIdempotencer is an in-memory Idempotencer for single-node deployments and
// tests. Production uses the PostgreSQL-backed orchestrator.Idempotency.
type MemoryIdempotencer struct {
	mu       sync.Mutex
	done     map[string][]byte
	inflight map[string]bool
}

// NewMemoryIdempotencer constructs a MemoryIdempotencer.
func NewMemoryIdempotencer() *MemoryIdempotencer {
	return &MemoryIdempotencer{done: map[string][]byte{}, inflight: map[string]bool{}}
}

// Do implements Idempotencer: a successful result is recorded and replayed; an
// error releases the claim so a later retry can succeed.
func (m *MemoryIdempotencer) Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	full := tenantID + "|" + key
	m.mu.Lock()
	if r, ok := m.done[full]; ok {
		m.mu.Unlock()
		return r, nil
	}
	if m.inflight[full] {
		m.mu.Unlock()
		return nil, ErrInProgress
	}
	m.inflight[full] = true
	m.mu.Unlock()

	res, err := fn(ctx)

	m.mu.Lock()
	delete(m.inflight, full)
	if err == nil {
		m.done[full] = res
	}
	m.mu.Unlock()
	return res, err
}
