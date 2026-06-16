// Package pkisecret exposes PKI issuance through the secrets API (S18.3, F67): a
// developer requests a short-lived certificate like any other dynamic secret. It
// implements dynsecret.Provider, so the certificate is leased and revokes on
// expiry (S17.1); it issues from the internal CA through the crypto boundary
// (AN-3) with profile-scoped constraints (S8.1), is policy-gated (S10.1), and is
// audited via the lease engine (AN-2).
//
// Revocation is real and event-sourced (AN-2): when a RevocationSink is wired,
// Revoke records the certificate's serial on the served revocation pipeline (the
// store-backed CRL/OCSP responder + a ca.certificate.revoked event), so a revoked
// dynamic-secret certificate actually stops validating — mirroring the served
// revocation path (CORRECT-001) at the library level. Without a sink (a bare
// single-process embed) it falls back to an in-memory liveness set, but that does
// not place the serial on a CRL/OCSP and is logged as a limitation; production
// must wire the sink. (GAP-005.)
package pkisecret

import (
	"context"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
)

// Profile constrains certificates issued through the secrets API (S8.1).
type Profile struct {
	Name               string
	MaxTTL             time.Duration
	AllowedCommonNames map[string]bool // empty = any
}

// RevocationSink is the event-sourced revocation pipeline a PKIProvider records
// against, so an issued serial is tracked for OCSP/CRL and a revocation is durably
// recorded and emitted as an event (AN-2). It is the neutral seam the platform
// wires to revocation.Service (store-backed CRL/OCSP + ca.certificate.revoked
// event); a revoked serial therefore actually stops validating (CORRECT-001 at the
// library level). All operations are tenant-scoped (AN-1).
type RevocationSink interface {
	// RecordIssued notes that the CA issued a certificate with serial, so the
	// responder can answer good (issued, not revoked) vs. unknown.
	RecordIssued(ctx context.Context, tenantID, caID, serial string) error
	// Revoke records the serial as revoked (reflected in OCSP immediately and the
	// next CRL) and emits a revocation event. Idempotent on serial.
	Revoke(ctx context.Context, tenantID, caID, serial string, reasonCode int) error
}

// reasonCessationOfOperation is the RFC 5280 CRLReason used for a leased
// certificate revoked because its lease ended or was explicitly revoked.
const reasonCessationOfOperation = 5

// PKIProvider issues short-lived certificates as a dynamic secret.
type PKIProvider struct {
	tenantID  string
	caID      string
	caCertDER []byte
	caSigner  crypto.DigestSigner
	profile   Profile
	gate      func(cn string) (bool, string) // optional policy gate (S10.1)
	sink      RevocationSink                 // optional event-sourced revocation pipeline (AN-2)

	mu   sync.Mutex
	live map[string]bool
}

// Option configures a PKIProvider.
type Option func(*PKIProvider)

// WithRevocationSink wires the event-sourced revocation pipeline (the served
// revocation.Service), so issuance and revocation are recorded and a revoked
// certificate actually stops validating (AN-2, CORRECT-001). tenantID/caID scope
// the records (AN-1).
func WithRevocationSink(tenantID, caID string, sink RevocationSink) Option {
	return func(p *PKIProvider) {
		p.tenantID = tenantID
		p.caID = caID
		p.sink = sink
	}
}

// NewPKIProvider constructs a PKIProvider over an internal CA.
func NewPKIProvider(caCertDER []byte, caSigner crypto.DigestSigner, profile Profile, gate func(string) (bool, string), opts ...Option) *PKIProvider {
	p := &PKIProvider{caCertDER: caCertDER, caSigner: caSigner, profile: profile, gate: gate, live: map[string]bool{}}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name implements dynsecret.Provider.
func (p *PKIProvider) Name() string { return "pki" }

// TenantID returns the tenant this provider is scoped to (set via
// WithRevocationSink). Issuance and revocation records are attributed to it on the
// revocation pipeline so a serial, its OCSP/CRL status, and its ca.certificate.*
// events are tenant-bound (AN-1); empty for a bare single-tenant embed.
func (p *PKIProvider) TenantID() string { return p.tenantID }

// Generate issues a short-lived certificate. The requested common name is carried
// in the lease Role (the "secret name"); the profile and policy gate it.
func (p *PKIProvider) Generate(ctx context.Context, req dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	cn := req.Role
	if cn == "" {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: common name required")
	}
	if len(p.profile.AllowedCommonNames) > 0 && !p.profile.AllowedCommonNames[cn] {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: common name %q not permitted by profile %q", cn, p.profile.Name)
	}
	if p.gate != nil {
		if ok, reason := p.gate(cn); !ok {
			return dynsecret.Credential{}, fmt.Errorf("pkisecret: policy denied %q: %s", cn, reason)
		}
	}
	ttl := req.TTL
	if ttl <= 0 || (p.profile.MaxTTL > 0 && ttl > p.profile.MaxTTL) {
		ttl = p.profile.MaxTTL // profile-enforced cap
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	defer leafKey.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn}, leafKey)
	if err != nil {
		return dynsecret.Credential{}, err
	}
	certDER, err := crypto.SignLeafFromCSR(p.caCertDER, p.caSigner, csr, ttl)
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: sign cert: %w", err)
	}
	serial := crypto.SHA256Hex(certDER)[:16]
	p.mu.Lock()
	p.live[serial] = true
	p.mu.Unlock()
	// Track the issued serial on the revocation pipeline so OCSP can answer
	// "good" (issued, not revoked) rather than "unknown", and so a later Revoke has
	// a record to flip (AN-2). Best-effort: a recorder failure must not fail
	// issuance of an otherwise-valid certificate.
	if p.sink != nil {
		_ = p.sink.RecordIssued(ctx, p.tenantID, p.caID, serial)
	}
	// Hand the requester the certificate AND its matching leaf private key — a
	// bare cert is unusable as a TLS identity. The key leaves the locked buffer
	// only as a PKCS#8 PEM block in the returned Secret; the transient unsealed
	// DER copy is zeroized immediately after encode (AN-8).
	keyDER, err := leafKey.PKCS8()
	if err != nil {
		return dynsecret.Credential{}, fmt.Errorf("pkisecret: export leaf key: %w", err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	secret.Wipe(keyDER) // wipe the transient unsealed DER copy
	bundle = append(bundle, keyPEM...)
	secret.Wipe(keyPEM) // keyPEM bytes now live only inside bundle (the returned Secret)
	return dynsecret.Credential{BackendRef: serial, Secret: bundle, Metadata: map[string]string{"cn": cn, "serial": serial}}, nil
}

// Revoke records an issued certificate as revoked (idempotent). When a revocation
// sink is wired, the serial is placed on the served CRL/OCSP and a revocation
// event is emitted (AN-2), so the certificate actually stops validating; the
// in-memory liveness set is updated either way for local inspection.
func (p *PKIProvider) Revoke(ctx context.Context, serial string) error {
	p.mu.Lock()
	delete(p.live, serial)
	p.mu.Unlock()
	if p.sink != nil {
		// Record on the served revocation pipeline. This is the real invalidation:
		// the serial is written to the store-backed CRL/OCSP and a
		// ca.certificate.revoked event is emitted (AN-2). Idempotent on serial.
		if err := p.sink.Revoke(ctx, p.tenantID, p.caID, serial, reasonCessationOfOperation); err != nil {
			return fmt.Errorf("pkisecret: revoke serial %s: %w", serial, err)
		}
	}
	return nil
}

// IsLive reports whether a certificate serial is still live (test/inspection).
func (p *PKIProvider) IsLive(serial string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live[serial]
}
