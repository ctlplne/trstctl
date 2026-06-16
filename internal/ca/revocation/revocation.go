// Package revocation is the X.509 revocation infrastructure (F47, sprint S4.16)
// for certificates trstctl issues from its own private CA (F48): an OCSP
// responder and CRL generation/publication. Revocation status is persisted
// tenant-scoped (AN-1); OCSP responses and CRLs are signed through the
// internal/crypto/ca boundary (AN-3, with signer/HSM custody under AN-4); every
// state change emits an event (AN-2); and the responder runs on a bounded
// bulkhead pool (AN-7) so a flood of OCSP queries cannot starve the API.
//
// This covers certificates from the internal CA only; brokered public certs use
// the upstream CA's revocation infrastructure.
package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// CALookup resolves the signing CA for a (tenant, caID) so OCSP responses and
// CRLs can be signed. In production this is wired to the CA hierarchy manager;
// the signer/HSM (AN-4) custodies the key behind the crypto boundary.
type CALookup func(tenantID, caID string) (*cryptoca.CA, error)

const (
	defaultCacheTTL    = 10 * time.Minute
	defaultCRLValidity = 7 * 24 * time.Hour
	defaultWorkers     = 8
	defaultQueue       = 512
)

// Service answers OCSP queries and generates CRLs for internally-issued certs.
type Service struct {
	store   *store.Store
	log     *events.Log
	lookup  CALookup
	pool    *bulkhead.Pool
	ownPool bool

	cacheTTL    time.Duration
	crlValidity time.Duration
	now         func() time.Time
}

// Option configures the Service.
type Option func(*Service)

// WithCacheTTL sets how long an OCSP response is cacheable (its NextUpdate).
func WithCacheTTL(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.cacheTTL = d
		}
	}
}

// WithCRLValidity sets how long a generated CRL is valid (its NextUpdate).
func WithCRLValidity(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.crlValidity = d
		}
	}
}

// WithPool injects the bulkhead pool the OCSP responder runs on (AN-7). The
// Service does not close an injected pool.
func WithPool(p *bulkhead.Pool) Option {
	return func(s *Service) { s.pool = p }
}

// New wires a revocation Service over the store, event log, and CA resolver.
func New(s *store.Store, log *events.Log, lookup CALookup, opts ...Option) *Service {
	svc := &Service{store: s, log: log, lookup: lookup, cacheTTL: defaultCacheTTL, crlValidity: defaultCRLValidity, now: time.Now}
	for _, o := range opts {
		o(svc)
	}
	if svc.pool == nil {
		svc.pool = bulkhead.New(bulkhead.Config{Name: "ocsp", Workers: defaultWorkers, Queue: defaultQueue})
		svc.ownPool = true
	}
	return svc
}

// Close releases the OCSP bulkhead pool if the Service created it.
func (s *Service) Close() {
	if s.ownPool {
		s.pool.Close()
	}
}

// RecordIssued records that the internal CA issued a certificate with serial, so
// the responder can answer good (issued, not revoked) vs. unknown.
func (s *Service) RecordIssued(ctx context.Context, tenantID, caID, serial string) error {
	return s.store.RecordIssuedCert(ctx, tenantID, caID, serial, s.now())
}

// Revoke marks a certificate revoked; it then reflects in OCSP immediately and in
// the next generated CRL.
func (s *Service) Revoke(ctx context.Context, tenantID, caID, serial string, reasonCode int) error {
	if err := s.store.RevokeIssuedCert(ctx, tenantID, caID, serial, reasonCode, s.now()); err != nil {
		return err
	}
	return s.emit(ctx, tenantID, "ca.certificate.revoked", map[string]any{"ca_id": caID, "serial": serial, "reason": reasonCode})
}

// OCSP answers an OCSP request (DER) for an internally-issued certificate,
// returning a signed response (DER). It runs on a bounded bulkhead pool; when the
// pool is saturated it returns a bulkhead rejection rather than blocking (AN-7).
func (s *Service) OCSP(ctx context.Context, tenantID, caID string, reqDER []byte) ([]byte, error) {
	type result struct {
		der []byte
		err error
	}
	ch := make(chan result, 1)
	if err := s.pool.Submit(func() {
		der, err := s.respond(ctx, tenantID, caID, reqDER)
		ch <- result{der, err}
	}); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		return r.der, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// respond builds and signs the OCSP response for the queried serial.
func (s *Service) respond(ctx context.Context, tenantID, caID string, reqDER []byte) ([]byte, error) {
	serial, err := cryptoca.ParseOCSPRequestSerial(reqDER)
	if err != nil {
		return nil, err
	}
	rec, found, err := s.store.LookupIssuedCert(ctx, tenantID, caID, serial)
	if err != nil {
		return nil, err
	}
	ca, err := s.lookup(tenantID, caID)
	if err != nil {
		return nil, fmt.Errorf("revocation: resolve CA: %w", err)
	}
	status := cryptoca.OCSPUnknown
	var revokedAt time.Time
	reason := 0
	switch {
	case found && rec.Revoked():
		status = cryptoca.OCSPRevoked
		revokedAt = *rec.RevokedAt
		reason = rec.ReasonCode
	case found:
		status = cryptoca.OCSPGood
	}
	now := s.now()
	return ca.SignOCSP(status, serial, now, now.Add(s.cacheTTL), revokedAt, reason)
}

// GenerateCRL produces, publishes, and returns the next CRL for a CA, listing all
// its revoked certificates.
func (s *Service) GenerateCRL(ctx context.Context, tenantID, caID string) ([]byte, error) {
	revoked, err := s.store.ListRevokedCerts(ctx, tenantID, caID)
	if err != nil {
		return nil, err
	}
	entries := make([]cryptoca.RevokedSerial, 0, len(revoked))
	for _, r := range revoked {
		var ra time.Time
		if r.RevokedAt != nil {
			ra = *r.RevokedAt
		}
		entries = append(entries, cryptoca.RevokedSerial{Serial: r.Serial, RevokedAt: ra, Reason: r.ReasonCode})
	}
	number, err := s.store.NextCRLNumber(ctx, tenantID, caID)
	if err != nil {
		return nil, err
	}
	ca, err := s.lookup(tenantID, caID)
	if err != nil {
		return nil, fmt.Errorf("revocation: resolve CA: %w", err)
	}
	now := s.now()
	nextUpdate := now.Add(s.crlValidity)
	der, err := ca.CreateCRL(entries, number, now, nextUpdate)
	if err != nil {
		return nil, err
	}
	if err := s.store.InsertCRL(ctx, store.CRL{TenantID: tenantID, CAID: caID, Number: number, DER: der, ThisUpdate: now, NextUpdate: nextUpdate}); err != nil {
		return nil, err
	}
	if err := s.emit(ctx, tenantID, "ca.crl.published", map[string]any{"ca_id": caID, "crl_number": number, "revoked": len(entries)}); err != nil {
		return nil, err
	}
	return der, nil
}

// LatestCRL returns the most recently published CRL (DER) for a CA.
func (s *Service) LatestCRL(ctx context.Context, tenantID, caID string) ([]byte, error) {
	crl, found, err := s.store.LatestCRL(ctx, tenantID, caID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("revocation: no CRL published for CA %s", caID)
	}
	return crl.DER, nil
}

func (s *Service) emit(ctx context.Context, tenantID, eventType string, data map[string]any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	return err
}
