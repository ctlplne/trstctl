package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/store"
)

// This file is the *served* revocation surface (EXC-REVOKE-01): an RFC 6960 OCSP
// responder and an RFC 5280 CRL endpoint, plus the freshness scheduler that
// regenerates CRLs on a cadence keyed to nextUpdate. It completes the revocation
// story whose store/projection half (a revoked cert stops validating and is
// recorded in ca_issued_certs) landed in CORRECT-001 and whose leaf CDP/AIA
// pointers landed in PKIGOV-001.
//
// AN-4: the served issuing CA's private key lives in the out-of-process signer.
// OCSP responses and CRLs are signed through the crypto boundary
// (crypto.SignOCSPResponse / crypto.CreateCRL) by handing it the same
// DigestSigner (a *signing.RemoteSigner asserting PurposeCASign) the leaf path
// uses — so the CA key never materializes in the control plane; only the digest
// crosses the boundary.
//
// AN-1: every query is tenant-scoped. The issuing CA is shared infrastructure but
// its issued/revoked rows stay tenant-isolated under RLS, so the served endpoints
// are tenant-scoped by path (/ocsp/{tenant}, /crl/{tenant}.crl) and the scheduler
// regenerates per tenant. A relying party's CDP/AIA URL therefore points at its
// tenant's scoped responder.

const (
	// crlValidity is how long a generated CRL is valid (its nextUpdate window).
	crlValidity = 7 * 24 * time.Hour
	// crlRefreshLead regenerates a CRL this far before its nextUpdate so a relying
	// party never sees an expired CRL between scheduler ticks.
	crlRefreshLead = 24 * time.Hour
	// crlSchedulerInterval is how often the freshness scheduler sweeps for CRLs due
	// for regeneration. The validity window is days, so an hourly cadence keeps the
	// served CRL comfortably fresh without pressure (same cadence as the other
	// background workers).
	crlSchedulerInterval = time.Hour
	// ocspCacheTTL is how long a served OCSP response is cacheable (its nextUpdate).
	ocspCacheTTL = 10 * time.Minute
)

// revocationService answers served OCSP queries and generates/serves CRLs for the
// served issuing CA's leaves, signing through the signer (AN-4).
type revocationService struct {
	store     *store.Store
	log       *events.Log
	caID      string
	caSigner  crypto.DigestSigner // the CA key in the signer (a *signing.RemoteSigner)
	caCertDER []byte
	now       func() time.Time
}

// newRevocationService wires the served responder over the assembled store, event
// log, and the issuing CA (its cert DER plus the signer-backed DigestSigner). It
// returns nil when no CA is provisioned (issuance — and therefore revocation
// serving — is unavailable), so callers can treat a nil service as "not served".
func newRevocationService(st *store.Store, log *events.Log, caID string, caSigner crypto.DigestSigner, caCertDER []byte) *revocationService {
	if caSigner == nil || len(caCertDER) == 0 {
		return nil
	}
	return &revocationService{store: st, log: log, caID: caID, caSigner: caSigner, caCertDER: caCertDER, now: time.Now}
}

// respondOCSP resolves the queried serial's revocation status for the tenant and
// returns a signed OCSP response (DER). An unknown serial (not issued by this CA
// for this tenant) yields a signed "unknown" response (RFC 6960), never a leak of
// another tenant's status. All access is tenant-scoped under RLS (AN-1).
func (s *revocationService) respondOCSP(ctx context.Context, tenantID string, reqDER []byte) ([]byte, error) {
	serial, err := crypto.ParseOCSPRequestSerial(reqDER)
	if err != nil {
		return nil, fmt.Errorf("server: parse OCSP request: %w", err)
	}
	rec, found, err := s.store.LookupIssuedCert(ctx, tenantID, s.caID, serial)
	if err != nil {
		return nil, err
	}
	status := crypto.OCSPUnknown
	var revokedAt time.Time
	reason := 0
	switch {
	case found && rec.Revoked():
		status = crypto.OCSPRevoked
		revokedAt = *rec.RevokedAt
		reason = rec.ReasonCode
	case found:
		status = crypto.OCSPGood
	}
	now := s.now()
	return crypto.SignOCSPResponse(s.caCertDER, s.caSigner, status, serial, now, now.Add(ocspCacheTTL), revokedAt, reason)
}

// generateCRL produces, signs, persists, and returns the next CRL for the tenant,
// listing all of that tenant's revoked serials under the issuing CA. The signature
// is produced by the signer (AN-4); the publication emits a ca.crl.published event
// (AN-2). Tenant-scoped under RLS (AN-1).
func (s *revocationService) generateCRL(ctx context.Context, tenantID string) ([]byte, error) {
	revoked, err := s.store.ListRevokedCerts(ctx, tenantID, s.caID)
	if err != nil {
		return nil, err
	}
	entries := make([]crypto.RevokedSerial, 0, len(revoked))
	for _, r := range revoked {
		var ra time.Time
		if r.RevokedAt != nil {
			ra = *r.RevokedAt
		}
		entries = append(entries, crypto.RevokedSerial{Serial: r.Serial, RevokedAt: ra, Reason: r.ReasonCode})
	}
	number, err := s.store.NextCRLNumber(ctx, tenantID, s.caID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	nextUpdate := now.Add(crlValidity)
	der, err := crypto.CreateCRL(s.caCertDER, s.caSigner, entries, number, now, nextUpdate)
	if err != nil {
		return nil, err
	}
	if err := s.store.InsertCRL(ctx, store.CRL{TenantID: tenantID, CAID: s.caID, Number: number, DER: der, ThisUpdate: now, NextUpdate: nextUpdate}); err != nil {
		return nil, err
	}
	if err := s.emit(ctx, tenantID, "ca.crl.published", map[string]any{"ca_id": s.caID, "crl_number": number, "revoked": len(entries)}); err != nil {
		return nil, err
	}
	return der, nil
}

// servedCRL returns the latest published CRL for the tenant (DER), generating a
// first one on demand if none has been published yet, so the CDP URL serves a
// valid CRL even before the scheduler's first tick.
func (s *revocationService) servedCRL(ctx context.Context, tenantID string) ([]byte, error) {
	crl, found, err := s.store.LatestCRL(ctx, tenantID, s.caID)
	if err != nil {
		return nil, err
	}
	if found {
		return crl.DER, nil
	}
	return s.generateCRL(ctx, tenantID)
}

// regenerateDue regenerates the CRL for every tenant whose latest CRL is missing
// or about to expire (within crlRefreshLead), keeping the served CRL fresh. It is
// the scheduler's per-sweep body. It returns the number of CRLs regenerated.
func (s *revocationService) regenerateDue(ctx context.Context) (int, error) {
	tenants, err := s.store.TenantsWithIssuedCerts(ctx, s.caID)
	if err != nil {
		return 0, err
	}
	now := s.now()
	count := 0
	for _, tenantID := range tenants {
		due, err := s.store.CRLDueForRegeneration(ctx, tenantID, s.caID, now, crlRefreshLead)
		if err != nil {
			return count, err
		}
		if !due {
			continue
		}
		if _, err := s.generateCRL(ctx, tenantID); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *revocationService) emit(ctx context.Context, tenantID, eventType string, data map[string]any) error {
	if s.log == nil {
		return nil
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	return err
}

// ---- served HTTP handlers ----

// ocspHandler serves RFC 6960 OCSP for a tenant at /ocsp/{tenant} (and the
// base64-in-path GET form /ocsp/{tenant}/{b64request}). It returns
// application/ocsp-response on success. The whole revocation surface runs on the
// API bulkhead pool already (it is mounted under the bulkheaded mux), so a flood
// sheds rather than starving the rest of the control plane (AN-7).
func (s *revocationService) ocspHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.PathValue("tenant")
		if tenantID == "" {
			http.Error(w, "ocsp: missing tenant", http.StatusBadRequest)
			return
		}
		reqDER, err := readOCSPRequest(r)
		if err != nil {
			http.Error(w, "ocsp: "+err.Error(), http.StatusBadRequest)
			return
		}
		respDER, err := s.respondOCSP(r.Context(), tenantID, reqDER)
		if err != nil {
			// A malformed request (unparseable serial) is the client's fault; any
			// other failure (signer/store) is ours. Either way do not leak detail.
			status := http.StatusBadGateway
			msg := "ocsp: cannot produce response"
			if errors.Is(err, crypto.ErrMalformedOCSPRequest) {
				status = http.StatusBadRequest
				msg = "ocsp: malformed request"
			}
			http.Error(w, msg, status)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(respDER)
	}
}

// crlHandler serves the latest CRL (DER) for a tenant at /crl/{tenant}.crl as
// application/pkix-crl, the conventional content type relying parties expect at a
// CRL distribution point.
func (s *revocationService) crlHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSuffix(r.PathValue("tenant"), ".crl")
		if tenantID == "" {
			http.Error(w, "crl: missing tenant", http.StatusBadRequest)
			return
		}
		der, err := s.servedCRL(r.Context(), tenantID)
		if err != nil {
			http.Error(w, "crl: cannot produce CRL", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(der)
	}
}

// maxOCSPRequest bounds an inbound OCSP request body so a hostile client cannot
// stream an unbounded body at the responder.
const maxOCSPRequest = 1 << 16 // 64 KiB — far larger than any real OCSP request

// readOCSPRequest reads an OCSP request (DER) from either the POST body
// (Content-Type application/ocsp-request) or the base64-encoded final path
// segment of a GET (RFC 6960 §A.1).
func readOCSPRequest(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodPost:
		b, err := io.ReadAll(io.LimitReader(r.Body, maxOCSPRequest))
		if err != nil {
			return nil, errors.New("read request body")
		}
		if len(b) == 0 {
			return nil, errors.New("empty OCSP request body")
		}
		return b, nil
	case http.MethodGet:
		enc := r.PathValue("b64request")
		if enc == "" {
			return nil, errors.New("GET OCSP requires a base64-encoded request in the path")
		}
		// The encoded request can contain '/' which a client may percent-decode; the
		// router gives us the already-unescaped segment, so decode it directly.
		der, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, errors.New("invalid base64 OCSP request")
		}
		return der, nil
	default:
		return nil, fmt.Errorf("method %s not allowed", r.Method)
	}
}

// revocationMux builds the served revocation routes for mounting under the
// bulkheaded API surface. It is a no-op (nil handler) when revocation is not
// served (no CA provisioned).
func (s *revocationService) routes(mux *http.ServeMux) {
	if s == nil {
		return
	}
	mux.HandleFunc("POST /ocsp/{tenant}", s.ocspHandler())
	mux.HandleFunc("GET /ocsp/{tenant}/{b64request}", s.ocspHandler())
	mux.HandleFunc("GET /crl/{tenant}", s.crlHandler())
}

// runScheduler runs the CRL freshness scheduler until ctx is cancelled: it sweeps
// once on start (so a freshly booted, overdue deployment regenerates promptly) and
// then on a fixed cadence, regenerating any CRL whose nextUpdate is within the
// refresh lead. A sweep error is logged and the next tick retries — the same
// resilient pattern the outbox dispatcher and the other background workers use.
func (s *revocationService) runScheduler(ctx context.Context, logf func(msg string, n int, err error)) {
	if s == nil {
		return
	}
	sweep := func() {
		n, err := s.regenerateDue(ctx)
		if logf != nil {
			logf("crl scheduler sweep", n, err)
		}
	}
	sweep()
	t := time.NewTicker(crlSchedulerInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
