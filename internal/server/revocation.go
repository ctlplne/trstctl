package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
	"trstctl.com/trstctl/internal/store"
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
	// ocspResponderValidity is the lifetime of a delegated OCSP responder
	// certificate. The signer-held responder key can be stable, but the certificate
	// it presents rotates as event-sourced evidence.
	ocspResponderValidity = 30 * 24 * time.Hour
	// ocspResponderRotateBefore refreshes the active responder before expiry, so a
	// relying party never sees an OCSP response carrying a near-dead responder cert.
	ocspResponderRotateBefore = 24 * time.Hour
)

// revocationService answers served OCSP queries and generates/serves CRLs for the
// served issuing CA's leaves, signing through the signer (AN-4).
type revocationService struct {
	store       revocationStore
	log         *events.Log
	caID        string
	caSigner    crypto.DigestSigner // the CA key in the signer (a *signing.RemoteSigner)
	caCertDER   []byte
	ocspSigner  crypto.DigestSigner // delegated responder key in the signer
	ocspCache   *ocspResponseCache
	ocspMetrics *observ.OCSPMetrics
	now         func() time.Time
}

type revocationStore interface {
	LookupIssuedCert(ctx context.Context, tenantID, caID, serial string) (store.IssuedCert, bool, error)
	HasIssuedCerts(ctx context.Context, tenantID, caID string) (bool, error)
	ListRevokedCerts(ctx context.Context, tenantID, caID string) ([]store.IssuedCert, error)
	NextCRLNumber(ctx context.Context, tenantID, caID string) (int64, error)
	InsertCRL(ctx context.Context, c store.CRL) error
	TenantsWithIssuedCerts(ctx context.Context, caID string) ([]string, error)
	CRLDueForRegeneration(ctx context.Context, tenantID, caID string, now time.Time, lead time.Duration) (bool, error)
	LatestCRL(ctx context.Context, tenantID, caID string) (store.CRL, bool, error)
	ActiveOCSPResponder(ctx context.Context, tenantID, caID string) (store.OCSPResponder, bool, error)
	UpsertOCSPResponder(ctx context.Context, responder store.OCSPResponder) error
}

var (
	errNoCRLSurface    = errors.New("server: tenant has no issued certificates for this CA")
	errCRLNotPublished = errors.New("server: CRL is not published yet")
)

// newRevocationService wires the served responder over the assembled store, event
// log, and the issuing CA (its cert DER plus the signer-backed DigestSigner). It
// returns nil when no CA is provisioned (issuance — and therefore revocation
// serving — is unavailable), so callers can treat a nil service as "not served".
func newRevocationService(st *store.Store, log *events.Log, caID string, caSigner crypto.DigestSigner, caCertDER []byte, ocspSigner crypto.DigestSigner) *revocationService {
	if caSigner == nil || len(caCertDER) == 0 || ocspSigner == nil {
		return nil
	}
	return &revocationService{store: st, log: log, caID: caID, caSigner: caSigner, caCertDER: caCertDER, ocspSigner: ocspSigner, ocspCache: newOCSPResponseCache(), now: time.Now}
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
	nonce, noncePresent, err := crypto.ParseOCSPRequestNonce(reqDER)
	if err != nil {
		s.observeOCSPNonce("malformed")
		return nil, err
	}
	if noncePresent {
		s.observeOCSPNonce("echoed")
	}
	rec, found, err := s.store.LookupIssuedCert(ctx, tenantID, s.caID, serial)
	if err != nil {
		return nil, err
	}
	responder, err := s.activeOCSPResponder(ctx, tenantID)
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
	nextUpdate := now.Add(ocspCacheTTL)
	key := ocspResponseCacheKey{
		tenantID: tenantID, caID: s.caID, serial: serial, status: status, reason: reason,
		revokedAt: revokedAt, responderSerial: responder.Serial,
	}
	if !noncePresent {
		if der, ok := s.ocspCache.get(key, now); ok {
			s.observeOCSPCache("hit")
			s.observeOCSPResponse("cache_hit")
			return der, nil
		}
		s.observeOCSPCache("miss")
	}
	der, err := crypto.SignDelegatedOCSPResponseWithNonce(s.caCertDER, responder.CertDER, s.ocspSigner, status, serial, now, nextUpdate, revokedAt, reason, nonce)
	if err != nil {
		s.observeOCSPResponse("error")
		return nil, err
	}
	if !noncePresent {
		s.ocspCache.put(key, der, nextUpdate)
	}
	s.observeOCSPResponse("signed")
	return der, nil
}

func (s *revocationService) observeOCSPResponse(result string) {
	if s.ocspMetrics != nil {
		s.ocspMetrics.ObserveResponse(s.caID, result)
	}
}

func (s *revocationService) observeOCSPCache(result string) {
	if s.ocspMetrics != nil {
		s.ocspMetrics.ObserveCache(s.caID, result)
	}
}

func (s *revocationService) observeOCSPNonce(result string) {
	if s.ocspMetrics != nil {
		s.ocspMetrics.ObserveNonce(s.caID, result)
	}
}

func (s *revocationService) activeOCSPResponder(ctx context.Context, tenantID string) (store.OCSPResponder, error) {
	if err := s.catchUp(ctx); err != nil {
		return store.OCSPResponder{}, err
	}
	now := s.now().UTC()
	active, found, err := s.store.ActiveOCSPResponder(ctx, tenantID, s.caID)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	if found && active.NotAfter.After(now.Add(ocspResponderRotateBefore)) && s.ocspResponderUsable(active) {
		return active, nil
	}
	var previousSerial string
	if found {
		previousSerial = active.Serial
	}
	return s.rotateOCSPResponder(ctx, tenantID, previousSerial, now)
}

func (s *revocationService) ocspResponderUsable(active store.OCSPResponder) bool {
	if _, err := crypto.InspectOCSPResponderCertificate(s.caCertDER, active.CertDER); err != nil {
		return false
	}
	matches, err := crypto.OCSPResponderCertificateMatchesSigner(active.CertDER, s.ocspSigner)
	return err == nil && matches
}

func (s *revocationService) rotateOCSPResponder(ctx context.Context, tenantID, previousSerial string, now time.Time) (store.OCSPResponder, error) {
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(ocspResponderValidity)
	certDER, err := crypto.CreateOCSPResponderCertificate(s.caCertDER, s.caSigner, s.ocspSigner, "trstctl OCSP Responder "+s.caID, notBefore, notAfter)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	info, err := crypto.InspectOCSPResponderCertificate(s.caCertDER, certDER)
	if err != nil {
		return store.OCSPResponder{}, err
	}
	responder := store.OCSPResponder{
		TenantID: tenantID, CAID: s.caID, Serial: info.Serial, CertDER: certDER,
		NotBefore: info.NotBefore, NotAfter: info.NotAfter, RotatedFromSerial: previousSerial,
		CreatedAt: now,
	}
	if err := s.publishOCSPResponder(ctx, responder); err != nil {
		return store.OCSPResponder{}, err
	}
	return responder, nil
}

// generateCRL produces, signs, persists, and returns the next CRL for the tenant,
// listing all of that tenant's revoked serials under the issuing CA. The signature
// is produced by the signer (AN-4); the publication emits a ca.crl.published event
// (AN-2). Tenant-scoped under RLS (AN-1).
func (s *revocationService) generateCRL(ctx context.Context, tenantID string) ([]byte, error) {
	if err := s.catchUp(ctx); err != nil {
		return nil, err
	}
	ok, err := s.store.HasIssuedCerts(ctx, tenantID, s.caID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNoCRLSurface
	}
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
	if err := s.publishCRL(ctx, store.CRL{TenantID: tenantID, CAID: s.caID, Number: number, DER: der, ThisUpdate: now, NextUpdate: nextUpdate}, len(entries)); err != nil {
		return nil, err
	}
	return der, nil
}

func (s *revocationService) ensureCRL(ctx context.Context, tenantID string) error {
	if err := s.catchUp(ctx); err != nil {
		return err
	}
	due, err := s.store.CRLDueForRegeneration(ctx, tenantID, s.caID, s.now(), crlRefreshLead)
	if err != nil {
		return err
	}
	if !due {
		return nil
	}
	_, err = s.generateCRL(ctx, tenantID)
	return err
}

// servedCRL returns the latest published CRL for the tenant (DER). It is a public
// read path, so it must never mutate tenant state: CRLs are produced by trusted
// issuance/revocation/scheduler paths, not by unauthenticated GETs.
func (s *revocationService) servedCRL(ctx context.Context, tenantID string) ([]byte, error) {
	ok, err := s.store.HasIssuedCerts(ctx, tenantID, s.caID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNoCRLSurface
	}
	crl, found, err := s.store.LatestCRL(ctx, tenantID, s.caID)
	if err != nil {
		return nil, err
	}
	if found {
		return crl.DER, nil
	}
	return nil, errCRLNotPublished
}

func weakCRLETag(der []byte) string {
	sum := crypto.SHA256Hex(der)
	return "W/\"" + sum[:32] + "\""
}

func crlIfNoneMatch(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		match := strings.TrimSpace(candidate)
		if match == etag || match == "*" {
			return true
		}
	}
	return false
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

func (s *revocationService) catchUp(ctx context.Context) error {
	st, ok := s.store.(*store.Store)
	if !ok || s.log == nil {
		return nil
	}
	if err := projections.New(st).ProjectCatchUp(ctx, s.log); err != nil {
		return fmt.Errorf("server: catch up revocation projections: %w", err)
	}
	return nil
}

func (s *revocationService) publishCRL(ctx context.Context, crl store.CRL, revokedCount int) error {
	st, ok := s.store.(*store.Store)
	if !ok {
		return s.store.InsertCRL(ctx, crl)
	}
	if s.log == nil {
		return errors.New("server: revocation service requires an event log")
	}
	payload, err := json.Marshal(projections.CRLPublished{
		CAID: crl.CAID, Number: crl.Number, DER: crl.DER,
		ThisUpdate: crl.ThisUpdate, NextUpdate: crl.NextUpdate, RevokedCount: revokedCount,
	})
	if err != nil {
		return err
	}
	ev, err := s.log.Append(ctx, events.Event{
		Type: projections.EventCRLPublished, TenantID: crl.TenantID,
		SchemaVersion: projections.CRLPublishedEventSchemaVersion, Data: payload,
	})
	if err != nil {
		return err
	}
	return projections.New(st).Apply(ctx, ev)
}

func (s *revocationService) publishOCSPResponder(ctx context.Context, responder store.OCSPResponder) error {
	st, ok := s.store.(*store.Store)
	if !ok {
		return s.store.UpsertOCSPResponder(ctx, responder)
	}
	if s.log == nil {
		return errors.New("server: OCSP responder rotation requires an event log")
	}
	payload, err := json.Marshal(projections.OCSPResponderRotated{
		CAID: responder.CAID, Serial: responder.Serial, CertDER: responder.CertDER,
		NotBefore: responder.NotBefore, NotAfter: responder.NotAfter,
		RotatedFromSerial: responder.RotatedFromSerial,
	})
	if err != nil {
		return err
	}
	ev, err := s.log.Append(ctx, events.Event{
		Type: projections.EventOCSPResponderRotated, TenantID: responder.TenantID, Data: payload,
	})
	if err != nil {
		return err
	}
	return projections.New(st).Apply(ctx, ev)
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
			status := http.StatusBadRequest
			if errors.Is(err, bodylimit.ErrTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "ocsp: "+err.Error(), status)
			return
		}
		respDER, err := s.respondOCSP(r.Context(), tenantID, reqDER)
		if err != nil {
			// A malformed request (unparseable serial) is the client's fault; any
			// other failure (signer/store) is ours. Either way do not leak detail.
			status := http.StatusBadGateway
			msg := "ocsp: cannot produce response"
			if errors.Is(err, crypto.ErrMalformedOCSPRequest) || errors.Is(err, crypto.ErrOCSPNonceMalformed) {
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
			status := http.StatusBadGateway
			msg := "crl: cannot serve CRL"
			if errors.Is(err, errNoCRLSurface) || errors.Is(err, errCRLNotPublished) {
				status = http.StatusNotFound
				msg = "crl: not found"
			}
			http.Error(w, msg, status)
			return
		}
		etag := weakCRLETag(der)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, must-revalidate", int(crlSchedulerInterval/time.Second)))
		if crlIfNoneMatch(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
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
		b, err := bodylimit.ReadAll(r.Body, maxOCSPRequest)
		if err != nil {
			if errors.Is(err, bodylimit.ErrTooLarge) {
				return nil, err
			}
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
		// FUZZ-005: the GET form decodes the base64 request from the path directly,
		// bypassing the POST body cap. Reject an over-cap encoded value BEFORE base64
		// decode (the decoded DER is bounded by maxOCSPRequest, and base64 inflates by
		// 4/3) so a hostile GET cannot allocate an unbounded decode buffer. Surface
		// ErrTooLarge so the handler maps it to 413 exactly like the POST path.
		if len(enc) > base64.StdEncoding.EncodedLen(maxOCSPRequest) {
			return nil, bodylimit.ErrTooLarge
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
