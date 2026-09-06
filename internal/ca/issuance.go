// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/dependents"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// IssuanceService issues certificates through a CA on the platform's safety
// rails: idempotency (AN-5) so a retried request never mints two certificates,
// and an outbox record (AN-6) so every issuance is observable. It is the path
// the orchestrator drives and the seam the upstream CA plugins (e.g. Let's
// Encrypt) plug into behind the same CA interface.
type IssuanceService struct {
	ca     CA
	idem   *orchestrator.Idempotency
	outbox *orchestrator.Outbox
	store  *store.Store
	log    *events.Log // optional; when set, profile-gated decisions are audited (S8.1)

	outboxAuthorityID string
	wakeOutbox        func()
	dependentRecorder dependents.Recorder
	externalReplay    ExternalIssueReplaySafety

	// lifetimeLogger and lifetimeWarnBelow surface a certificate whose whole
	// remaining lifetime is shorter than the tenant's expiry alert window. An
	// external authority chooses the lifetime (trstctl cannot request an ACME
	// profile yet), and a six-day certificate against a fourteen-day window
	// raises an expiry alert within a minute of issuance. The WARN names the
	// tenant and authority so the operator can read the alert as "the CA's
	// lifetime policy", not "renewal is broken".
	lifetimeLogger    *slog.Logger
	lifetimeWarnBelow time.Duration
}

// ExternalIssueReplaySafety is the audited upstream crash contract. The default
// is at-most-once: a provider without a pre-submit token must never be called
// blindly after an ambiguous failure. Reconciled is reserved for adapters that
// enforce the supplied ProviderIdempotencyKey at their receiver.
type ExternalIssueReplaySafety uint8

const (
	ExternalIssueAtMostOnce ExternalIssueReplaySafety = iota
	ExternalIssueReconciled
)

// Option configures an IssuanceService.
type Option func(*IssuanceService)

// WithAuditLog wires the event log so profile-gated issuance decisions are emitted
// as AN-2 audit events (with the actor from the request context).
func WithAuditLog(log *events.Log) Option { return func(s *IssuanceService) { s.log = log } }

// WithLifetimeWarning logs a WARN when an issued certificate's remaining
// lifetime is below the given window (the tenant's expiry alert window). A nil
// logger or a non-positive window disables the check.
func WithLifetimeWarning(logger *slog.Logger, below time.Duration) Option {
	return func(s *IssuanceService) { s.lifetimeLogger, s.lifetimeWarnBelow = logger, below }
}

// WithOutboxIssueWorker moves provider issuance to the shared outbox dispatcher.
// authorityID identifies which configured CA owns the external-ca.issue row, and
// wake asks that normal bounded worker to sweep after the durable intent commits.
// It never performs provider work on the request goroutine.
func WithOutboxIssueWorker(authorityID string, wake func()) Option {
	return func(s *IssuanceService) {
		s.outboxAuthorityID = authorityID
		s.wakeOutbox = wake
	}
}

// WithExternalIssueReplaySafety attaches the provider adapter's audited replay
// contract. Unknown values fail closed to at-most-once.
func WithExternalIssueReplaySafety(safety ExternalIssueReplaySafety) Option {
	return func(s *IssuanceService) {
		if safety == ExternalIssueReconciled {
			s.externalReplay = safety
		}
	}
}

// WithDependentRecorder registers a feature-neutral observer for credentials
// minted by this issuance path. Edition code can attach an implementation through
// the tagged attach seam without making MPL core import the edition package.
func WithDependentRecorder(rec dependents.Recorder) Option {
	return func(s *IssuanceService) { s.dependentRecorder = rec }
}

// NewIssuanceService wires an issuance service over a CA and the platform's
// idempotency and outbox.
func NewIssuanceService(ca CA, idem *orchestrator.Idempotency, outbox *orchestrator.Outbox, st *store.Store, opts ...Option) *IssuanceService {
	s := &IssuanceService{ca: ca, idem: idem, outbox: outbox, store: st}
	for _, o := range opts {
		o(s)
	}
	return s
}

const DestinationExternalCAIssue = "external-ca.issue"

// ErrExternalIssueIncomplete means an external-CA outbox worker did not complete
// the idempotent result before the served request needed to return.
var ErrExternalIssueIncomplete = errors.New("ca: external CA issue result is not complete")

const (
	externalIssueResultPollInterval = 10 * time.Millisecond
	externalIssueResultWaitTimeout  = 30 * time.Second
)

// ExternalIssuePayload is the durable outbox payload for provider-backed CA
// issuance. It carries the full provider request so the outbox worker, not the
// request handler, owns issue/poll/download side effects.
type ExternalIssuePayload struct {
	AuthorityID            string   `json:"authority_id"`
	TenantID               string   `json:"tenant_id"`
	CSR                    []byte   `json:"csr_der"`
	DNSNames               []string `json:"dns_names,omitempty"`
	TTLNanos               int64    `json:"ttl_nanos"`
	ProviderIdempotencyKey string   `json:"provider_idempotency_key"`
	ProfileName            string   `json:"profile_name,omitempty"`
	Protocol               string   `json:"protocol,omitempty"`
	RequestedEKUs          []string `json:"requested_ekus,omitempty"`
	RequestBinding         string   `json:"request_binding"`
}

func externalIssueResultKey(idempotencyKey string) string {
	return "external-ca.issue:" + idempotencyKey
}

// IssueRecordIdempotencyKey returns the outbox key for the ca.issue
// observability row that follows an upstream CA issue. The provider call itself
// uses idempotencyKey; this sibling key prevents the external-ca.issue intent and
// ca.issue record from collapsing into one outbox row while still deduping crash
// recovery retries.
func IssueRecordIdempotencyKey(idempotencyKey string) string {
	return idempotencyKey + ":ca.issue"
}

func dependentRecordIdempotencyKey(idempotencyKey string) string {
	return idempotencyKey + ":ca.issue.dependent"
}

func newExternalIssuePayload(authorityID string, req IssueRequest) ExternalIssuePayload {
	return ExternalIssuePayload{
		AuthorityID:            authorityID,
		TenantID:               req.TenantID,
		CSR:                    append([]byte(nil), req.CSR...),
		DNSNames:               append([]string(nil), req.DNSNames...),
		TTLNanos:               int64(req.TTL),
		ProviderIdempotencyKey: req.ProviderIdempotencyKey,
		ProfileName:            req.ProfileName,
		Protocol:               req.Protocol,
		RequestedEKUs:          append([]string(nil), req.RequestedEKUs...),
		RequestBinding:         req.RequestBinding,
	}
}

func (p ExternalIssuePayload) IssueRequest() IssueRequest {
	return IssueRequest{
		TenantID:               p.TenantID,
		CSR:                    append([]byte(nil), p.CSR...),
		DNSNames:               append([]string(nil), p.DNSNames...),
		TTL:                    time.Duration(p.TTLNanos),
		ProviderIdempotencyKey: p.ProviderIdempotencyKey,
		ProfileName:            p.ProfileName,
		Protocol:               p.Protocol,
		RequestedEKUs:          append([]string(nil), p.RequestedEKUs...),
		RequestBinding:         p.RequestBinding,
	}
}

// ProviderIdempotencyKey derives a provider-safe token from trstctl's
// Idempotency-Key. Hex keeps it accepted by conservative upstream APIs such as
// AWS PCA while preserving deterministic retry behavior.
func ProviderIdempotencyKey(idempotencyKey string) string {
	const tokenBytes = 32
	sum := crypto.SHA256Hex([]byte(idempotencyKey))
	if len(sum) <= tokenBytes {
		return sum
	}
	return sum[:tokenBytes]
}

// Issue signs the request under idempotencyKey: the first call mints the
// certificate and records the issuance in the outbox; a replay with the same key
// returns the original certificate without minting again.
func (s *IssuanceService) Issue(ctx context.Context, req IssueRequest, idempotencyKey string) (Certificate, error) {
	// Profile gate (S8.1): when the request binds a profile, validate it before
	// anything is signed. Deterministic, so a replay re-validates and still hits the
	// idempotency cache below. A violation is rejected with a clear reason.
	if err := s.enforceProfile(ctx, req); err != nil {
		return Certificate{}, err
	}
	if req.ProviderIdempotencyKey == "" {
		req.ProviderIdempotencyKey = ProviderIdempotencyKey(idempotencyKey)
	}
	if s.outboxAuthorityID != "" {
		return s.issueViaOutbox(ctx, req, idempotencyKey)
	}
	if err := s.recordIntent(ctx, req.TenantID, idempotencyKey, req); err != nil {
		return Certificate{}, err
	}
	raw, err := s.idem.DoAtMostOnceEffect(ctx, req.TenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		cert, err := s.ca.Issue(ctx, req)
		if err != nil {
			return nil, err
		}
		s.observeLifetime(req.TenantID, cert)
		if err := s.record(ctx, req.TenantID, idempotencyKey, req.RequestBinding, cert); err != nil {
			return nil, err
		}
		return json.Marshal(cert)
	})
	if err != nil {
		return Certificate{}, err
	}
	var cert Certificate
	if err := json.Unmarshal(raw, &cert); err != nil {
		return Certificate{}, err
	}
	if err := s.recordDependentOnce(ctx, req, idempotencyKey, cert); err != nil {
		return Certificate{}, err
	}
	return cert, nil
}

func (s *IssuanceService) issueViaOutbox(ctx context.Context, req IssueRequest, idempotencyKey string) (Certificate, error) {
	if req.RequestBinding == "" {
		return Certificate{}, errors.New("ca: external CA issue is missing its authenticated request binding")
	}
	if cert, found, err := s.recoverExternalIssue(ctx, req.TenantID, idempotencyKey, req.RequestBinding); err != nil || found {
		return cert, err
	}
	payload, err := json.Marshal(newExternalIssuePayload(s.outboxAuthorityID, req))
	if err != nil {
		return Certificate{}, err
	}
	var (
		outboxID        int64
		initialAttempts int
	)
	if err := s.store.WithTenant(ctx, req.TenantID, func(tx pgx.Tx) error {
		if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       req.TenantID,
			Destination:    DestinationExternalCAIssue,
			IdempotencyKey: idempotencyKey,
			Payload:        payload,
			EffectLane:     DestinationExternalCAIssue + ":authority:" + s.outboxAuthorityID,
		}); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT id, attempts
			   FROM outbox
			  WHERE tenant_id = $1 AND idempotency_key = $2`,
			req.TenantID, idempotencyKey).Scan(&outboxID, &initialAttempts)
	}); err != nil {
		return Certificate{}, err
	}
	if s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return s.waitForExternalIssue(ctx, req.TenantID, idempotencyKey, req.RequestBinding, outboxID, initialAttempts)
}

func (s *IssuanceService) waitForExternalIssue(ctx context.Context, tenantID, idempotencyKey, requestBinding string, outboxID int64, initialAttempts int) (Certificate, error) {
	waitCtx, cancel := context.WithTimeout(ctx, externalIssueResultWaitTimeout)
	defer cancel()
	ticker := time.NewTicker(externalIssueResultPollInterval)
	defer ticker.Stop()
	for {
		if cert, found, err := s.recoverExternalIssue(waitCtx, tenantID, idempotencyKey, requestBinding); err != nil {
			return Certificate{}, err
		} else if found {
			return cert, nil
		}
		var raw []byte
		var err error
		if s.externalReplay == ExternalIssueReconciled {
			raw, err = s.idem.BoundResult(waitCtx, tenantID, externalIssueResultKey(idempotencyKey), requestBinding)
		} else {
			raw, err = s.idem.Result(waitCtx, tenantID, externalIssueResultKey(idempotencyKey))
		}
		if err == nil {
			var cert Certificate
			if err := json.Unmarshal(raw, &cert); err != nil {
				return Certificate{}, err
			}
			return cert, nil
		}
		if !errors.Is(err, orchestrator.ErrIdempotencyNotFound) && !errors.Is(err, orchestrator.ErrInProgress) {
			return Certificate{}, err
		}
		record, recordErr := s.outbox.Get(waitCtx, tenantID, outboxID)
		if recordErr != nil {
			return Certificate{}, recordErr
		}
		// A retryable worker failure belongs to this exact issuance. Return a
		// sanitized upstream failure now; a replay wakes the worker and recovers
		// using the same provider idempotency key. Never inspect or dispatch any
		// unrelated tenant/destination row from this request path.
		if record.Status == "failed" || (record.Status == "pending" && record.Attempts > initialAttempts && record.LastError != "") {
			return Certificate{}, fmt.Errorf("%w: worker attempt failed", ErrExternalIssueIncomplete)
		}
		select {
		case <-waitCtx.Done():
			return Certificate{}, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

// DeliverExternalIssue performs one external-ca.issue outbox message. It is the
// only place the provider-backed CA is called when WithOutboxIssueWorker is set.

// observeLifetime is the WithLifetimeWarning check. It reads only public
// certificate facts (expiry) and routing metadata; no error text, no body.
func (s *IssuanceService) observeLifetime(tenantID string, cert Certificate) {
	if s.lifetimeLogger == nil || s.lifetimeWarnBelow <= 0 || cert.NotAfter.IsZero() {
		return
	}
	remaining := time.Until(cert.NotAfter)
	if remaining >= s.lifetimeWarnBelow {
		return
	}
	s.lifetimeLogger.Warn("external CA issued a certificate whose whole lifetime is inside the expiry alert window; the authority chose the lifetime because trstctl does not request an ACME profile yet — expect an immediate expiry alert",
		slog.String("tenant_id", tenantID), slog.String("authority_id", s.outboxAuthorityID),
		slog.Duration("remaining_lifetime", remaining.Round(time.Minute)), slog.Duration("alert_before", s.lifetimeWarnBelow),
		slog.String("finding", "DP2-032"))
}

func (s *IssuanceService) DeliverExternalIssue(ctx context.Context, m orchestrator.Message) error {
	if m.Destination != DestinationExternalCAIssue {
		return fmt.Errorf("ca: unsupported external issue destination %q", m.Destination)
	}
	var payload ExternalIssuePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("ca: decode external issue payload: %w", err)
	}
	if payload.AuthorityID != s.outboxAuthorityID {
		return fmt.Errorf("ca: external issue for authority %q delivered to %q", payload.AuthorityID, s.outboxAuthorityID)
	}
	req := payload.IssueRequest()
	if req.TenantID == "" {
		req.TenantID = m.TenantID
	}
	if req.TenantID != m.TenantID {
		return fmt.Errorf("ca: external issue tenant mismatch")
	}
	if req.ProviderIdempotencyKey == "" {
		req.ProviderIdempotencyKey = ProviderIdempotencyKey(m.IdempotencyKey)
	}
	if req.RequestBinding == "" {
		return errors.New("ca: external issue payload has no authenticated request binding")
	}
	// Every served external-CA adapter receives a stable provider token. The
	// durable certificate projection closes crash-after-record for all adapters;
	// only adapters whose receiver actually enforces that token may re-enter the
	// provider after an ambiguous pre-record failure.
	effect := func(ctx context.Context) ([]byte, error) {
		if recovered, found, err := s.recoverExternalIssue(ctx, m.TenantID, m.IdempotencyKey, req.RequestBinding); err != nil {
			return nil, err
		} else if found {
			return json.Marshal(recovered)
		}
		cert, err := s.ca.Issue(ctx, req)
		if err != nil {
			return nil, preserveOrClassifyExternalIssueError("external_ca_provider_failed", "external CA provider issuance failed", err)
		}
		s.observeLifetime(m.TenantID, cert)
		if err := s.record(ctx, m.TenantID, m.IdempotencyKey, req.RequestBinding, cert); err != nil {
			return nil, safeExternalIssueError("external_ca_record_failed", "external CA certificate recording failed", err)
		}
		raw, err := json.Marshal(cert)
		if err != nil {
			return nil, safeExternalIssueError("external_ca_result_encode_failed", "external CA result encoding failed", err)
		}
		return raw, nil
	}
	var raw []byte
	var err error
	if s.externalReplay == ExternalIssueReconciled {
		raw, err = s.idem.DoDurableEffectBound(ctx, m.TenantID, externalIssueResultKey(m.IdempotencyKey), req.RequestBinding, effect)
	} else {
		// The durable certificate check above closes crash-after-record. If the
		// provider returned ambiguously before record, retain an indeterminate
		// at-most-once claim rather than risking a second certificate.
		raw, err = s.idem.DoAtMostOnceEffect(ctx, m.TenantID, externalIssueResultKey(m.IdempotencyKey), effect)
	}
	if err != nil {
		return preserveOrClassifyExternalIssueError("external_ca_idempotency_failed", "external CA idempotency finalization failed", err)
	}
	var cert Certificate
	if err := json.Unmarshal(raw, &cert); err != nil {
		return safeExternalIssueError("external_ca_result_decode_failed", "external CA result decoding failed", err)
	}
	if err := s.recordDependentOnce(ctx, req, m.IdempotencyKey, cert); err != nil {
		return safeExternalIssueError("external_ca_observation_failed", "external CA issuance observation failed", err)
	}
	return nil
}

type externalIssueSafeError struct {
	class string
	text  string
	cause error
}

func (e *externalIssueSafeError) Error() string             { return e.text }
func (e *externalIssueSafeError) Unwrap() error             { return e.cause }
func (e *externalIssueSafeError) SafeDeliveryClass() string { return e.class }
func (e *externalIssueSafeError) Destroy() {
	var destroyer interface{ Destroy() }
	if errors.As(e.cause, &destroyer) {
		destroyer.Destroy()
	}
	e.cause = nil
}

func safeExternalIssueError(class, text string, cause error) error {
	return &externalIssueSafeError{class: class, text: text, cause: cause}
}

func preserveOrClassifyExternalIssueError(class, text string, cause error) error {
	var alreadyClassified interface{ SafeDeliveryClass() string }
	if errors.As(cause, &alreadyClassified) {
		return cause
	}
	return safeExternalIssueError(class, text, cause)
}

func (s *IssuanceService) recoverExternalIssue(ctx context.Context, tenantID, idempotencyKey, requestBinding string) (Certificate, bool, error) {
	recovered, err := s.store.GetIssuedCertificateRecovery(ctx, tenantID, idempotencyKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, false, nil
	}
	if err != nil {
		return Certificate{}, false, err
	}
	if requestBinding != "" && !crypto.ConstantTimeEqual([]byte(recovered.RequestBinding), []byte(requestBinding)) {
		return Certificate{}, false, fmt.Errorf("%w: external CA issuance key belongs to a different authenticated command", store.ErrIdempotencyConflict)
	}
	if len(recovered.CertificatePEM) == 0 || recovered.Serial == "" || recovered.NotAfter == nil {
		return Certificate{}, false, errors.New("ca: durable external CA result is incomplete")
	}
	var cert Certificate
	if len(recovered.Response) > 0 {
		if err := json.Unmarshal(recovered.Response, &cert); err != nil {
			return Certificate{}, false, errors.New("ca: durable external CA response is invalid")
		}
		if !bytes.Equal(cert.CertificatePEM, recovered.CertificatePEM) || cert.Serial != recovered.Serial || cert.NotAfter.IsZero() || cert.Issuer == "" {
			return Certificate{}, false, errors.New("ca: durable external CA response does not match certificate inventory")
		}
	} else {
		cert = Certificate{
			CertificatePEM: append([]byte(nil), recovered.CertificatePEM...),
			Serial:         recovered.Serial, Issuer: recovered.Issuer, NotAfter: recovered.NotAfter.UTC(),
		}
	}
	// The certificate projection is committed immediately before the sibling
	// ca.issue observability row. A request poll can therefore see the projection
	// while the worker is still inside that final outbox transaction. Repairing
	// the idempotent sibling here closes both that live ordering window and a
	// crash-after-projection window before any served caller observes success.
	if err := s.recordIssueNotification(ctx, tenantID, idempotencyKey, cert); err != nil {
		return Certificate{}, false, err
	}
	return cert, true, nil
}

// enforceProfile resolves the request's bound profile (if any) and validates the
// request against it, emitting an AN-2 audit event for the decision. An unbound
// request (no ProfileName) is allowed — the enrollment-protocol servers that build
// on this (S8.2–S8.4) always bind a profile.
func (s *IssuanceService) enforceProfile(ctx context.Context, req IssueRequest) error {
	if req.ProfileName == "" {
		return nil
	}
	rec, err := s.store.GetActiveProfile(ctx, req.TenantID, req.ProfileName)
	if err != nil {
		if store.IsNotFound(err) {
			return s.auditDecision(ctx, req, 0, "deny", fmt.Sprintf("profile %q not found", req.ProfileName))
		}
		return err
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return fmt.Errorf("issuance: decode profile %q: %w", req.ProfileName, err)
	}
	info, err := crypto.InspectCSR(req.CSR)
	if err != nil {
		return s.auditDecision(ctx, req, rec.Version, "deny", "unparseable CSR")
	}
	preq := profile.Request{
		KeyAlgorithm:   info.KeyAlgorithm,
		KeyBits:        info.KeyBits,
		RequestedEKUs:  req.RequestedEKUs,
		TTL:            req.TTL,
		DNSNames:       profileDNSNames(info, req.DNSNames),
		IPAddresses:    info.IPAddresses,
		EmailAddresses: info.EmailAddresses,
		URIs:           info.URIs,
		Protocol:       req.Protocol,
	}
	if verr := prof.Validate(preq); verr != nil {
		if aerr := s.auditDecision(ctx, req, rec.Version, "deny", verr.Error()); aerr != nil {
			return aerr
		}
		return verr
	}
	return s.auditDecision(ctx, req, rec.Version, "allow", "")
}

// profileDNSNames returns every DNS name the profile must vet: the CSR's own
// SANs UNION the request's DNSNames.
//
// Preferring one over the other was a policy bypass. In-process CAs take the
// issued certificate's names from the CSR, but several external-CA adapters
// (see internal/ca/{digicert,venafi,awspca,...}) build the UPSTREAM order's
// CN/SANs from req.DNSNames instead — so whenever the CSR carried any SAN, the
// req.DNSNames set went to the upstream CA having never been checked against the
// tenant's profile suffix policy. Validating the union means every name that
// could reach a certificate, by either route, has to satisfy the profile.
func profileDNSNames(info crypto.CSRInfo, fallback []string) []string {
	seen := make(map[string]struct{}, len(info.DNSNames)+len(fallback))
	out := make([]string, 0, len(info.DNSNames)+len(fallback))
	for _, group := range [][]string{info.DNSNames, fallback} {
		for _, name := range group {
			key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
			if key == "" {
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// recordIntent durably records the external CA call before any provider request
// is attempted (AN-6). Replays reuse the same row so retries cannot create a
// second upstream side effect without an already-recorded local intent.
func (s *IssuanceService) recordIntent(ctx context.Context, tenantID, key string, req IssueRequest) error {
	payload, err := json.Marshal(struct {
		ProviderIdempotencyKey string   `json:"provider_idempotency_key"`
		DNSNames               []string `json:"dns_names,omitempty"`
		Profile                string   `json:"profile,omitempty"`
		Protocol               string   `json:"protocol,omitempty"`
	}{
		ProviderIdempotencyKey: req.ProviderIdempotencyKey,
		DNSNames:               req.DNSNames,
		Profile:                req.ProfileName,
		Protocol:               req.Protocol,
	})
	if err != nil {
		return err
	}
	return s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    DestinationExternalCAIssue,
			IdempotencyKey: key,
			Payload:        payload,
			EffectLane:     DestinationExternalCAIssue + ":authority:" + s.ca.Name(),
		})
		return err
	})
}

// auditDecision emits the profile-gated issuance decision as an AN-2 event; the
// actor is attached from the request context. A nil log (audit not wired) is a
// no-op, but the decision (the returned error path) still holds.
func (s *IssuanceService) auditDecision(ctx context.Context, req IssueRequest, version int, decision, reason string) error {
	if s.log == nil {
		return nil
	}
	payload, err := json.Marshal(struct {
		Profile  string `json:"profile"`
		Version  int    `json:"version"`
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
		Protocol string `json:"protocol,omitempty"`
	}{req.ProfileName, version, decision, reason, req.Protocol})
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: "issuance.profile_evaluated", TenantID: req.TenantID, Data: payload})
	return err
}

// record appends the public issued-certificate fact and projects inventory before
// writing the downstream ca.issue notification. The event is the reconstructable
// source of truth (AN-2); idempotency_keys is only a bounded response cache.
func (s *IssuanceService) record(ctx context.Context, tenantID, key, requestBinding string, cert Certificate) error {
	if s.log != nil {
		info, err := certinfo.Inspect(cert.CertificatePEM)
		if err != nil {
			return fmt.Errorf("ca: inspect issued certificate: %w", err)
		}
		leafDER, err := certinfo.LeafDER(cert.CertificatePEM)
		if err != nil {
			return fmt.Errorf("ca: extract issued certificate DER: %w", err)
		}
		caID := s.outboxAuthorityID
		if caID != "" {
			if err := uuid.Validate(caID); err != nil {
				// External registry IDs are UUIDs in production configuration. A
				// legacy non-UUID test/plugin name remains useful inventory source
				// metadata but cannot populate the UUID CA revocation relation.
				caID = ""
			}
		}
		notBefore, notAfter := info.NotBefore.UTC(), info.NotAfter.UTC()
		issuanceResponse, err := json.Marshal(cert)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(projections.CertificateRecorded{
			ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantID+"\x00external-ca\x00"+key)).String(),
			CAID: caID, Subject: info.Subject, SANs: append([]string(nil), info.DNSNames...),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &notBefore, NotAfter: &notAfter,
			Source: "external-ca:" + s.outboxAuthorityID, CertificateDER: leafDER,
			CertificatePEM:         append([]byte(nil), cert.CertificatePEM...),
			IssuanceResponse:       issuanceResponse,
			IssuanceIdempotencyKey: key, IssuanceRequestBinding: requestBinding,
		})
		if err != nil {
			return err
		}
		eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantID+"\x00certificate.recorded\x00"+key)).String()
		event, err := s.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventCertificateRecorded, TenantID: tenantID, Data: payload,
		})
		if err != nil {
			return err
		}
		if err := projections.New(s.store).Apply(ctx, event); err != nil {
			return err
		}
	}

	return s.recordIssueNotification(ctx, tenantID, key, cert)
}

func (s *IssuanceService) recordIssueNotification(ctx context.Context, tenantID, key string, cert Certificate) error {
	payload, err := json.Marshal(struct {
		Serial string `json:"serial"`
		Issuer string `json:"issuer"`
	}{cert.Serial, cert.Issuer})
	if err != nil {
		return err
	}
	return s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    "ca.issue",
			IdempotencyKey: IssueRecordIdempotencyKey(key),
			Payload:        payload,
		})
		return err
	})
}

func (s *IssuanceService) recordDependentOnce(ctx context.Context, req IssueRequest, idempotencyKey string, cert Certificate) error {
	if s.dependentRecorder == nil {
		return nil
	}
	_, err := s.idem.Do(ctx, req.TenantID, dependentRecordIdempotencyKey(idempotencyKey), func(ctx context.Context) ([]byte, error) {
		if err := s.recordDependent(ctx, req, idempotencyKey, cert); err != nil {
			return nil, err
		}
		return []byte(`{"recorded":true}`), nil
	})
	return err
}

func (s *IssuanceService) recordDependent(ctx context.Context, req IssueRequest, idempotencyKey string, cert Certificate) error {
	keyID := s.outboxAuthorityID
	if keyID == "" && s.ca != nil {
		keyID = s.ca.Name()
	}
	if keyID == "" {
		keyID = cert.Issuer
	}
	dependentID := cert.Serial
	if dependentID == "" && len(cert.CertificatePEM) > 0 {
		dependentID = crypto.SHA256Hex(cert.CertificatePEM)
	}
	return s.dependentRecorder.RecordDependent(ctx, dependents.Record{
		TenantID:         req.TenantID,
		ProtectedByKeyID: keyID,
		Kind:             dependents.KindCredential,
		DependentID:      dependentID,
		IdempotencyKey:   idempotencyKey,
		Source:           "ca.issue",
		Metadata: map[string]string{
			"issuer": cert.Issuer,
			"serial": cert.Serial,
		},
	})
}
