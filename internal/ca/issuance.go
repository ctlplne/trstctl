package ca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
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
	drainOutbox       func(context.Context) error
}

// Option configures an IssuanceService.
type Option func(*IssuanceService)

// WithAuditLog wires the event log so profile-gated issuance decisions are emitted
// as AN-2 audit events (with the actor from the request context).
func WithAuditLog(log *events.Log) Option { return func(s *IssuanceService) { s.log = log } }

// WithOutboxIssueWorker moves provider issuance to the shared outbox dispatcher.
// authorityID identifies which configured CA owns the external-ca.issue row, and
// drain is used by synchronous served APIs to wait for the worker-produced result.
func WithOutboxIssueWorker(authorityID string, drain func(context.Context) error) Option {
	return func(s *IssuanceService) {
		s.outboxAuthorityID = authorityID
		s.drainOutbox = drain
	}
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
	raw, err := s.idem.Do(ctx, req.TenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		cert, err := s.ca.Issue(ctx, req)
		if err != nil {
			return nil, err
		}
		if err := s.record(ctx, req.TenantID, idempotencyKey, cert); err != nil {
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
	return cert, nil
}

func (s *IssuanceService) issueViaOutbox(ctx context.Context, req IssueRequest, idempotencyKey string) (Certificate, error) {
	payload, err := json.Marshal(newExternalIssuePayload(s.outboxAuthorityID, req))
	if err != nil {
		return Certificate{}, err
	}
	if err := s.store.WithTenant(ctx, req.TenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       req.TenantID,
			Destination:    DestinationExternalCAIssue,
			IdempotencyKey: idempotencyKey,
			Payload:        payload,
		})
		return err
	}); err != nil {
		return Certificate{}, err
	}
	if s.drainOutbox != nil {
		if err := s.drainOutbox(ctx); err != nil {
			return Certificate{}, err
		}
	}
	raw, err := s.idem.Result(ctx, req.TenantID, externalIssueResultKey(idempotencyKey))
	if err != nil {
		return Certificate{}, fmt.Errorf("%w: %v", ErrExternalIssueIncomplete, err)
	}
	var cert Certificate
	if err := json.Unmarshal(raw, &cert); err != nil {
		return Certificate{}, err
	}
	return cert, nil
}

// DeliverExternalIssue performs one external-ca.issue outbox message. It is the
// only place the provider-backed CA is called when WithOutboxIssueWorker is set.
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
	_, err := s.idem.Do(ctx, m.TenantID, externalIssueResultKey(m.IdempotencyKey), func(ctx context.Context) ([]byte, error) {
		cert, err := s.ca.Issue(ctx, req)
		if err != nil {
			return nil, err
		}
		if err := s.record(ctx, m.TenantID, m.IdempotencyKey, cert); err != nil {
			return nil, err
		}
		return json.Marshal(cert)
	})
	return err
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

func profileDNSNames(info crypto.CSRInfo, fallback []string) []string {
	if len(info.DNSNames) > 0 {
		return append([]string(nil), info.DNSNames...)
	}
	return append([]string(nil), fallback...)
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

// record writes a ca.issue outbox entry so the issuance is observable (AN-6).
func (s *IssuanceService) record(ctx context.Context, tenantID, key string, cert Certificate) error {
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
