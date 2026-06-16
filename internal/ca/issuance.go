package ca

import (
	"context"
	"encoding/json"
	"fmt"

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
}

// Option configures an IssuanceService.
type Option func(*IssuanceService)

// WithAuditLog wires the event log so profile-gated issuance decisions are emitted
// as AN-2 audit events (with the actor from the request context).
func WithAuditLog(log *events.Log) Option { return func(s *IssuanceService) { s.log = log } }

// NewIssuanceService wires an issuance service over a CA and the platform's
// idempotency and outbox.
func NewIssuanceService(ca CA, idem *orchestrator.Idempotency, outbox *orchestrator.Outbox, st *store.Store, opts ...Option) *IssuanceService {
	s := &IssuanceService{ca: ca, idem: idem, outbox: outbox, store: st}
	for _, o := range opts {
		o(s)
	}
	return s
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
		KeyAlgorithm: info.KeyAlgorithm, KeyBits: info.KeyBits,
		RequestedEKUs: req.RequestedEKUs, TTL: req.TTL,
		DNSNames: req.DNSNames, Protocol: req.Protocol,
	}
	if verr := prof.Validate(preq); verr != nil {
		if aerr := s.auditDecision(ctx, req, rec.Version, "deny", verr.Error()); aerr != nil {
			return aerr
		}
		return verr
	}
	return s.auditDecision(ctx, req, rec.Version, "allow", "")
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
		_, err := s.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    "ca.issue",
			IdempotencyKey: key,
			Payload:        payload,
		})
		return err
	})
}
