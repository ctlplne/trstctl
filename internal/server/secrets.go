package server

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// sealKeyWrapper is the envelope-encryption key wrapper the served secret store seals
// values under at rest (the credential KEK). It is an alias for seal.KeyWrapper so
// Deps can name the type without server.go itself importing the seal package.
type sealKeyWrapper = seal.KeyWrapper

// This file wires the SERVED secrets/identity surface (GAP-006): it assembles the
// api.SecretsBackend from the control plane's already-provisioned dependencies — the
// credential KEK (envelope encryption at rest), the RLS-isolated store, the AN-2
// event log (as an auditor), and the issuing CA in the out-of-process signer (AN-4)
// for the dynamic PKI secret. Until now the five frameworks (authmethod F58,
// secretsync F60, secretsdk F64, pkisecret F67, secretshare F68) were library-only
// with zero importers on the served path; this is the composition that mounts them.

// secretRevocationSink is the store-backed pkisecret.RevocationSink (GAP-005): it
// records issued/revoked dynamic-secret serials as events projected into the SAME
// ca_issued_certs table the served OCSP responder / CRL endpoint read (AN-1), so
// a revoked dynamic-secret certificate actually stops validating, exactly like a
// revoked protocol/API leaf. It is the seam pkisecret's WithRevocationSink expects.
type secretRevocationSink struct {
	store *store.Store
	log   *events.Log
}

// RecordIssued notes that the CA issued a serial so OCSP can answer "good" rather
// than "unknown" and a later revoke has a row to flip (idempotent in the store).
func (s *secretRevocationSink) RecordIssued(ctx context.Context, tenantID, caID, serial string) error {
	issuedAt := time.Now().UTC()
	if s.log == nil {
		return errors.New("server: secret revocation sink requires an event log")
	}
	payload, err := json.Marshal(projections.CAIssuedCertificate{
		CAID: caID, Serial: serial, IssuedAt: issuedAt, Source: "pkisecret",
	})
	if err != nil {
		return err
	}
	return s.appendAndProject(ctx, events.Event{
		Type: projections.EventCAIssuedCertificate, TenantID: tenantID, Data: payload,
	})
}

// Revoke records the serial revoked on the served revocation pipeline (reflected in
// OCSP immediately and the next CRL) by emitting a revocation event (AN-2).
// Idempotent on serial (the projection keeps the first revocation time).
func (s *secretRevocationSink) Revoke(ctx context.Context, tenantID, caID, serial string, reasonCode int) error {
	revokedAt := time.Now().UTC()
	if s.log == nil {
		return errors.New("server: secret revocation sink requires an event log")
	}
	payload, err := json.Marshal(projections.CACertificateRevoked{
		CAID: caID, Serial: serial, ReasonCode: reasonCode, RevokedAt: revokedAt, Source: "pkisecret",
	})
	if err != nil {
		return err
	}
	return s.appendAndProject(ctx, events.Event{
		Type: projections.EventCACertificateRevoked, TenantID: tenantID, Data: payload,
	})
}

func (s *secretRevocationSink) appendAndProject(ctx context.Context, ev events.Event) error {
	stored, err := s.log.Append(ctx, ev)
	if err != nil {
		return err
	}
	return projections.New(s.store).Apply(ctx, stored)
}

// apiSecretsServed reports whether the running binary mounts the served secrets/
// identity surface (GAP-006) — the wiring assertion (it delegates to the API's
// SecretsServed). A startup log and the acceptance test consult it.
func (s *Server) apiSecretsServed() bool { return s.api != nil && s.api.SecretsServed() }

// buildSecretsBackend assembles the api.SecretsBackend from the assembled server's
// dependencies. It is wired into the served API only when the secrets surface is
// enabled and a KEK is provided (envelope encryption at rest is mandatory for the
// secret store). The issuing CA + auth secret are optional and gate their
// sub-features (the dynamic PKI secret and machine login respectively); when absent,
// those routes fail closed rather than degrade. The KEK is the same credential KEK
// the rest of the platform uses for secrets at rest (R3.1).
func (s *Server) buildSecretsBackend(d Deps) api.SecretsBackend {
	be := api.SecretsBackend{
		KEK:        d.KEK,
		Store:      d.Store,
		Audit:      audit.NewAuditor(s.log),
		AuthSecret: d.SecretsAuthSecret,
		CAID:       IssuingCAID(),
		// Resolve the issuing CA lazily (the control plane provisions it AFTER the API
		// is constructed): the dynamic PKI secret reaches s.caSigner/s.caCertDER once
		// they are set, and reports issuance unavailable (fail closed) until then or if
		// no signer is configured (AN-4).
		CA: func() ([]byte, crypto.DigestSigner) {
			if s.caSigner == nil || len(s.caCertDER) == 0 {
				return nil, nil
			}
			return s.caCertDER, s.caSigner
		},
		// Record dynamic-secret issuance/revocation on the served revocation pipeline so
		// a revoked dynamic-secret cert stops validating (GAP-005). The store ops are
		// harmless when no cert was issued, and the resolver above gates actual issuance.
		RevocationSink: &secretRevocationSink{store: d.Store, log: s.log},
	}
	return be
}
