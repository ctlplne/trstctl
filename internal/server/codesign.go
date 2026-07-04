// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const defaultRekorDestination = "transparency.rekor"

// CodeSigningConfig wires the served CLM-06 code-signing surface. Keys is a
// compile-time Go interface boundary: production can pass a PKCS#11/HSM resolver,
// while tests/eval may pass software signers. There is no runtime provider registry.
type CodeSigningConfig struct {
	Keys codesign.KeyResolver
	Gate codesign.Gate

	// Attestors verify keyless/Sigstore identity proofs before signing. Fulcio is
	// represented as an attestor here: it establishes the OIDC subject and issuer
	// that SignKeyless binds into the response.
	Attestors []attest.Attestor
	// EphemeralAlgorithm is used for keyless short-lived signing keys. Empty defaults
	// to ECDSA-P256, matching common Sigstore keyless signing.
	EphemeralAlgorithm crypto.Algorithm
	// RekorDestination is the outbox destination for transparency-log publication.
	// Empty defaults to transparency.rekor.
	RekorDestination string
	// TransparencyHandler receives transparency.* outbox messages from the dispatcher
	// (a real Rekor client in production, a fixture in acceptance tests).
	TransparencyHandler orchestrator.Handler
}

func (c CodeSigningConfig) enabled() bool {
	return c.Keys != nil || len(c.Attestors) > 0
}

type servedCodeSigningService struct {
	cfg    CodeSigningConfig
	store  *store.Store
	log    *events.Log
	outbox *orchestrator.Outbox
}

func newServedCodeSigningService(cfg CodeSigningConfig, st *store.Store, log *events.Log, outbox *orchestrator.Outbox) (*servedCodeSigningService, error) {
	if !cfg.enabled() {
		return nil, nil
	}
	if st == nil || log == nil || outbox == nil {
		return nil, errors.New("server: code-signing requires store, event log, and outbox")
	}
	if cfg.Keys == nil {
		cfg.Keys = emptyCodeSigningKeys{}
	}
	if cfg.EphemeralAlgorithm == "" {
		cfg.EphemeralAlgorithm = crypto.ECDSAP256
	}
	if cfg.RekorDestination == "" {
		cfg.RekorDestination = defaultRekorDestination
	}
	return &servedCodeSigningService{cfg: cfg, store: st, log: log, outbox: outbox}, nil
}

func (s *servedCodeSigningService) SignCode(ctx context.Context, tenantID, idempotencyKey string, req api.CodeSigningRequest) (api.CodeSigningResponse, error) {
	svc, err := codesign.New(codesign.Config{
		TenantID: tenantID,
		Keys:     s.cfg.Keys,
		Gate:     s.cfg.Gate,
		Audit:    codeSigningEventAuditor{log: s.log},
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	sig, err := svc.Sign(ctx, codesign.SignRequest{
		Principal:    req.Principal,
		KeyID:        req.KeyID,
		ArtifactType: req.ArtifactType,
		Digest:       req.Digest,
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	dest, err := s.enqueueTransparency(ctx, tenantID, idempotencyKey, codeSigningTransparencyPayload{
		Mode:         "key",
		Principal:    req.Principal,
		KeyID:        sig.KeyID,
		ArtifactType: sig.ArtifactType,
		DigestHex:    fmt.Sprintf("%x", req.Digest),
		Algorithm:    sig.Algorithm,
		Signature:    sig.Value,
		PublicKeyDER: sig.PublicKeyDER,
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	return api.CodeSigningResponse{
		Algorithm:               sig.Algorithm,
		KeyID:                   sig.KeyID,
		ArtifactType:            sig.ArtifactType,
		Signature:               sig.Value,
		PublicKeyDER:            sig.PublicKeyDER,
		TransparencyDestination: dest,
	}, nil
}

func (s *servedCodeSigningService) SignKeylessCode(ctx context.Context, tenantID, idempotencyKey string, req api.CodeSigningKeylessRequest) (api.CodeSigningResponse, error) {
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: s.cfg.Attestors,
		Audit:     codeSigningEventAuditor{log: s.log},
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	identity, err := verifier.Verify(ctx, req.IdentityMethod, req.IdentityPayload)
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	ephemeral, err := crypto.GenerateLockedKey(s.cfg.EphemeralAlgorithm)
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	defer ephemeral.Destroy()

	svc, err := codesign.New(codesign.Config{
		TenantID: tenantID,
		Keys:     s.cfg.Keys,
		Gate:     s.cfg.Gate,
		Audit:    codeSigningEventAuditor{log: s.log},
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	sig, err := svc.SignKeyless(ctx, codesign.KeylessRequest{
		Principal:    req.Principal,
		Identity:     identity,
		FulcioSAN:    req.FulcioSAN,
		FulcioIssuer: req.FulcioIssuer,
		Ephemeral:    ephemeral,
		ArtifactType: req.ArtifactType,
		Digest:       req.Digest,
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	dest, err := s.enqueueTransparency(ctx, tenantID, idempotencyKey, codeSigningTransparencyPayload{
		Mode:         "keyless",
		Principal:    req.Principal,
		ArtifactType: sig.ArtifactType,
		DigestHex:    fmt.Sprintf("%x", req.Digest),
		Algorithm:    sig.Algorithm,
		Signature:    sig.Value,
		PublicKeyDER: sig.PublicKeyDER,
		FulcioSAN:    sig.FulcioSAN,
		FulcioIssuer: sig.FulcioIssuer,
	})
	if err != nil {
		return api.CodeSigningResponse{}, err
	}
	return api.CodeSigningResponse{
		Algorithm:               sig.Algorithm,
		ArtifactType:            sig.ArtifactType,
		Signature:               sig.Value,
		PublicKeyDER:            sig.PublicKeyDER,
		FulcioSAN:               sig.FulcioSAN,
		FulcioIssuer:            sig.FulcioIssuer,
		TransparencyDestination: dest,
	}, nil
}

func (s *servedCodeSigningService) enqueueTransparency(ctx context.Context, tenantID, idempotencyKey string, payload codeSigningTransparencyPayload) (string, error) {
	payload.QueuedAt = time.Now().UTC()
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	dest := s.cfg.RekorDestination
	key := fmt.Sprintf("%s:%s:%s", dest, idempotencyKey, payload.Mode)
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: tenantID, Destination: dest, IdempotencyKey: key, Payload: encoded,
		})
		return err
	})
	if err != nil {
		return "", err
	}
	return dest, nil
}

type codeSigningTransparencyPayload struct {
	Mode         string    `json:"mode"`
	Principal    string    `json:"principal"`
	KeyID        string    `json:"key_id,omitempty"`
	ArtifactType string    `json:"artifact_type"`
	DigestHex    string    `json:"digest_hex"`
	Algorithm    string    `json:"algorithm"`
	Signature    []byte    `json:"signature"`
	PublicKeyDER []byte    `json:"public_key_der"`
	FulcioSAN    string    `json:"fulcio_san,omitempty"`
	FulcioIssuer string    `json:"fulcio_issuer,omitempty"`
	QueuedAt     time.Time `json:"queued_at"`
}

type codeSigningEventAuditor struct {
	log *events.Log
}

func (a codeSigningEventAuditor) Audit(ctx context.Context, eventType, tenantID string, data []byte) error {
	if a.log == nil {
		return nil
	}
	_, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	return err
}

type emptyCodeSigningKeys struct{}

func (emptyCodeSigningKeys) Signer(keyID string) (crypto.DigestSigner, error) {
	return nil, fmt.Errorf("codesign: no key %s", keyID)
}
