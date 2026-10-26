// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
	corestore "trstctl.com/trstctl/internal/store"
)

// AttestorProvisioner reaches the isolated signer's tenant attestor floor over
// its authenticated transport, the same way RootAnchorProvisioner reaches the
// root floor. What the control plane wrote is not evidence of what the signer
// will verify against, so every registration is read back from the signer.
type AttestorProvisioner interface {
	ProvisionAgentAttestor(context.Context, string, string, []byte, string) error
	ReadAgentAttestor(context.Context, string, string) ([]byte, string, error)
}

var (
	ErrAttestorSignerUnavailable = errors.New("agentid api: signer attestor floor is unavailable")
	ErrAttestorSignerReadback    = errors.New("agentid api: signer attestor readback differs from the registered binding")
	ErrInvalidAttestorRequest    = errors.New("agentid api: invalid attestor request")
	ErrAttestorLogUnavailable    = errors.New("agentid api: attestor event log is unavailable")
)

// RegisterAttestor appends the immutable tenant/key attestor binding, projects its
// RLS serving copy, then provisions the signer's tenant attestor floor and reads it
// back independently (A150). The deterministic event ID, the projection and the
// signer each keep the first writer, so a lost response can be retried and a
// changed key or method needs a new key ID.
func (s *service) RegisterAttestor(ctx context.Context, tenantID string, req AttestorRequest) (AttestorResponse, error) {
	if s.attestorProvisioner == nil {
		return AttestorResponse{}, ErrAttestorSignerUnavailable
	}
	if len(req.PublicDER) != 0 && req.PublicPEM != "" {
		return AttestorResponse{}, fmt.Errorf("provide only one of public_der or public_pem: %w", ErrInvalidAttestorRequest)
	}
	publicDER := append([]byte(nil), req.PublicDER...)
	if req.PublicPEM != "" {
		decoded, err := delegation.DecodeRootAnchorPEM([]byte(req.PublicPEM))
		if err != nil {
			return AttestorResponse{}, fmt.Errorf("decode public_pem: %w", ErrInvalidAttestorRequest)
		}
		publicDER = decoded
	}
	if !delegation.ValidRootAnchorID(req.KeyID) {
		return AttestorResponse{}, fmt.Errorf("key_id is empty or contains an unsafe path character: %w", ErrInvalidAttestorRequest)
	}
	if strings.TrimSpace(req.Method) != req.Method || delegation.ClassOfMethod(req.Method) == delegation.ClassNone {
		return AttestorResponse{}, fmt.Errorf("method %q is not a known attestation method: %w", req.Method, ErrInvalidAttestorRequest)
	}
	if len(publicDER) == 0 {
		return AttestorResponse{}, fmt.Errorf("attestor public key is required: %w", ErrInvalidAttestorRequest)
	}
	if err := crypto.ValidatePublicKeyDER(publicDER); err != nil {
		return AttestorResponse{}, fmt.Errorf("attestor public key is invalid (%v): %w", err, ErrInvalidAttestorRequest)
	}
	if s.repo != nil {
		if s.log == nil {
			return AttestorResponse{}, ErrAttestorLogUnavailable
		}
		encoded, err := delegation.Encode(delegation.AttestorRegisteredV1{
			TenantID: tenantID, KeyID: req.KeyID, Method: req.Method, PublicDER: publicDER,
		})
		if err != nil {
			return AttestorResponse{}, err
		}
		encoded.ID = delegation.AttestorEventID(tenantID, req.KeyID)
		recorded, found, err := s.log.EventByID(ctx, encoded.ID)
		if err != nil {
			return AttestorResponse{}, err
		}
		if !found {
			recorded, err = s.log.Append(ctx, encoded)
			if err != nil {
				return AttestorResponse{}, err
			}
		}
		if recorded.TenantID != tenantID || recorded.Type != encoded.Type ||
			recorded.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(recorded.Data, encoded.Data) {
			return AttestorResponse{}, fmt.Errorf("agentid api: attestor key ID already binds a different key or method: %w", corestore.ErrIdempotencyConflict)
		}
		if err := s.repo.ApplyAttestorEvent(ctx, recorded); err != nil {
			return AttestorResponse{}, err
		}
	}
	if err := s.attestorProvisioner.ProvisionAgentAttestor(ctx, tenantID, req.KeyID, publicDER, req.Method); err != nil {
		return AttestorResponse{}, fmt.Errorf("agentid api: provision signer attestor: %w", err)
	}
	readDER, readMethod, err := s.attestorProvisioner.ReadAgentAttestor(ctx, tenantID, req.KeyID)
	if err != nil {
		return AttestorResponse{}, fmt.Errorf("agentid api: read signer attestor: %w", err)
	}
	if !bytes.Equal(readDER, publicDER) || readMethod != req.Method {
		return AttestorResponse{}, ErrAttestorSignerReadback
	}
	return AttestorResponse{
		KeyID:       req.KeyID,
		Method:      req.Method,
		Class:       delegation.ClassOfMethod(req.Method).String(),
		PublicDER:   publicDER,
		Provisioned: true,
	}, nil
}

// ListAttestors returns the tenant's registered attestors, each marked provisioned
// only when the signer independently reads back the exact key and method.
func (s *service) ListAttestors(ctx context.Context, tenantID string) (AttestorsResponse, error) {
	resp := AttestorsResponse{Attestors: []AttestorResponse{}}
	if s.repo == nil {
		return resp, nil
	}
	if s.attestorProvisioner == nil {
		return AttestorsResponse{}, ErrAttestorSignerUnavailable
	}
	attestors, err := s.repo.ListAttestors(ctx, tenantID)
	if err != nil {
		return AttestorsResponse{}, err
	}
	for _, a := range attestors {
		readDER, readMethod, readErr := s.attestorProvisioner.ReadAgentAttestor(ctx, tenantID, a.KeyID)
		resp.Attestors = append(resp.Attestors, AttestorResponse{
			KeyID:       a.KeyID,
			Method:      a.Method,
			Class:       delegation.ClassOfMethod(a.Method).String(),
			PublicDER:   append([]byte(nil), a.PublicDER...),
			CreatedAt:   a.CreatedAt,
			Provisioned: readErr == nil && bytes.Equal(readDER, a.PublicDER) && readMethod == a.Method,
		})
	}
	resp.Count = len(resp.Attestors)
	return resp, nil
}
