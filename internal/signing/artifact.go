// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// ArtifactSigner is a generic signer-side extension for opaque artifacts whose
// signature must be produced inside the AN-4 signing process. Core names only
// this neutral seam; edition code decides what a kind means and which signer-held
// key is allowed to sign it.
type ArtifactSigner interface {
	SignArtifact(ctx context.Context, req ArtifactSignRequest) (ArtifactSignature, error)
}

// ArtifactSignRequest carries public identifiers and opaque payload bytes into
// the isolated signer. It carries no private key material.
type ArtifactSignRequest struct {
	Kind        string
	TenantID    string
	AuthorityID string
	KeyID       string
	Payload     []byte
}

// ArtifactSignature is the public-only result of a signer-side artifact
// signature.
type ArtifactSignature struct {
	KeyID        string
	Algorithm    crypto.Algorithm
	PublicKeyDER []byte
	Signature    []byte
}

// ErrNoArtifactSigner is returned when no artifact signer is attached.
var ErrNoArtifactSigner = errors.New("signing: no artifact signer attached")

// WithArtifactSigner attaches a generic artifact signer to the isolated signer.
// Core imports no edition package; the command attach seam supplies the concrete
// implementation when a licensed build chooses to expose one.
func WithArtifactSigner(signer ArtifactSigner) ServerOption {
	return func(s *Server) {
		if signer != nil {
			s.artifactSigner = signer
		}
	}
}

func (s *Server) signArtifact(ctx context.Context, req ArtifactSignRequest) (ArtifactSignature, error) {
	if strings.HasPrefix(req.Kind, "trstctl.audit-evidence/") {
		return s.signAuditEvidenceArtifact(req)
	}
	s.mu.Lock()
	signer := s.artifactSigner
	s.mu.Unlock()
	if signer == nil {
		return ArtifactSignature{}, ErrNoArtifactSigner
	}
	return signer.SignArtifact(ctx, req)
}

var auditEvidenceKinds = map[string]bool{
	jose.ArtifactAuditExport:        true,
	jose.ArtifactAuditRetention:     true,
	jose.ArtifactHistoryContinuity:  true,
	jose.ArtifactBillingInvoice:     true,
	jose.ArtifactDoctorReceipt:      true,
	jose.ArtifactPQCCampaignClosure: true,
	jose.ArtifactRestoreDrill:       true,
}

// signAuditEvidenceArtifact is the core, signer-owned evidence admission path.
// It accepts only the fixed audit authority/handle and a versioned kind allowlist,
// then builds the complete domain-bound JWS inside this isolated process.
func (s *Server) signAuditEvidenceArtifact(req ArtifactSignRequest) (ArtifactSignature, error) {
	if !auditEvidenceKinds[req.Kind] {
		return ArtifactSignature{}, fmt.Errorf("unsupported audit evidence kind %q", req.Kind)
	}
	if req.TenantID != "deployment" || req.AuthorityID != "audit-evidence" || req.KeyID != "audit-export" {
		return ArtifactSignature{}, errors.New("audit evidence requires deployment/audit-evidence authority and audit-export key")
	}
	held, err := s.lookup(&signerpb.KeyHandle{Id: "audit-export"})
	if err != nil {
		return ArtifactSignature{}, err
	}
	if err := held.constraints.check(&signerpb.SignRequest{
		Handle:  &signerpb.KeyHandle{Id: "audit-export"},
		Hash:    signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE,
	}); err != nil {
		return ArtifactSignature{}, err
	}
	key, err := jose.NewDigestSigningKey("audit-export", held.signer)
	if err != nil {
		return ArtifactSignature{}, err
	}
	compact, err := key.SignArtifact(req.Kind, req.Payload)
	if err != nil {
		return ArtifactSignature{}, err
	}
	return ArtifactSignature{
		KeyID:        "audit-export",
		Algorithm:    held.signer.Algorithm(),
		PublicKeyDER: append([]byte(nil), held.signer.Public().DER...),
		Signature:    []byte(compact),
	}, nil
}
