// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
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
	s.mu.Lock()
	signer := s.artifactSigner
	s.mu.Unlock()
	if signer == nil {
		return ArtifactSignature{}, ErrNoArtifactSigner
	}
	return signer.SignArtifact(ctx, req)
}
