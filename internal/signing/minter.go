// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// SuccessionMinter is a generic successor-minting extension attached to the AN-4
// signer. The core defines only this generic seam; the concrete succession
// semantics — commitment forming, dual-signing, and epoch discipline — live in an
// edition implementation attached via WithSuccessionMinter. The core-only build
// attaches none and mints no successions. The interface names nothing
// edition-specific: it takes a generic minting request and returns a generic
// result whose record body is opaque to core.
type SuccessionMinter interface {
	MintSuccessor(ctx context.Context, req MintRequest) (MintResult, error)
}

// MintRequest is the generic successor-minting request. It carries NO private key
// material: the predecessor key is referenced only by an opaque in-signer handle,
// so the request that crosses into the minter never contains a private key.
type MintRequest struct {
	IdentityID               string
	TenantID                 string
	DeploymentScope          string
	PredecessorHandle        string
	AssertedPredecessorEpoch uint64
	TargetAlgorithm          crypto.Algorithm
	PolicyRef                string
	PolicyDecision           []byte // signed policy artifact (optional)
	Authorization            []byte // dual-control authorization token (optional)
	NotBefore                int64
	NotAfter                 int64
}

// MintResult is the generic successor-minting result. It carries only public
// material — the successor public key and the opaque encoded record — so no
// private key crosses the boundary.
type MintResult struct {
	Epoch              uint64
	SuccessorAlgorithm crypto.Algorithm
	SuccessorPublicDER []byte
	EncodedRecord      []byte
}

// ErrNoMinter is returned when no successor minter is attached (core-only build).
var ErrNoMinter = errors.New("signing: no successor minter attached")

// WithSuccessionMinter attaches a successor minter to the signer, beside
// WithKeyFactory. The core names only the generic seam; the edition supplies the
// implementation without importing ee/ into core.
func WithSuccessionMinter(m SuccessionMinter) ServerOption {
	return func(s *Server) {
		if m != nil {
			s.minter = m
		}
	}
}

// MintSuccessor dispatches to the attached minter, failing closed when none is
// attached. It is the Go entry point that the edition RPC handler and tests use;
// the wire RPC is added with generated code under the buf compatibility gates.
func (s *Server) MintSuccessor(ctx context.Context, req MintRequest) (MintResult, error) {
	s.mu.Lock()
	m := s.minter
	s.mu.Unlock()
	if m == nil {
		return MintResult{}, ErrNoMinter
	}
	return m.MintSuccessor(ctx, req)
}
