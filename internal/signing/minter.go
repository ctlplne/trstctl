// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
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
	BreakGlass               []byte // strength-downgrade break-glass token (optional)
	Attestation              []byte // successor-custodian attestation evidence (optional; PCAS-29)
	DelegationScope          string // delegated-authority scope id; when set, the minter enforces the effective ancestor constraint and binds the delegation path in the commitment (claim 33, INT-13)
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

// mintSuccessor dispatches to the attached minter, failing closed when none is
// attached. It is the in-process Go entry point; the exported gRPC handler
// Server.MintSuccessor (server.go, satisfying signerpb.SignerServiceServer) calls
// it after decoding the wire request, so the same custody discipline applies
// whether a mint arrives in-process or over the transport (INT-01).
func (s *Server) mintSuccessor(ctx context.Context, req MintRequest) (MintResult, error) {
	s.mu.Lock()
	m := s.minter
	s.mu.Unlock()
	if m == nil {
		return MintResult{}, ErrNoMinter
	}
	return m.MintSuccessor(ctx, req)
}

// MintSuccessor is the gRPC handler that satisfies signerpb.SignerServiceServer
// (INT-01). It decodes the wire request, dispatches to the attached minter inside
// the signer, and returns only public material — the successor public key and the
// opaque encoded record. It fails closed with UNIMPLEMENTED when no minter is
// attached (core-only or unlicensed signer). No private key crosses the boundary:
// the control plane can request a succession over this RPC but cannot forge one,
// because it never obtains the key material (claims 1/12/49).
func (s *Server) MintSuccessor(ctx context.Context, req *signerpb.MintSuccessorRequest) (*signerpb.MintSuccessorResponse, error) {
	mreq, err := mintRequestFromProto(req)
	if err != nil {
		return nil, err
	}
	res, err := s.mintSuccessor(ctx, mreq)
	if err != nil {
		if errors.Is(err, ErrNoMinter) {
			return nil, status.Error(codes.Unimplemented, err.Error())
		}
		// The minter's typed refusals (epoch/strength/policy/attestation/dual-control)
		// are precondition failures the caller can inspect via the status message.
		return nil, status.Errorf(codes.FailedPrecondition, "mint successor: %v", err)
	}
	return mintResultToProto(res), nil
}

// PredecessorResolver resolves an in-signer predecessor key handle to a message
// Signer whose private key never leaves the signer (INT-02). The attached
// succession minter uses it to obtain predecessor keys this signer holds — for
// example an issuing CA key under succession — so a mint resolves the predecessor
// against the signer's own custody rather than any control-plane-supplied material.
type PredecessorResolver interface {
	ResolvePredecessor(handle string) (crypto.Signer, error)
}

// SuccessorKeyStore generates a successor key INSIDE the signer keystore under a
// chosen handle, so the key persists (the identity uses it and it becomes the next
// predecessor) and never leaves the signer (INT-03).
type SuccessorKeyStore interface {
	GenerateSuccessorKey(handle string, alg crypto.Algorithm) (crypto.Signer, error)
}

// SignerCustody is the signer's key-custody surface bound into the attached
// succession minter at attach time: resolving predecessor handles and generating
// persisted successor keys. The Server implements it; the edition minter opts in via
// custodyAwareMinter, so core never imports ee/ and the minter needs no standalone
// key store.
type SignerCustody interface {
	PredecessorResolver
	SuccessorKeyStore
}

// custodyAwareMinter is implemented by a succession minter that wants the signer's
// own key custody injected. Core defines only this seam; the edition minter opts in.
type custodyAwareMinter interface {
	UseSignerCustody(SignerCustody)
}

// ResolvePredecessor returns a message-Signer view of a held key by handle, so the
// attached succession minter can use it as a predecessor. Private key bytes never
// leave the signer: signing goes through the in-signer DigestSigner.
func (s *Server) ResolvePredecessor(handle string) (crypto.Signer, error) {
	held, err := s.lookup(&signerpb.KeyHandle{Id: handle})
	if err != nil {
		return nil, err
	}
	return crypto.SignerFromDigestSigner(held.signer), nil
}

// GenerateSuccessorKey generates a key of alg INSIDE the signer keystore under the
// given handle and returns a message-Signer view of it. The private key persists in
// the signer (sealed at rest when a key store is configured) so the identity can use
// it and it becomes the next predecessor; it never leaves the signer.
func (s *Server) GenerateSuccessorKey(handle string, alg crypto.Algorithm) (crypto.Signer, error) {
	if handle == "" {
		return nil, errors.New("signing: successor handle required")
	}
	protoAlg := s.keyspec.ProtoFromAlgorithm(alg)
	if protoAlg == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, fmt.Errorf("signing: unsupported successor algorithm %q", alg)
	}
	ls, err := s.keyspec.GenerateSigningKeyFromProto(protoAlg)
	if err != nil {
		return nil, fmt.Errorf("signing: generate successor key: %w", err)
	}
	held := &heldKey{signer: ls}
	s.mu.Lock()
	if _, exists := s.keys[handle]; exists {
		s.mu.Unlock()
		ls.Destroy()
		return nil, fmt.Errorf("signing: successor handle %q already exists", handle)
	}
	s.keys[handle] = held
	s.mu.Unlock()
	if s.store != nil {
		if err := s.store.Save(handle, ls, keyConstraints{}); err != nil {
			s.mu.Lock()
			delete(s.keys, handle)
			s.mu.Unlock()
			ls.Destroy()
			return nil, fmt.Errorf("signing: persist successor key: %w", err)
		}
	}
	return crypto.SignerFromDigestSigner(ls), nil
}

// bindMinterCustody injects this signer's key custody into the attached minter, if
// the minter opts into the seam (INT-02/INT-03). Called once at construction, before
// serving, so no lock is required.
func (s *Server) bindMinterCustody() {
	if s.minter == nil {
		return
	}
	if ca, ok := s.minter.(custodyAwareMinter); ok {
		ca.UseSignerCustody(s)
	}
}
