// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// KEMCustody is the signer's private-key custody surface for PCAS KEM re-wrap.
// The concrete algorithm implementation is attached by EE through WithKEMCustody;
// core only names the transport-neutral operation shape. KEM private keys are not
// signing keys and are unreachable through Sign.
type KEMCustody interface {
	GenerateSuccessorKEM(ctx context.Context, handle string, alg signerpb.Algorithm) (signerpb.Algorithm, []byte, error)
	Decapsulate(ctx context.Context, handle string, ciphertext []byte) ([]byte, error)
	ZeroizeKey(ctx context.Context, handle string) error
	DestroyAll()
}

type KEMAlgorithm = signerpb.Algorithm

// KEMPublicKey is the public result returned to control-plane callers. It holds
// no private or shared-secret bytes.
type KEMPublicKey struct {
	Handle    string
	Algorithm signerpb.Algorithm
	PublicDER []byte
}

// ErrNoKEMCustody is returned when the signer was not licensed or configured for
// KEM custody.
var ErrNoKEMCustody = errors.New("signing: no KEM custody attached")

// WithKEMCustody attaches the KEM custody implementation to the signer. The core
// build never attaches one; the EE signer attach does so only under the PCAS
// license gate.
func WithKEMCustody(c KEMCustody) ServerOption {
	return func(s *Server) {
		if c != nil {
			s.kemCustody = c
		}
	}
}

func (s *Server) GenerateSuccessorKEM(ctx context.Context, req *signerpb.GenerateSuccessorKEMRequest) (*signerpb.GenerateSuccessorKEMResponse, error) {
	if req == nil || req.GetHandle() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing KEM handle")
	}
	if req.GetAlgorithm() == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "missing KEM algorithm")
	}
	s.mu.Lock()
	custody := s.kemCustody
	s.mu.Unlock()
	if custody == nil {
		return nil, status.Error(codes.Unimplemented, ErrNoKEMCustody.Error())
	}
	alg, pub, err := custody.GenerateSuccessorKEM(ctx, req.GetHandle(), req.GetAlgorithm())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "generate successor KEM: %v", err)
	}
	return &signerpb.GenerateSuccessorKEMResponse{
		Handle:    req.GetHandle(),
		Algorithm: alg,
		PublicKey: pub,
	}, nil
}

func (s *Server) Decapsulate(ctx context.Context, req *signerpb.DecapsulateRequest) (*signerpb.DecapsulateResponse, error) {
	if req == nil || req.GetHandle() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing KEM handle")
	}
	if len(req.GetCiphertext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing KEM ciphertext")
	}
	s.mu.Lock()
	custody := s.kemCustody
	s.mu.Unlock()
	if custody == nil {
		return nil, status.Error(codes.Unimplemented, ErrNoKEMCustody.Error())
	}
	ss, err := custody.Decapsulate(ctx, req.GetHandle(), req.GetCiphertext())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "decapsulate: %v", err)
	}
	return &signerpb.DecapsulateResponse{SharedSecret: ss}, nil
}

func (s *Server) ZeroizeKey(ctx context.Context, req *signerpb.ZeroizeKeyRequest) (*signerpb.ZeroizeKeyResponse, error) {
	if req == nil || req.GetHandle() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing key handle")
	}
	s.mu.Lock()
	custody := s.kemCustody
	s.mu.Unlock()
	if custody != nil {
		if err := custody.ZeroizeKey(ctx, req.GetHandle()); err != nil {
			return nil, status.Errorf(codes.Internal, "zeroize KEM key: %v", err)
		}
	}
	_, err := s.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: &signerpb.KeyHandle{Id: req.GetHandle()}})
	if err != nil {
		return nil, err
	}
	return &signerpb.ZeroizeKeyResponse{}, nil
}

// GenerateSuccessorKEM asks the isolated signer to generate a KEM private key in
// signer custody and return only its public encapsulation key.
func (c *Client) GenerateSuccessorKEM(ctx context.Context, handle string, alg signerpb.Algorithm) (KEMPublicKey, error) {
	resp, err := c.svc.GenerateSuccessorKEM(ctx, &signerpb.GenerateSuccessorKEMRequest{
		Handle:    handle,
		Algorithm: alg,
	})
	if err != nil {
		return KEMPublicKey{}, err
	}
	return KEMPublicKey{Handle: resp.GetHandle(), Algorithm: resp.GetAlgorithm(), PublicDER: resp.GetPublicKey()}, nil
}

// Decapsulate asks the signer to perform decapsulation against a held KEM private
// key. The returned shared secret is secret material; callers must wipe it once
// the re-wrap step is complete.
func (c *Client) Decapsulate(ctx context.Context, handle string, ciphertext []byte) ([]byte, error) {
	resp, err := c.svc.Decapsulate(ctx, &signerpb.DecapsulateRequest{Handle: handle, Ciphertext: ciphertext})
	if err != nil {
		return nil, err
	}
	return resp.GetSharedSecret(), nil
}

// ZeroizeKey asks the signer to zeroize a KEM or signing key handle. It is
// idempotent for unknown handles.
func (c *Client) ZeroizeKey(ctx context.Context, handle string) error {
	_, err := c.svc.ZeroizeKey(ctx, &signerpb.ZeroizeKeyRequest{Handle: handle})
	return err
}
