// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TenantKEKCustody keeps tenant domain key-encryption keys inside the signer
// (A123). A domain KEK is created here and wrapped by the operator HSM key the
// wrapper ID names; only the wrapped form leaves. Every later call opens it
// inside the signer, for that call alone, and destroys it after. The concrete
// custody is attached by the Enterprise signer seam through
// WithTenantKEKCustody; the core build attaches none and answers UNIMPLEMENTED.
//
// Implementations report a wrapper ID they do not hold as
// ErrTenantKEKWrapperUnknown and use tenantwrap's errors for the rest, which
// these handlers carry across the transport as fixed status codes.
type TenantKEKCustody interface {
	CreateDomainKEK(ctx context.Context, wrapperID string, binding []byte) (wrapped []byte, err error)
	OpenDomainKEK(ctx context.Context, wrapperID string, wrapped, binding []byte) error
	WrapDataKey(ctx context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error)
	UnwrapDataKey(ctx context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error)
}

var (
	// ErrNoTenantKEKCustody is returned when the signer was not licensed or
	// configured to hold tenant domain KEKs.
	ErrNoTenantKEKCustody = errors.New("signing: no tenant KEK custody attached")
	// ErrTenantKEKWrapperUnknown means the signer holds no HSM wrapper key
	// under the requested wrapper ID.
	ErrTenantKEKWrapperUnknown = errors.New("signing: the signer holds no tenant KEK wrapper with that ID")
)

const (
	maxTenantKEKWrapperID  = 128
	maxTenantKEKBinding    = 512
	maxWrappedDomainKEK    = 1 << 10
	tenantDataKeySize      = 32
	maxWrappedTenantDEKLen = 256
)

// WithTenantKEKCustody attaches the tenant domain KEK custody. The core build
// never attaches one; the EE signer attach does so only under the BYOK license.
func WithTenantKEKCustody(c TenantKEKCustody) ServerOption {
	return func(s *Server) {
		if c != nil {
			s.tenantKEK = c
		}
	}
}

func (s *Server) tenantKEKCustody() (TenantKEKCustody, error) {
	s.mu.Lock()
	custody := s.tenantKEK
	s.mu.Unlock()
	if custody == nil {
		return nil, status.Error(codes.Unimplemented, ErrNoTenantKEKCustody.Error())
	}
	return custody, nil
}

func validTenantKEKWrapperID(id string) bool {
	return id != "" && strings.TrimSpace(id) == id && len(id) <= maxTenantKEKWrapperID
}

func validTenantKEKDomain(wrapperID string, wrapped, binding []byte) error {
	if !validTenantKEKWrapperID(wrapperID) {
		return status.Error(codes.InvalidArgument, "wrapper_id must be 1 to 128 bytes with no surrounding space")
	}
	if len(binding) == 0 || len(binding) > maxTenantKEKBinding {
		return status.Error(codes.InvalidArgument, "binding must be 1 to 512 bytes")
	}
	if wrapped != nil && (len(wrapped) == 0 || len(wrapped) > maxWrappedDomainKEK) {
		return status.Error(codes.InvalidArgument, "wrapped_domain_kek must be 1 to 1024 bytes")
	}
	return nil
}

// tenantKEKStatus carries a custody failure across the transport as a fixed
// code and message; no wrapper, key, binding or ciphertext detail crosses.
func tenantKEKStatus(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	case errors.Is(err, ErrTenantKEKWrapperUnknown):
		return status.Error(codes.NotFound, ErrTenantKEKWrapperUnknown.Error())
	case errors.Is(err, tenantwrap.ErrUnavailable), errors.Is(err, tenantwrap.ErrInvalidWrapperKey):
		return status.Error(codes.Unavailable, "the tenant KEK wrapper key is unavailable")
	case errors.Is(err, tenantwrap.ErrCorrupt), errors.Is(err, tenantwrap.ErrDomainBinding):
		return status.Error(codes.DataLoss, "the wrapped domain KEK is corrupt")
	case errors.Is(err, tenantwrap.ErrUnwrap):
		return status.Error(codes.FailedPrecondition, "the wrapped value does not open under this wrapper and binding")
	default:
		return status.Error(codes.Internal, "tenant KEK custody failed")
	}
}

func (s *Server) CreateTenantDomainKEK(ctx context.Context, req *signerpb.CreateTenantDomainKEKRequest) (*signerpb.CreateTenantDomainKEKResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request")
	}
	if err := validTenantKEKDomain(req.GetWrapperId(), nil, req.GetBinding()); err != nil {
		return nil, err
	}
	custody, err := s.tenantKEKCustody()
	if err != nil {
		return nil, err
	}
	wrapped, err := custody.CreateDomainKEK(ctx, req.GetWrapperId(), req.GetBinding())
	if err != nil {
		return nil, tenantKEKStatus(err)
	}
	return &signerpb.CreateTenantDomainKEKResponse{WrappedDomainKek: wrapped}, nil
}

func (s *Server) OpenTenantDomainKEK(ctx context.Context, req *signerpb.OpenTenantDomainKEKRequest) (*signerpb.OpenTenantDomainKEKResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request")
	}
	if err := validTenantKEKDomain(req.GetWrapperId(), nonNil(req.GetWrappedDomainKek()), req.GetBinding()); err != nil {
		return nil, err
	}
	custody, err := s.tenantKEKCustody()
	if err != nil {
		return nil, err
	}
	if err := custody.OpenDomainKEK(ctx, req.GetWrapperId(), req.GetWrappedDomainKek(), req.GetBinding()); err != nil {
		return nil, tenantKEKStatus(err)
	}
	return &signerpb.OpenTenantDomainKEKResponse{}, nil
}

func (s *Server) WrapTenantDataKey(ctx context.Context, req *signerpb.WrapTenantDataKeyRequest) (*signerpb.WrapTenantDataKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request")
	}
	if err := validTenantKEKDomain(req.GetWrapperId(), nonNil(req.GetWrappedDomainKek()), req.GetBinding()); err != nil {
		return nil, err
	}
	if len(req.GetDataKey()) != tenantDataKeySize {
		return nil, status.Error(codes.InvalidArgument, "data_key must be a 32-byte data key")
	}
	custody, err := s.tenantKEKCustody()
	if err != nil {
		return nil, err
	}
	wrapped, err := custody.WrapDataKey(ctx, req.GetWrapperId(), req.GetWrappedDomainKek(), req.GetBinding(), req.GetDataKey())
	if err != nil {
		return nil, tenantKEKStatus(err)
	}
	return &signerpb.WrapTenantDataKeyResponse{WrappedDataKey: wrapped}, nil
}

func (s *Server) UnwrapTenantDataKey(ctx context.Context, req *signerpb.UnwrapTenantDataKeyRequest) (*signerpb.UnwrapTenantDataKeyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request")
	}
	if err := validTenantKEKDomain(req.GetWrapperId(), nonNil(req.GetWrappedDomainKek()), req.GetBinding()); err != nil {
		return nil, err
	}
	if len(req.GetWrappedDataKey()) == 0 || len(req.GetWrappedDataKey()) > maxWrappedTenantDEKLen {
		return nil, status.Error(codes.InvalidArgument, "wrapped_data_key must be 1 to 256 bytes")
	}
	custody, err := s.tenantKEKCustody()
	if err != nil {
		return nil, err
	}
	dek, err := custody.UnwrapDataKey(ctx, req.GetWrapperId(), req.GetWrappedDomainKek(), req.GetBinding(), req.GetWrappedDataKey())
	if err != nil {
		return nil, tenantKEKStatus(err)
	}
	return &signerpb.UnwrapTenantDataKeyResponse{DataKey: dek}, nil
}

// nonNil turns an absent bytes field into an empty, non-nil slice so the
// length check refuses it rather than skipping it.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// CreateTenantDomainKEK asks the signer to create a tenant domain KEK under
// the HSM wrapper wrapperID, bound to binding, and returns only its wrapped
// form for the caller to persist.
func (c *Client) CreateTenantDomainKEK(ctx context.Context, wrapperID string, binding []byte) ([]byte, error) {
	resp, err := c.svc.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: wrapperID, Binding: binding})
	if err != nil {
		return nil, tenantKEKError(err)
	}
	return resp.GetWrappedDomainKek(), nil
}

// OpenTenantDomainKEK asks the signer to prove the wrapped domain KEK opens
// under its wrapper and binding.
func (c *Client) OpenTenantDomainKEK(ctx context.Context, wrapperID string, wrapped, binding []byte) error {
	_, err := c.svc.OpenTenantDomainKEK(ctx, &signerpb.OpenTenantDomainKEKRequest{
		WrapperId: wrapperID, WrappedDomainKek: wrapped, Binding: binding,
	})
	return tenantKEKError(err)
}

// WrapTenantDataKey asks the signer to wrap one data key under the tenant's
// domain KEK.
func (c *Client) WrapTenantDataKey(ctx context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error) {
	resp, err := c.svc.WrapTenantDataKey(ctx, &signerpb.WrapTenantDataKeyRequest{
		WrapperId: wrapperID, WrappedDomainKek: wrapped, Binding: binding, DataKey: dataKey,
	})
	if err != nil {
		return nil, tenantKEKError(err)
	}
	return resp.GetWrappedDataKey(), nil
}

// UnwrapTenantDataKey asks the signer to unwrap one data key under the
// tenant's domain KEK. The returned key is secret material the caller wipes.
func (c *Client) UnwrapTenantDataKey(ctx context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	resp, err := c.svc.UnwrapTenantDataKey(ctx, &signerpb.UnwrapTenantDataKeyRequest{
		WrapperId: wrapperID, WrappedDomainKek: wrapped, Binding: binding, WrappedDataKey: wrappedDataKey,
	})
	if err != nil {
		return nil, tenantKEKError(err)
	}
	return resp.GetDataKey(), nil
}

// tenantKEKError turns the signer's fixed status codes back into the custody
// errors callers classify: a signer with no custody or no such wrapper is a
// wrapper that is not configured, an unreachable signer or HSM key is an
// unavailable wrapper, and an authentication failure is an unwrap failure.
func tenantKEKError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.Unimplemented:
		return ErrNoTenantKEKCustody
	case codes.NotFound:
		return ErrTenantKEKWrapperUnknown
	case codes.Unavailable, codes.ResourceExhausted:
		return fmt.Errorf("%w: %s", tenantwrap.ErrUnavailable, status.Convert(err).Message())
	case codes.DataLoss:
		return tenantwrap.ErrCorrupt
	case codes.FailedPrecondition:
		return tenantwrap.ErrUnwrap
	case codes.Canceled:
		return context.Canceled
	case codes.DeadlineExceeded:
		return context.DeadlineExceeded
	default:
		return fmt.Errorf("%w: %s", tenantwrap.ErrCustody, status.Convert(err).Message())
	}
}
