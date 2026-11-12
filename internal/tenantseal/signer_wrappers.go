// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/tenantwrap"
)

// SignerTenantKEK is the isolated signer's tenant domain KEK custody as the
// control plane reaches it (A123, owner decision 2026-10-26). The signer
// creates each domain KEK, keeps it wrapped by an operator HSM key, and wraps
// and unwraps the tenant's data keys itself; only the wrapped KEK is persisted
// here. Implementations report a signer without custody, or a wrapper it does
// not hold, as an error matching ErrWrapperNotConfigured, and the rest with
// tenantwrap's errors.
type SignerTenantKEK interface {
	CreateTenantDomainKEK(ctx context.Context, wrapperID string, binding []byte) ([]byte, error)
	OpenTenantDomainKEK(ctx context.Context, wrapperID string, wrapped, binding []byte) error
	WrapTenantDataKey(ctx context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error)
	UnwrapTenantDataKey(ctx context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error)
}

// SignerWrapperRegistry resolves only explicit pkcs11 and kms kind/ID pairs
// the operator configured on the control plane and routes them to the signer.
// It holds no key: the TransientDomainKEK it returns wraps and unwraps through
// the signer, which opens the domain KEK for each call. signer returns the
// current client at call time, since a supervised signer restart replaces it.
// The signer names its wrappers by ID alone, so one ID has one kind.
type SignerWrapperRegistry struct {
	kinds  map[string]string
	signer func() SignerTenantKEK
}

// NewSignerWrapperRegistry builds the exact pkcs11 wrapper registry. It does
// not reach the signer; the first tenant operation does.
func NewSignerWrapperRegistry(ids []string, signer func() SignerTenantKEK) (*SignerWrapperRegistry, error) {
	refs := make([]WrapperRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, WrapperRef{Kind: WrapperKindPKCS11, ID: id})
	}
	return NewSignerWrapperRegistryRefs(refs, signer)
}

// NewSignerWrapperRegistryRefs builds the exact registry of pkcs11 and kms
// (OD-10) wrappers the signer holds.
func NewSignerWrapperRegistryRefs(refs []WrapperRef, signer func() SignerTenantKEK) (*SignerWrapperRegistry, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: the signer is required for pkcs11 and kms wrappers", ErrInvalidWrapperConfig)
	}
	kinds := make(map[string]string, len(refs))
	for _, ref := range refs {
		if ref.ID == "" || strings.TrimSpace(ref.ID) != ref.ID {
			return nil, ErrInvalidWrapperConfig
		}
		if ref.Kind != WrapperKindPKCS11 && ref.Kind != WrapperKindKMS {
			return nil, fmt.Errorf("%w: the signer holds pkcs11 and kms wrappers only", ErrInvalidWrapperConfig)
		}
		if _, dup := kinds[ref.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate wrapper id", ErrInvalidWrapperConfig)
		}
		kinds[ref.ID] = ref.Kind
	}
	return &SignerWrapperRegistry{kinds: kinds, signer: signer}, nil
}

func (r *SignerWrapperRegistry) holds(kind string) bool {
	if r == nil {
		return false
	}
	for _, k := range r.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func (r *SignerWrapperRegistry) route(ctx context.Context, ref WrapperRef) (SignerTenantKEK, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: wrapper kind/id has no exact match", ErrWrapperNotConfigured)
	}
	if kind, ok := r.kinds[ref.ID]; !ok || kind != ref.Kind {
		return nil, fmt.Errorf("%w: wrapper kind/id has no exact match", ErrWrapperNotConfigured)
	}
	signer := r.signer()
	if signer == nil {
		return nil, fmt.Errorf("%w: the signer is not available", tenantwrap.ErrUnavailable)
	}
	return signer, nil
}

// OpenDomainKEK proves through the signer that the wrapped domain KEK opens
// under its wrapper and binding, and returns a handle bound to them.
func (r *SignerWrapperRegistry) OpenDomainKEK(
	ctx context.Context,
	ref WrapperRef,
	wrapped, binding []byte,
) (TransientDomainKEK, error) {
	signer, err := r.route(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := signer.OpenTenantDomainKEK(ctx, ref.ID, wrapped, binding); err != nil {
		return nil, err
	}
	return newSignerDomainKEK(ctx, signer, ref.ID, wrapped, binding), nil
}

// CreateDomainKEK has the signer create a domain KEK under the wrapper and
// returns a handle bound to it with the wrapped form to persist.
func (r *SignerWrapperRegistry) CreateDomainKEK(
	ctx context.Context,
	ref WrapperRef,
	binding []byte,
) (TransientDomainKEK, []byte, error) {
	signer, err := r.route(ctx, ref)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := signer.CreateTenantDomainKEK(ctx, ref.ID, binding)
	if err != nil {
		return nil, nil, err
	}
	return newSignerDomainKEK(ctx, signer, ref.ID, wrapped, binding), wrapped, nil
}

var errSignerDomainKEKDestroyed = errors.New("tenantseal: the signer-held domain key is outside its fenced callback")

// signerDomainKEK is a callback-scoped handle on a domain KEK the signer
// holds. It carries the wrapped KEK and binding, never the KEK, and refuses
// every call after Destroy.
type signerDomainKEK struct {
	mu        sync.Mutex
	ctx       context.Context
	signer    SignerTenantKEK
	wrapperID string
	wrapped   []byte
	binding   []byte
	destroyed bool
}

var _ TransientDomainKEK = (*signerDomainKEK)(nil)

func newSignerDomainKEK(ctx context.Context, signer SignerTenantKEK, wrapperID string, wrapped, binding []byte) *signerDomainKEK {
	return &signerDomainKEK{
		ctx: ctx, signer: signer, wrapperID: wrapperID,
		wrapped: append([]byte(nil), wrapped...), binding: append([]byte(nil), binding...),
	}
}

func (k *signerDomainKEK) live() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.destroyed {
		return errSignerDomainKEKDestroyed
	}
	return nil
}

func (k *signerDomainKEK) WrapDEK(dek []byte) ([]byte, error) {
	if err := k.live(); err != nil {
		return nil, err
	}
	return k.signer.WrapTenantDataKey(k.ctx, k.wrapperID, k.wrapped, k.binding, dek)
}

func (k *signerDomainKEK) UnwrapDEK(wrapped []byte) ([]byte, error) {
	if err := k.live(); err != nil {
		return nil, err
	}
	return k.signer.UnwrapTenantDataKey(k.ctx, k.wrapperID, k.wrapped, k.binding, wrapped)
}

func (k *signerDomainKEK) Destroy() {
	k.mu.Lock()
	k.destroyed = true
	k.mu.Unlock()
}

// RoutedWrapperRegistry sends each exact wrapper kind to the one registry
// configured for it: local_file to the local files, pkcs11 to the signer. An
// unknown or unconfigured kind is not configured; nothing falls back across
// kinds or to the deployment KEK.
type RoutedWrapperRegistry struct {
	byKind map[string]DomainKEKManager
}

var _ DomainKEKManager = (*RoutedWrapperRegistry)(nil)

// NewRoutedWrapperRegistry routes local_file to local and, when signer is
// non-nil, pkcs11 to signer.
func NewRoutedWrapperRegistry(local *LocalWrapperRegistry, signer *SignerWrapperRegistry) *RoutedWrapperRegistry {
	byKind := map[string]DomainKEKManager{}
	if local != nil {
		byKind[WrapperKindLocalFile] = local
	}
	if signer.holds(WrapperKindPKCS11) {
		byKind[WrapperKindPKCS11] = signer
	}
	if signer.holds(WrapperKindKMS) {
		byKind[WrapperKindKMS] = signer
	}
	return &RoutedWrapperRegistry{byKind: byKind}
}

func (r *RoutedWrapperRegistry) manager(ref WrapperRef) (DomainKEKManager, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: wrapper kind/id has no exact match", ErrWrapperNotConfigured)
	}
	m, ok := r.byKind[ref.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: wrapper kind/id has no exact match", ErrWrapperNotConfigured)
	}
	return m, nil
}

func (r *RoutedWrapperRegistry) OpenDomainKEK(
	ctx context.Context,
	ref WrapperRef,
	wrapped, binding []byte,
) (TransientDomainKEK, error) {
	m, err := r.manager(ref)
	if err != nil {
		return nil, err
	}
	return m.OpenDomainKEK(ctx, ref, wrapped, binding)
}

func (r *RoutedWrapperRegistry) CreateDomainKEK(
	ctx context.Context,
	ref WrapperRef,
	binding []byte,
) (TransientDomainKEK, []byte, error) {
	m, err := r.manager(ref)
	if err != nil {
		return nil, nil, err
	}
	return m.CreateDomainKEK(ctx, ref, binding)
}
