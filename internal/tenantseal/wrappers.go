// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
)

const WrapperKindLocalFile = "local_file"

var (
	// ErrWrapperNotConfigured means the persisted wrapper kind and ID did not
	// exactly match an operator-provisioned registry entry. The registry never
	// chooses a default or tries another wrapper.
	ErrWrapperNotConfigured = errors.New("tenantseal: wrapper is not configured")
	// ErrInvalidWrapperConfig means the operator registry itself is ambiguous or
	// incomplete. It is returned at construction, before any tenant access.
	ErrInvalidWrapperConfig = errors.New("tenantseal: invalid local wrapper configuration")
)

// WrapperRef is the complete, non-secret routing identity persisted beside a
// tenant's wrapped domain KEK. Both fields must match; neither is inferred from
// ciphertext or AAD.
type WrapperRef struct {
	Kind string
	ID   string
}

// TransientDomainKEK is a callback-scoped, destroyable tenant key-encryption
// key. LocalWrapperRegistry returns a *seal.LocalKEK in locked memory.
type TransientDomainKEK interface {
	seal.KeyWrapper
	Destroy()
}

// DomainKEKRegistry opens a transient tenant-domain KEK through one exact,
// non-egress operator-configured wrapper. Implementations return key memory
// owned by the caller, which must Destroy it. A remote custody integration must
// not use this request-path seam; it belongs in the bounded outbox workflow.
type DomainKEKRegistry interface {
	OpenDomainKEK(
		ctx context.Context,
		ref WrapperRef,
		wrapped, binding []byte,
	) (TransientDomainKEK, error)
}

// LocalWrapper names one existing operator-provisioned local wrapper file. Path
// is configuration metadata, never key material; tenant rows persist only ID.
type LocalWrapper struct {
	ID   string
	Path string
}

// LocalWrapperRegistry resolves only explicit local_file kind/ID pairs. It is
// immutable after construction and safe for concurrent reads.
type LocalWrapperRegistry struct {
	pathsByID map[string]string
}

// NewLocalWrapperRegistry builds an exact local wrapper registry. It does not
// read or create wrapper files; availability and custody checks happen inside
// tenantwrap when a fenced operation needs the key.
func NewLocalWrapperRegistry(wrappers []LocalWrapper) (*LocalWrapperRegistry, error) {
	paths := make(map[string]string, len(wrappers))
	for _, wrapper := range wrappers {
		if wrapper.ID == "" ||
			strings.TrimSpace(wrapper.ID) != wrapper.ID ||
			wrapper.Path == "" {
			return nil, ErrInvalidWrapperConfig
		}
		if _, exists := paths[wrapper.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate wrapper id", ErrInvalidWrapperConfig)
		}
		paths[wrapper.ID] = wrapper.Path
	}
	return &LocalWrapperRegistry{pathsByID: paths}, nil
}

// OpenDomainKEK requires an exact local_file kind and configured ID. It never
// falls back to the only entry, a deployment wrapper, or a trial-decrypt path.
func (r *LocalWrapperRegistry) OpenDomainKEK(
	ctx context.Context,
	ref WrapperRef,
	wrapped, binding []byte,
) (TransientDomainKEK, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || ref.Kind != WrapperKindLocalFile {
		return nil, fmt.Errorf("%w: wrapper kind/id has no exact match", ErrWrapperNotConfigured)
	}
	path, ok := r.pathsByID[ref.ID]
	if !ok {
		return nil, fmt.Errorf("%w: wrapper kind/id has no exact match", ErrWrapperNotConfigured)
	}
	return tenantwrap.OpenDomainKEK(path, wrapped, binding)
}
