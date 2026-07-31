// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/store"
)

var ErrCipherLeaseExpired = errors.New("tenantseal: cipher is outside its fenced callback")

// Status is the stable public reason tenant cryptographic access failed closed.
// Projection states retain their exact spellings; runtime custody failures use
// separate honest values instead of pretending an authenticated unwrap failure
// proves which input was wrong.
type Status string

const (
	StatusMigrating          Status = store.TenantKeyDomainStateMigrating
	StatusPartial            Status = store.TenantKeyDomainStatePartial
	StatusSealQueued         Status = store.TenantKeyDomainStateSealQueued
	StatusSealing            Status = store.TenantKeyDomainStateSealing
	StatusSealed             Status = store.TenantKeyDomainStateSealed
	StatusUnsealing          Status = store.TenantKeyDomainStateUnsealing
	StatusWrapperUnavailable Status = store.TenantKeyDomainStateWrapperUnavailable
	StatusWrongWrapper       Status = store.TenantKeyDomainStateWrongWrapper
	StatusCorrupt            Status = store.TenantKeyDomainStateCorrupt

	StatusUnwrapFailed       Status = "unwrap_failed"
	StatusCustodyUnavailable Status = "custody_unavailable"
)

// AccessError carries one public fail-closed status while retaining a generic
// internal cause for errors.Is/log correlation. Error intentionally exposes no
// wrapper path, key bytes, ciphertext, or AAD.
type AccessError struct {
	status Status
	cause  error
}

func (e *AccessError) Error() string {
	return "tenantseal: tenant cryptographic access unavailable: " + string(e.status)
}

func (e *AccessError) Unwrap() error { return e.cause }

// PublicStatus returns the exact status safe to expose to an operator.
func (e *AccessError) PublicStatus() Status { return e.status }

// StatusOf extracts a public tenant-seal status through wrapped errors.
func StatusOf(err error) (Status, bool) {
	var accessErr *AccessError
	if !errors.As(err, &accessErr) {
		return "", false
	}
	return accessErr.PublicStatus(), true
}

func statusError(status Status, cause error) error {
	return &AccessError{status: status, cause: cause}
}

// Cipher is valid only during its Access.WithTenant callback. Implementations
// route to exactly one already-resolved wrapper and never parse AAD to select a
// tenant, domain, or wrapper.
type Cipher interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(container, aad []byte) ([]byte, error)
}

// Access resolves one tenant's protection mode under the shared PostgreSQL
// tenant-domain fence and lends a callback-scoped Cipher.
type Access interface {
	WithTenant(ctx context.Context, tenantID string, fn func(Cipher) error) error
}

// SharedDomainStore keeps the projection read and the complete crypto callback
// inside one RLS-scoped shared tenant-domain fence.
type SharedDomainStore interface {
	WithTenantKeyDomainShared(
		ctx context.Context,
		tenantID string,
		fn func(*store.TenantKeyDomain) error,
	) error
}

// Resolver implements Access using the deployment wrapper for missing legacy
// rows, an explicit version-routed dual cipher during migration, and a transient
// independently wrapped domain key after hot-state migration completes.
type Resolver struct {
	domains    SharedDomainStore
	deployment seal.KeyWrapper
	registry   DomainKEKRegistry
}

var _ Access = (*Resolver)(nil)

// NewAccess constructs the tenant cryptographic resolver. It performs no
// filesystem or database work.
func NewAccess(
	domains SharedDomainStore,
	deployment seal.KeyWrapper,
	registry DomainKEKRegistry,
) (*Resolver, error) {
	if domains == nil {
		return nil, errors.New("tenantseal: shared domain store is required")
	}
	if deployment == nil {
		return nil, errors.New("tenantseal: deployment wrapper is required")
	}
	if registry == nil {
		return nil, errors.New("tenantseal: tenant wrapper registry is required")
	}
	return &Resolver{domains: domains, deployment: deployment, registry: registry}, nil
}

// WithTenant holds the store's shared tenant-domain fence until fn finishes,
// the Cipher lease is revoked, and any transient domain key is destroyed.
func (r *Resolver) WithTenant(
	ctx context.Context,
	tenantID string,
	fn func(Cipher) error,
) error {
	if tenantID == "" {
		return errors.New("tenantseal: tenant id is required (AN-1)")
	}
	if fn == nil {
		return errors.New("tenantseal: cipher callback is required")
	}
	return r.domains.WithTenantKeyDomainShared(
		ctx,
		tenantID,
		func(domain *store.TenantKeyDomain) error {
			if domain == nil {
				cipher := newLeasedCipher(
					func(plaintext, aad []byte) ([]byte, error) {
						return seal.Seal(r.deployment, plaintext, aad)
					},
					func(container, aad []byte) ([]byte, error) {
						containerDomain, err := seal.Domain(container)
						if err != nil {
							return nil, err
						}
						if containerDomain != nil {
							return nil, seal.ErrDomain
						}
						return seal.Open(r.deployment, container, aad)
					},
				)
				defer cipher.invalidate()
				return fn(cipher)
			}

			mode, status := resolveDomainAccessMode(tenantID, *domain)
			if mode == domainAccessDenied {
				return statusError(status, nil)
			}
			binding, err := DomainBinding(domain.TenantID, domain.DomainID, domain.Generation)
			if err != nil {
				return statusError(StatusCorrupt, err)
			}
			domainKey, err := r.registry.OpenDomainKEK(
				ctx,
				WrapperRef{Kind: domain.WrapperKind, ID: domain.WrapperID},
				domain.WrappedDomainKEK,
				binding,
			)
			if err != nil {
				return classifyDomainOpenError(err)
			}
			if domainKey == nil {
				return statusError(
					StatusCustodyUnavailable,
					errors.New("tenantseal: wrapper registry returned no domain key"),
				)
			}
			defer domainKey.Destroy()

			open := func(container, aad []byte) ([]byte, error) {
				return seal.OpenDomain(domainKey, container, aad, binding)
			}
			if mode == domainAccessDualMigration {
				open = func(container, aad []byte) ([]byte, error) {
					containerDomain, err := seal.Domain(container)
					if err != nil {
						return nil, err
					}
					if containerDomain == nil {
						return seal.Open(r.deployment, container, aad)
					}
					if !bytes.Equal(containerDomain, binding) {
						return nil, seal.ErrDomain
					}
					return seal.OpenDomain(domainKey, container, aad, binding)
				}
			}
			cipher := newLeasedCipher(
				func(plaintext, aad []byte) ([]byte, error) {
					return seal.SealDomain(domainKey, plaintext, aad, binding)
				},
				open,
			)
			defer cipher.invalidate()
			return fn(cipher)
		},
	)
}

type domainAccessMode uint8

const (
	domainAccessDenied domainAccessMode = iota
	domainAccessTenantOnly
	domainAccessDualMigration
)

func resolveDomainAccessMode(tenantID string, domain store.TenantKeyDomain) (domainAccessMode, Status) {
	if domain.TenantID != tenantID ||
		domain.ProtectionMode != store.TenantKeyProtectionTenantDomain ||
		domain.DomainID == "" ||
		domain.Generation <= 0 {
		return domainAccessDenied, StatusCorrupt
	}
	if domain.WrapperKind == "" ||
		domain.WrapperID == "" ||
		len(domain.WrappedDomainKEK) == 0 {
		return domainAccessDenied, StatusCorrupt
	}

	switch domain.State {
	case store.TenantKeyDomainStateUnsealed:
		validCompletedOperation := domain.OperationStatus == store.TenantKeyOperationCompleted &&
			(domain.OperationKind == store.TenantKeyOperationMigrate ||
				domain.OperationKind == store.TenantKeyOperationUnseal)
		validExposure := domain.LegacyHistoryExposure == store.TenantKeyLegacyNone ||
			domain.LegacyHistoryExposure == store.TenantKeyLegacyExternalArchivesPossible
		if !validCompletedOperation || !validExposure {
			return domainAccessDenied, StatusCorrupt
		}
		return domainAccessTenantOnly, ""
	case store.TenantKeyDomainStatePartial:
		validProgress := domain.ProgressCompleted >= 0 &&
			domain.ProgressTotal >= 0 &&
			domain.ProgressCompleted <= domain.ProgressTotal
		completedHotMigration := domain.OperationKind == store.TenantKeyOperationMigrate &&
			domain.OperationStatus == store.TenantKeyOperationCompleted &&
			validProgress &&
			domain.ProgressCompleted == domain.ProgressTotal &&
			domain.LegacyHistoryExposure == store.TenantKeyLegacyExternalArchivesPossible
		if completedHotMigration {
			return domainAccessTenantOnly, ""
		}
		retryableMigration := domain.OperationKind == store.TenantKeyOperationMigrate &&
			(domain.OperationStatus == store.TenantKeyOperationRunning ||
				domain.OperationStatus == store.TenantKeyOperationFailed) &&
			validProgress &&
			knownLegacyExposure(domain.LegacyHistoryExposure)
		if retryableMigration {
			return domainAccessDualMigration, ""
		}
		return domainAccessDenied, StatusPartial
	case store.TenantKeyDomainStateMigrating:
		validProgress := domain.ProgressCompleted >= 0 &&
			domain.ProgressTotal >= 0 &&
			domain.ProgressCompleted <= domain.ProgressTotal
		activeMigration := domain.OperationKind == store.TenantKeyOperationMigrate &&
			(domain.OperationStatus == store.TenantKeyOperationPending ||
				domain.OperationStatus == store.TenantKeyOperationRunning) &&
			validProgress &&
			knownLegacyExposure(domain.LegacyHistoryExposure)
		if activeMigration {
			return domainAccessDualMigration, ""
		}
		return domainAccessDenied, StatusMigrating
	case store.TenantKeyDomainStateSealQueued:
		queuedSeal := domain.OperationID != nil && *domain.OperationID != "" &&
			domain.OperationKind == store.TenantKeyOperationSeal &&
			domain.OperationStatus == store.TenantKeyOperationPending &&
			knownLegacyExposure(domain.LegacyHistoryExposure)
		if queuedSeal {
			// The request is durable, but the worker has not yet proven the
			// idempotency-result completion wall. Crypto remains available and
			// the worker later acquires the exclusive fence before committing
			// sealed, so this state never pretends the seal already happened.
			return domainAccessTenantOnly, ""
		}
		return domainAccessDenied, StatusSealQueued
	case store.TenantKeyDomainStateSealing:
		return domainAccessDenied, StatusSealing
	case store.TenantKeyDomainStateSealed:
		return domainAccessDenied, StatusSealed
	case store.TenantKeyDomainStateUnsealing:
		return domainAccessDenied, StatusUnsealing
	case store.TenantKeyDomainStateWrapperUnavailable:
		return domainAccessDenied, StatusWrapperUnavailable
	case store.TenantKeyDomainStateWrongWrapper:
		return domainAccessDenied, StatusWrongWrapper
	case store.TenantKeyDomainStateCorrupt:
		return domainAccessDenied, StatusCorrupt
	default:
		return domainAccessDenied, StatusCorrupt
	}
}

func knownLegacyExposure(exposure string) bool {
	switch exposure {
	case store.TenantKeyLegacyNone,
		store.TenantKeyLegacyHotHistoryPending,
		store.TenantKeyLegacyExternalArchivesPossible:
		return true
	default:
		return false
	}
}

func classifyDomainOpenError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, ErrWrapperNotConfigured),
		errors.Is(err, tenantwrap.ErrUnavailable),
		errors.Is(err, tenantwrap.ErrInvalidWrapperKey):
		return statusError(StatusWrapperUnavailable, err)
	case errors.Is(err, tenantwrap.ErrCorrupt),
		errors.Is(err, tenantwrap.ErrDomainBinding):
		return statusError(StatusCorrupt, err)
	case errors.Is(err, tenantwrap.ErrUnwrap):
		return statusError(StatusUnwrapFailed, err)
	case errors.Is(err, tenantwrap.ErrCustody):
		return statusError(StatusCustodyUnavailable, err)
	default:
		return statusError(StatusCustodyUnavailable, err)
	}
}

// DomainBinding is the canonical, non-secret identity used both to authenticate
// a wrapped domain KEK and as the v2 sealed-container domain. It binds tenant,
// domain UUID, and generation without consulting AAD or ciphertext.
func DomainBinding(tenantID, domainID string, generation int64) ([]byte, error) {
	if tenantID == "" ||
		domainID == "" ||
		strings.TrimSpace(tenantID) != tenantID ||
		strings.TrimSpace(domainID) != domainID ||
		strings.ContainsAny(tenantID, ";\x00") ||
		strings.ContainsAny(domainID, ";\x00") ||
		generation <= 0 {
		return nil, errors.New("tenantseal: tenant, domain, and positive generation are required")
	}
	out := make([]byte, 0, len(tenantID)+len(domainID)+40)
	out = append(out, "tenant="...)
	out = append(out, tenantID...)
	out = append(out, ";domain="...)
	out = append(out, domainID...)
	out = append(out, ";generation="...)
	out = strconv.AppendInt(out, generation, 10)
	return out, nil
}

type cipherFunc func(value, aad []byte) ([]byte, error)

type leasedCipher struct {
	mu     sync.Mutex
	active bool
	seal   cipherFunc
	open   cipherFunc
}

func newLeasedCipher(sealFn, openFn cipherFunc) *leasedCipher {
	return &leasedCipher{active: true, seal: sealFn, open: openFn}
}

func (c *leasedCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return nil, ErrCipherLeaseExpired
	}
	return c.seal(plaintext, aad)
}

func (c *leasedCipher) Open(container, aad []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return nil, ErrCipherLeaseExpired
	}
	return c.open(container, aad)
}

func (c *leasedCipher) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
	c.seal = nil
	c.open = nil
}
