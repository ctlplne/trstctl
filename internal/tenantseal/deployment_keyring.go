// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// ErrDeploymentGenerationNotLive means a data key names a deployment KEK
// generation that is neither current nor the next one: a retired generation,
// or one this process has not seen recorded.
var ErrDeploymentGenerationNotLive = errors.New("tenantseal: the data key's deployment KEK generation is not current")

// deploymentKeyringRefresh bounds how long a direct (unfenced) use of the
// keyring may act on the deployment KEK state it last read.
const deploymentKeyringRefresh = 2 * time.Second

// deploymentDEKSize is the only data-key size the deployment KEK wraps: every
// caller seals through internal/crypto/seal containers.
const deploymentDEKSize = 32

// DeploymentKEKSource reads the deployment KEK state.
type DeploymentKEKSource interface {
	DeploymentKEKDomain(ctx context.Context) (store.DeploymentKEKDomain, bool, error)
}

// DeploymentKeyring is the deployment KEK (A198): generation 0 is the local
// key file (secrets.kek_file); a served rotation moves it to generation n >= 1,
// a key created and held under an operator wrapper (a local wrapper file, or an
// HSM key the isolated signer holds), of which only the wrapped form is
// persisted. A data key wrapped under a later generation carries it
// (seal.TagGeneration), so every unwrap goes to exactly one generation, and a
// retired generation unwraps nothing. It replaces the local key everywhere the
// control plane held it.
//
// Tenant data reaches it through a View bound to the state read inside the
// tenant's key-domain fence. A direct call (deployment-scoped files) uses the
// state it read at most deploymentKeyringRefresh ago and re-reads it once when
// a data key names a generation it does not know.
type DeploymentKeyring struct {
	local    *seal.LocalKEK
	source   DeploymentKEKSource
	registry DomainKEKManager
	refresh  time.Duration
	now      func() time.Time

	mu       sync.Mutex
	state    *store.DeploymentKEKDomain
	loaded   bool
	loadedAt time.Time
}

var _ seal.KeyWrapper = (*DeploymentKeyring)(nil)

// NewDeploymentKeyring wraps the deployment key file. A nil source keeps the
// keyring at generation 0 (no database); a nil registry refuses every later
// generation.
func NewDeploymentKeyring(local *seal.LocalKEK, source DeploymentKEKSource, registry DomainKEKManager) (*DeploymentKeyring, error) {
	if local == nil {
		return nil, errors.New("tenantseal: the deployment key file is required")
	}
	return &DeploymentKeyring{
		local: local, source: source, registry: registry,
		refresh: deploymentKeyringRefresh, now: time.Now,
	}, nil
}

// KeyedDigest computes request and review evidence MACs under the deployment
// key file. It is not a wrapping key, so it stays stable across rotations.
func (k *DeploymentKeyring) KeyedDigest(domain, material []byte) ([]byte, error) {
	return k.local.KeyedDigest(domain, material)
}

// WrapDEK wraps under the generation new data is written to.
func (k *DeploymentKeyring) WrapDEK(dek []byte) ([]byte, error) {
	state, err := k.current(false)
	if err != nil {
		return nil, err
	}
	view := k.View(state)
	defer view.Destroy()
	return view.WrapDEK(dek)
}

// UnwrapDEK unwraps under the generation the data key names.
func (k *DeploymentKeyring) UnwrapDEK(wrapped []byte) ([]byte, error) {
	state, err := k.current(false)
	if err != nil {
		return nil, err
	}
	view := k.View(state)
	dek, err := view.UnwrapDEK(wrapped)
	view.Destroy()
	if !errors.Is(err, ErrDeploymentGenerationNotLive) || k.source == nil {
		return dek, err
	}
	if state, err = k.current(true); err != nil {
		return nil, err
	}
	view = k.View(state)
	defer view.Destroy()
	return view.UnwrapDEK(wrapped)
}

// Observe records a state this process just committed, so its own direct uses
// do not wait for the next read.
func (k *DeploymentKeyring) Observe(d store.DeploymentKEKDomain) {
	if k == nil || k.source == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	copied := copyDeploymentState(d)
	k.state, k.loaded, k.loadedAt = &copied, true, k.now()
}

func (k *DeploymentKeyring) current(force bool) (*store.DeploymentKEKDomain, error) {
	if k.source == nil {
		return nil, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !force && k.loaded && k.now().Sub(k.loadedAt) < k.refresh {
		return k.state, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, found, err := k.source.DeploymentKEKDomain(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenantseal: read the deployment KEK state: %w", err)
	}
	k.state = nil
	if found {
		copied := copyDeploymentState(d)
		k.state = &copied
	}
	k.loaded, k.loadedAt = true, k.now()
	return k.state, nil
}

func copyDeploymentState(d store.DeploymentKEKDomain) store.DeploymentKEKDomain {
	d.WrappedKEK = append([]byte(nil), d.WrappedKEK...)
	d.NextWrappedKEK = append([]byte(nil), d.NextWrappedKEK...)
	return d
}

// View is the deployment KEK exactly as one state describes it: nil for a
// deployment KEK that has never rotated. Generation keys it opens stay open
// until Destroy.
func (k *DeploymentKeyring) View(state *store.DeploymentKEKDomain) *DeploymentView {
	return &DeploymentView{ring: k, state: state, opened: map[int64]TransientDomainKEK{}}
}

// DeploymentView is one state of the deployment KEK, as a seal.KeyWrapper.
type DeploymentView struct {
	ring  *DeploymentKeyring
	state *store.DeploymentKEKDomain

	mu        sync.Mutex
	opened    map[int64]TransientDomainKEK
	destroyed bool
}

var _ seal.KeyWrapper = (*DeploymentView)(nil)

// WritingGeneration is the generation new data is wrapped under: the next one
// from the moment a rotation records it.
func (v *DeploymentView) WritingGeneration() int64 {
	switch {
	case v.state == nil:
		return 0
	case v.state.Rotating():
		return v.state.NextGeneration
	default:
		return v.state.Generation
	}
}

// live reports whether this state still unwraps a generation: the current one
// and, during a rotation, the next. Generation 0 (the key file) is current
// until the first rotation completes.
func (v *DeploymentView) live(generation int64) bool {
	current := int64(0)
	if v.state != nil {
		current = v.state.Generation
	}
	return generation == current || (v.state != nil && v.state.Rotating() && generation == v.state.NextGeneration)
}

// WrapDEK wraps a data key under the writing generation.
func (v *DeploymentView) WrapDEK(dek []byte) ([]byte, error) {
	if len(dek) != deploymentDEKSize {
		return nil, errors.New("tenantseal: the deployment KEK wraps 32-byte data keys only")
	}
	generation := v.WritingGeneration()
	if generation == 0 {
		return v.ring.local.WrapDEK(dek)
	}
	key, err := v.open(generation)
	if err != nil {
		return nil, err
	}
	inner, err := key.WrapDEK(dek)
	if err != nil {
		return nil, err
	}
	return seal.TagGeneration(uint32(generation), inner) // #nosec G115 -- a generation is a small positive counter checked by the table (CWE-190)
}

// UnwrapDEK unwraps a data key under the generation it names, if this state
// still holds it.
func (v *DeploymentView) UnwrapDEK(wrapped []byte) ([]byte, error) {
	generation, inner, err := seal.WrappedGeneration(wrapped)
	if err != nil {
		return nil, seal.ErrDecrypt
	}
	if !v.live(int64(generation)) {
		return nil, fmt.Errorf("%w: generation %d", ErrDeploymentGenerationNotLive, generation)
	}
	if generation == 0 {
		return v.ring.local.UnwrapDEK(inner)
	}
	key, err := v.open(int64(generation))
	if err != nil {
		return nil, err
	}
	return key.UnwrapDEK(inner)
}

// Rewrap moves one wrapped data key to the writing generation; a key already
// there is left as is. The data key is wiped before return.
func (v *DeploymentView) Rewrap(wrapped []byte) ([]byte, bool, error) {
	generation, _, err := seal.WrappedGeneration(wrapped)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrCorruptContainer, err)
	}
	if int64(generation) == v.WritingGeneration() {
		return wrapped, false, nil
	}
	dek, err := v.UnwrapDEK(wrapped)
	if err != nil {
		return nil, false, err
	}
	defer secret.Wipe(dek)
	next, err := v.WrapDEK(dek)
	if err != nil {
		return nil, false, err
	}
	return next, true, nil
}

// Destroy releases every generation key the view opened and refuses later use.
func (v *DeploymentView) Destroy() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for generation, key := range v.opened {
		key.Destroy()
		delete(v.opened, generation)
	}
	v.destroyed = true
}

func (v *DeploymentView) open(generation int64) (TransientDomainKEK, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.destroyed {
		return nil, errors.New("tenantseal: the deployment KEK view was released")
	}
	if key, ok := v.opened[generation]; ok {
		return key, nil
	}
	state := v.state
	if state == nil || generation <= 0 {
		return nil, fmt.Errorf("%w: generation %d", ErrDeploymentGenerationNotLive, generation)
	}
	ref, wrapped := WrapperRef{Kind: state.WrapperKind, ID: state.WrapperID}, state.WrappedKEK
	if state.Rotating() && generation == state.NextGeneration {
		ref, wrapped = WrapperRef{Kind: state.NextWrapperKind, ID: state.NextWrapperID}, state.NextWrappedKEK
	} else if generation != state.Generation {
		return nil, fmt.Errorf("%w: generation %d", ErrDeploymentGenerationNotLive, generation)
	}
	if v.ring.registry == nil {
		return nil, fmt.Errorf("%w: no wrapper registry holds the deployment KEK", ErrWrapperNotConfigured)
	}
	binding, err := DeploymentBinding(state.DomainID, generation)
	if err != nil {
		return nil, err
	}
	// The signer-backed handle keeps this context for its wrap and unwrap
	// calls; each call has the signer's own call deadline.
	key, err := v.ring.registry.OpenDomainKEK(context.Background(), ref, wrapped, binding)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("%w: the wrapper registry returned no key", ErrWrapperNotConfigured)
	}
	v.opened[generation] = key
	return key, nil
}

// DeploymentBinding is the authenticated binding of one deployment KEK
// generation's wrapped key. A tenant domain's binding starts "tenant=", so the
// two can never be confused.
func DeploymentBinding(domainID string, generation int64) ([]byte, error) {
	if domainID == "" || strings.TrimSpace(domainID) != domainID ||
		strings.ContainsAny(domainID, ";\x00") || generation <= 0 {
		return nil, errors.New("tenantseal: deployment domain and positive generation are required")
	}
	out := make([]byte, 0, len(domainID)+48)
	out = append(out, "deployment-kek;domain="...)
	out = append(out, domainID...)
	out = append(out, ";generation="...)
	return strconv.AppendInt(out, generation, 10), nil
}
