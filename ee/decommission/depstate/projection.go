// SPDX-License-Identifier: LicenseRef-trstctl-EE

package depstate

import (
	"fmt"

	"trstctl.com/trstctl/internal/eventspec"
)

type KeyState struct {
	KeyID             string
	TenantID          string
	Registered        []Dependent
	Accounted         []Dependent
	Released          []Dependent
	ErasureDesignated []Dependent
	LedgerPosition    uint64
}

func (s KeyState) Unaccounted() []Dependent {
	accounted := make(map[string]struct{}, len(s.Accounted)+len(s.Released)+len(s.ErasureDesignated))
	for _, dep := range s.Accounted {
		accounted[dep.key()] = struct{}{}
	}
	for _, dep := range s.Released {
		accounted[dep.key()] = struct{}{}
	}
	for _, dep := range s.ErasureDesignated {
		accounted[dep.key()] = struct{}{}
	}
	out := make([]Dependent, 0)
	for _, dep := range s.Registered {
		if _, ok := accounted[dep.key()]; !ok {
			out = append(out, dep)
		}
	}
	return out
}

type ProjectionKey struct {
	TenantID string
	KeyID    string
}

type Projection map[ProjectionKey]KeyState

func (p Projection) Lookup(tenantID, keyID string) (KeyState, bool) {
	state, ok := p[ProjectionKey{TenantID: tenantID, KeyID: keyID}]
	return state, ok
}

type keyBuilder struct {
	state KeyState

	registered map[string]struct{}
	accounted  map[string]struct{}
	released   map[string]struct{}
	erased     map[string]struct{}
}

func newKeyBuilder(tenantID, keyID string) *keyBuilder {
	return &keyBuilder{
		state:      KeyState{KeyID: keyID, TenantID: tenantID},
		registered: make(map[string]struct{}),
		accounted:  make(map[string]struct{}),
		released:   make(map[string]struct{}),
		erased:     make(map[string]struct{}),
	}
}

func (b *keyBuilder) advance(pos uint64) {
	if pos > b.state.LedgerPosition {
		b.state.LedgerPosition = pos
	}
}

func (b *keyBuilder) register(dep Dependent) {
	appendUnique(b.registered, &b.state.Registered, dep)
}

func (b *keyBuilder) account(dep Dependent) {
	appendUnique(b.accounted, &b.state.Accounted, dep)
}

func (b *keyBuilder) release(dep Dependent) {
	if appendUnique(b.released, &b.state.Released, dep) {
		b.account(dep)
	}
}

func (b *keyBuilder) erase(dep Dependent) {
	b.register(dep)
	if appendUnique(b.erased, &b.state.ErasureDesignated, dep) {
		b.account(dep)
	}
}

func appendUnique(set map[string]struct{}, dst *[]Dependent, dep Dependent) bool {
	k := dep.key()
	if _, ok := set[k]; ok {
		return false
	}
	set[k] = struct{}{}
	*dst = append(*dst, dep)
	return true
}

func (b *keyBuilder) snapshot() KeyState {
	out := b.state
	out.Registered = append([]Dependent(nil), b.state.Registered...)
	out.Accounted = append([]Dependent(nil), b.state.Accounted...)
	out.Released = append([]Dependent(nil), b.state.Released...)
	out.ErasureDesignated = append([]Dependent(nil), b.state.ErasureDesignated...)
	return out
}

func Fold(seq []eventspec.Event) (Projection, error) {
	builders := make(map[ProjectionKey]*keyBuilder)
	for i, e := range seq {
		payload, err := Decode(e)
		if err != nil {
			return nil, fmt.Errorf("depstate: fold event %d (%s): %w", i, e.Type, err)
		}
		c, ok := payloadChange(payload)
		if !ok {
			continue
		}
		b := builderFor(builders, c.tenantID, c.keyID)
		b.apply(c.op, c.dependent)
		b.advance(ledgerPosition(e, i))
	}
	out := make(Projection, len(builders))
	for key, b := range builders {
		out[key] = b.snapshot()
	}
	return out, nil
}

type change struct {
	tenantID, keyID string
	dependent       Dependent
	op              byte
}

const (
	opRegister byte = iota
	opRelease
	opErase
	opAccount
)

func payloadChange(p Payload) (change, bool) {
	switch v := p.(type) {
	case DependencyRegisteredV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opRegister}, true
	case DependencyReleasedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opRelease}, true
	case DependencyErasureDesignatedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opErase}, true
	case ReprotectionCompletedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opAccount}, true
	case RevocationCompletedV1:
		return change{v.TenantID, v.KeyID, v.Dependent, opAccount}, true
	default:
		return change{}, false
	}
}

func (b *keyBuilder) apply(op byte, dep Dependent) {
	switch op {
	case opRegister:
		b.register(dep)
	case opRelease:
		b.release(dep)
	case opErase:
		b.erase(dep)
	case opAccount:
		b.account(dep)
	}
}

func builderFor(builders map[ProjectionKey]*keyBuilder, tenantID, keyID string) *keyBuilder {
	key := ProjectionKey{TenantID: tenantID, KeyID: keyID}
	if b, ok := builders[key]; ok {
		return b
	}
	b := newKeyBuilder(tenantID, keyID)
	builders[key] = b
	return b
}

func ledgerPosition(e eventspec.Event, index int) uint64 {
	if e.Sequence != 0 {
		return e.Sequence
	}
	return uint64(index + 1)
}
