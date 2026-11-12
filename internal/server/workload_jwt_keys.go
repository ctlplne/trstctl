// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// N5-L3: the workload JWT signing key rotates without breaking a verifier
// that caches the key set. A rotation creates the next generation's key in the
// signer and publishes it at once; it signs from its activation time, so a
// cloud that refreshes its cached key set before then already holds it; the
// key it replaces stays published for the retain window after that, so every
// token signed before the switch keeps verifying until it expires and a cache
// fetched before the switch keeps working.

// Workload JWT key states.
const (
	workloadJWTKeyActive   = "active"
	workloadJWTKeyNext     = "next"
	workloadJWTKeyRetiring = "retiring"
	workloadJWTKeyRetired  = "retired"
)

// Rotation windows: how far ahead the next key is published, and how long the
// key it replaces stays published after the switch.
const (
	defaultWorkloadJWTKeyPublishAhead = 24 * time.Hour
	defaultWorkloadJWTKeyRetain       = 24 * time.Hour
	minWorkloadJWTKeyRetain           = time.Hour
	maxWorkloadJWTKeyWindow           = 30 * 24 * time.Hour
	// workloadJWTKeyRefresh is how stale another replica's view of the
	// rotations may get: a rotation publishes its key ahead of signing with
	// it, so the lag only delays publication by this much.
	workloadJWTKeyRefresh = 10 * time.Second
)

// workloadJWTKeyHandle is the signer handle of a generation's key; the first
// generation is the handle the SPIFFE protocol has always used.
func workloadJWTKeyHandle(generation int) string {
	if generation <= 1 {
		return spiffeJWTHandle
	}
	return spiffeJWTHandle + "-g" + strconv.Itoa(generation)
}

// workloadJWTKeyState is one generation of the workload JWT key as of a time.
type workloadJWTKeyState struct {
	Generation  int
	KeyID       string
	State       string
	PublishedAt *time.Time
	ActivatesAt *time.Time
	RetiresAt   *time.Time
}

// published reports whether verifiers are offered the key.
func (k workloadJWTKeyState) published() bool { return k.State != workloadJWTKeyRetired }

// workloadJWTKeySchedule derives every generation's state at now from the
// recorded rotations: the newest generation whose activation has come signs,
// a later one is the next key (published, not yet signing), and an earlier one
// is retiring until its successor's retain window ends, then retired.
func workloadJWTKeySchedule(rotations []store.WorkloadJWTKeyRotation, now time.Time) []workloadJWTKeyState {
	keys := make([]workloadJWTKeyState, 0, len(rotations)+1)
	keys = append(keys, workloadJWTKeyState{Generation: 1, KeyID: projections.WorkloadJWTKeyID(1)})
	for _, r := range rotations {
		published, activates, retires := r.PublishedAt, r.ActivatesAt, r.PreviousRetiresAt
		keys[len(keys)-1].RetiresAt = &retires
		keys = append(keys, workloadJWTKeyState{Generation: r.Generation, KeyID: r.KeyID, PublishedAt: &published, ActivatesAt: &activates})
	}
	active := 0
	for i, k := range keys {
		if k.ActivatesAt == nil || !now.Before(*k.ActivatesAt) {
			active = i
		}
	}
	for i := range keys {
		switch {
		case i == active:
			keys[i].State = workloadJWTKeyActive
		case i > active:
			keys[i].State = workloadJWTKeyNext
		case keys[i].RetiresAt != nil && now.Before(*keys[i].RetiresAt):
			keys[i].State = workloadJWTKeyRetiring
		default:
			keys[i].State = workloadJWTKeyRetired
		}
	}
	return keys
}

// workloadJWTKeyRing resolves the SPIFFE issuer's JWT keys from the recorded
// rotations: it backs spiffe.CAIssuer.JWTKeys.
type workloadJWTKeyRing struct {
	srv      *Server
	client   *signing.Client
	tenantID string
	first    crypto.DigestSigner
	// algorithm is what a rotation's new key is created as (OD-6).
	algorithm crypto.Algorithm
	now       func() time.Time

	mu        sync.Mutex
	signers   map[int]crypto.DigestSigner
	rotations []store.WorkloadJWTKeyRotation
	loadedAt  time.Time
}

func newWorkloadJWTKeyRing(s *Server, c *signing.Client, tenantID string, first crypto.DigestSigner, algorithm crypto.Algorithm) *workloadJWTKeyRing {
	return &workloadJWTKeyRing{srv: s, client: c, tenantID: tenantID, first: first, algorithm: algorithm, now: time.Now,
		signers: map[int]crypto.DigestSigner{1: first}}
}

// schedule is every generation's state now, from rotations read at most
// workloadJWTKeyRefresh ago. A read that fails after an earlier one succeeded
// keeps the last rotations it read.
func (k *workloadJWTKeyRing) schedule(ctx context.Context) ([]workloadJWTKeyState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.loadedAt.IsZero() || time.Since(k.loadedAt) >= workloadJWTKeyRefresh {
		rotations, err := k.srv.store.WorkloadJWTKeyRotations(ctx, k.tenantID)
		switch {
		case err == nil:
			k.rotations, k.loadedAt = rotations, time.Now()
		case k.loadedAt.IsZero():
			return nil, fmt.Errorf("read the workload JWT key rotations: %w", err)
		}
	}
	return workloadJWTKeySchedule(k.rotations, k.now()), nil
}

// clock is the ring's time; a test moves it to cross a rotation's windows.
func (k *workloadJWTKeyRing) clock() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.now()
}

// setClock replaces the ring's time source.
func (k *workloadJWTKeyRing) setClock(now func() time.Time) {
	k.mu.Lock()
	k.now = now
	k.mu.Unlock()
}

// invalidate makes the next schedule read the rotations again.
func (k *workloadJWTKeyRing) invalidate() {
	k.mu.Lock()
	k.loadedAt = time.Time{}
	k.mu.Unlock()
}

// signer is a generation's key in the signer (AN-4).
func (k *workloadJWTKeyRing) signer(ctx context.Context, generation int) (crypto.DigestSigner, error) {
	k.mu.Lock()
	cached, ok := k.signers[generation]
	k.mu.Unlock()
	if ok {
		return cached, nil
	}
	remote, err := k.srv.signerForPrivilegedHandle(ctx, k.client, workloadJWTKeyHandle(generation), signing.PurposeGeneric)
	if err != nil {
		return nil, fmt.Errorf("the signer has no key for workload JWT key generation %d: %w", generation, err)
	}
	k.mu.Lock()
	k.signers[generation] = remote
	k.mu.Unlock()
	return remote, nil
}

// ensureSigner returns a generation's key, creating it in the signer when it
// is not there yet (a rotation retried after a crash finds the one it made).
func (k *workloadJWTKeyRing) ensureSigner(ctx context.Context, generation int) error {
	if _, err := k.signer(ctx, generation); err == nil {
		return nil
	}
	remote, err := k.srv.generatePrivilegedKeyHandle(ctx, k.client, k.algorithm, workloadJWTKeyHandle(generation),
		[]signing.KeyPurpose{signing.PurposeGeneric}, signing.PurposeGeneric)
	if err != nil {
		return fmt.Errorf("create workload JWT key generation %d in the signer: %w", generation, err)
	}
	k.mu.Lock()
	k.signers[generation] = remote
	k.mu.Unlock()
	return nil
}

// keys implements spiffe.CAIssuer.JWTKeys: the active key signs, and every
// published key is in the bundle.
func (k *workloadJWTKeyRing) keys(ctx context.Context) (spiffe.JWTKey, []spiffe.JWTKey, error) {
	states, err := k.schedule(ctx)
	if err != nil {
		return spiffe.JWTKey{}, nil, err
	}
	var active spiffe.JWTKey
	published := make([]spiffe.JWTKey, 0, len(states))
	for _, state := range states {
		if !state.published() {
			continue
		}
		signer, err := k.signer(ctx, state.Generation)
		if err != nil {
			return spiffe.JWTKey{}, nil, err
		}
		key := spiffe.JWTKey{Signer: signer, KeyID: state.KeyID}
		published = append(published, key)
		if state.State == workloadJWTKeyActive {
			active = key
		}
	}
	return active, published, nil
}

// WorkloadJWTPublicKeysFor hands out the public halves of the tenant's
// published workload JWT keys (A205-L2), so the SPIRE upstream authority's
// shared key set carries trstctl's own SPIFFE JWT authority. served is false
// when the SPIFFE protocol does not serve the tenant.
func (s *Server) WorkloadJWTPublicKeysFor(ctx context.Context, tenantID string) ([]api.WorkloadJWTPublicKey, bool, error) {
	ring := s.workloadJWTKeyRingFor(tenantID)
	if ring == nil {
		return nil, false, nil
	}
	states, err := ring.schedule(ctx)
	if err != nil {
		return nil, true, err
	}
	out := make([]api.WorkloadJWTPublicKey, 0, len(states))
	for _, state := range states {
		if !state.published() {
			continue
		}
		signer, err := ring.signer(ctx, state.Generation)
		if err != nil {
			return nil, true, err
		}
		out = append(out, api.WorkloadJWTPublicKey{
			KeyID: state.KeyID, PublicKeyDER: append([]byte(nil), signer.Public().DER...),
			PublishedAt: state.PublishedAt, RetiresAt: state.RetiresAt,
		})
	}
	return out, true, nil
}

// WorkloadJWTKeysFor reports the tenant's workload JWT key generations for
// the API; served is false when the SPIFFE protocol does not serve the tenant.
func (s *Server) WorkloadJWTKeysFor(ctx context.Context, tenantID string) ([]api.WorkloadJWTKey, bool, error) {
	ring := s.workloadJWTKeyRingFor(tenantID)
	if ring == nil {
		return nil, false, nil
	}
	states, err := ring.schedule(ctx)
	if err != nil {
		return nil, true, err
	}
	return workloadJWTKeysView(states), true, nil
}

func workloadJWTKeysView(states []workloadJWTKeyState) []api.WorkloadJWTKey {
	out := make([]api.WorkloadJWTKey, 0, len(states))
	for _, state := range states {
		out = append(out, api.WorkloadJWTKey{
			KeyID: state.KeyID, Generation: state.Generation, State: state.State,
			PublishedAt: state.PublishedAt, ActivatesAt: state.ActivatesAt, RetiresAt: state.RetiresAt,
		})
	}
	return out
}

// workloadJWTKeyRingFor is the tenant's key ring, or nil when the SPIFFE
// protocol does not serve the tenant.
func (s *Server) workloadJWTKeyRingFor(tenantID string) *workloadJWTKeyRing {
	sp := s.spiffeForExchange()
	if sp == nil || sp.jwtKeys == nil || tenantID != sp.tenantID {
		return nil
	}
	return sp.jwtKeys
}

// RotateWorkloadJWTKey starts the next generation of the workload JWT key for
// the API (N5-L3): the key is created in the signer and published now, signs
// after publishAhead, and the key it replaces stays published for retain
// after that. A rotation still waiting for its activation is refused.
func (s *Server) RotateWorkloadJWTKey(ctx context.Context, tenantID string, publishAhead, retain time.Duration) ([]api.WorkloadJWTKey, error) {
	ring := s.workloadJWTKeyRingFor(tenantID)
	if ring == nil || s.orch == nil || s.store == nil {
		return nil, api.ErrStatus(http.StatusNotFound,
			"the workload JWT key belongs to the SPIFFE protocol's tenant (protocols.spiffe.tenant_id)")
	}
	switch {
	case publishAhead < 0 || publishAhead > maxWorkloadJWTKeyWindow:
		return nil, api.ErrStatus(http.StatusBadRequest, "publish_ahead_seconds must be between 0 and 30 days")
	case retain < minWorkloadJWTKeyRetain || retain > maxWorkloadJWTKeyWindow:
		return nil, api.ErrStatus(http.StatusBadRequest,
			"retain_seconds must be between 1 hour and 30 days: longer than the key's tokens live and than the clouds cache the key set")
	}
	err := s.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		ring.invalidate()
		states, err := ring.schedule(ctx)
		if err != nil {
			return err
		}
		last := states[len(states)-1]
		if last.State == workloadJWTKeyNext {
			return api.ErrStatus(http.StatusConflict, fmt.Sprintf(
				"key %s is published and signs from %s; rotate again after that", last.KeyID, last.ActivatesAt.UTC().Format(time.RFC3339)))
		}
		generation := last.Generation + 1
		if err := ring.ensureSigner(ctx, generation); err != nil {
			return err
		}
		now := ring.clock().UTC().Truncate(time.Second)
		activates := now.Add(publishAhead)
		return s.orch.RotateWorkloadJWTKey(ctx, tenantID, generation, now, activates, activates.Add(retain))
	})
	ring.invalidate()
	if err != nil {
		return nil, err
	}
	states, err := ring.schedule(ctx)
	if err != nil {
		return nil, err
	}
	return workloadJWTKeysView(states), nil
}
