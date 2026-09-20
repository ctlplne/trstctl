// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"errors"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/succession"
)

// highwater.go hardens the per-identity epoch floor beyond PCAS-05's restart
// persistence so that "the floor cannot regress" holds under OPERATIONAL failure —
// backup/restore, HA fail-over, and control-plane replay — not just runtime
// compromise (PCAS-claim-21, completes INV-3; load-bearing for independent PCAS-claim-12).
//
// Three backings, composable:
//   - a hardware MonotonicCounter (TPM/HSM) whose value survives a restore of the
//     signer's sealed map and cannot be regressed by it;
//   - a signer quorum: an epoch advance becomes durable only once a quorum of signer
//     instances acknowledges it;
//   - push-based reconcile: on restart/restore the control plane PRESENTS the newest
//     signed epoch checkpoint (PCAS-13 format); the signer cryptographically verifies
//     it, adopts max(sealed, counter, verified-presented), and never lowers.
//
// r11 rules honored: reconciliation is push-based (the signer opens no connection to
// control-plane stores — it only accepts presentations); the adopted value is always
// the max of the verified inputs; and loss of state degrades AVAILABILITY (an
// identity fails closed until reconciled), never MONOTONICITY.

// Errors.
var (
	ErrRegress              = errors.New("high-water: refusing to lower the epoch floor")
	ErrCheckpointUnverified = errors.New("high-water: presented checkpoint failed cryptographic verification")
	ErrNoCheckpointKey      = errors.New("high-water: no checkpoint trust anchor configured; cannot verify a presentation")
	ErrStalePresentation    = errors.New("high-water: presented checkpoint is older than the configured freshness bound")
	ErrNotReconciled        = errors.New("high-water: identity is unreconciled after restore; minting is fail-closed")
)

// MonotonicCounter is an external hardware monotonic counter (TPM/HSM). Its value is
// NOT part of the signer's sealed state, so restoring that state from an earlier
// backup cannot regress it.
type MonotonicCounter interface {
	// Value returns the current counter value for slot (0 if never bumped).
	Value(slot string) (uint64, error)
	// Bump advances slot to at least v and returns the resulting value; it never
	// lowers.
	Bump(slot string, v uint64) (uint64, error)
}

// HighWater is the hardened per-identity epoch floor.
type HighWater struct {
	mu     sync.Mutex
	sealed map[string]uint64

	counter          MonotonicCounter
	checkpointKeyDER []byte
	freshness        int64 // presentations older than this (in the caller's time unit) don't reconcile; 0 disables
	quorumSize       int

	needsReconcile map[string]bool
	acks           map[string]map[string]bool // "identity@epoch" -> instance -> true
}

// HWOption configures a HighWater.
type HWOption func(*HighWater)

// WithMonotonicCounter backs the floor with a hardware monotonic counter.
func WithMonotonicCounter(c MonotonicCounter) HWOption { return func(h *HighWater) { h.counter = c } }

// WithCheckpointKey sets the trust anchor used to verify presented checkpoints.
func WithCheckpointKey(pubDER []byte) HWOption {
	return func(h *HighWater) { h.checkpointKeyDER = append([]byte(nil), pubDER...) }
}

// WithFreshnessBound sets the reconcile freshness bound: a presentation whose
// (now - IssuedAt) exceeds bound does not clear an identity's fail-closed state.
func WithFreshnessBound(bound int64) HWOption { return func(h *HighWater) { h.freshness = bound } }

// WithQuorum requires size acknowledgements for an epoch advance to become durable.
func WithQuorum(size int) HWOption { return func(h *HighWater) { h.quorumSize = size } }

// NewHighWater builds a HighWater over a sealed floor map (as loaded from PCAS-05's
// durable store, possibly from an old backup).
func NewHighWater(sealed map[string]uint64, opts ...HWOption) *HighWater {
	cp := map[string]uint64{}
	for k, v := range sealed {
		cp[k] = v
	}
	h := &HighWater{
		sealed:         cp,
		needsReconcile: map[string]bool{},
		acks:           map[string]map[string]bool{},
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Floor returns the current adopted epoch floor for identityID: the maximum of the
// sealed value and the hardware counter (if any). It never reflects a value below
// what was durably sealed or externally counted.
func (h *HighWater) Floor(identityID string) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.floorLocked(identityID)
}

func (h *HighWater) floorLocked(identityID string) (uint64, error) {
	f := h.sealed[identityID]
	if h.counter != nil {
		cv, err := h.counter.Value(identityID)
		if err != nil {
			return 0, fmt.Errorf("high-water: counter read: %w", err)
		}
		if cv > f {
			f = cv
		}
	}
	return f, nil
}

// Ready reports whether minting is permitted for identityID. An identity marked
// needing reconcile (after a restore/restart with suspect state) is NOT ready until a
// fresh, verified checkpoint is reconciled — fail closed (availability), never a
// regressed floor (monotonicity).
func (h *HighWater) Ready(identityID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.needsReconcile[identityID]
}

// MarkNeedsReconcile flags identities whose sealed value may be stale after a restore,
// so they fail closed until a fresh verified presentation reconciles them.
func (h *HighWater) MarkNeedsReconcile(identityIDs ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range identityIDs {
		h.needsReconcile[id] = true
	}
}

// SealAdvance durably advances the floor for identityID to epoch at mint time,
// bumping the hardware counter if present. It is monotonic: an epoch below the
// current floor is refused (ErrRegress). Advancing an unreconciled identity is
// refused (fail closed).
func (h *HighWater) SealAdvance(identityID string, epoch uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.needsReconcile[identityID] {
		return fmt.Errorf("%w: %q", ErrNotReconciled, identityID)
	}
	cur, err := h.floorLocked(identityID)
	if err != nil {
		return err
	}
	if epoch < cur {
		return fmt.Errorf("%w: %q epoch %d < floor %d", ErrRegress, identityID, epoch, cur)
	}
	return h.adoptLocked(identityID, epoch)
}

// AdoptPresented verifies a pushed checkpoint's signature and adopts
// max(floor, checkpoint epoch) for its identity — never lowering. It performs no
// freshness check and does not clear fail-closed state (use Reconcile for that); a
// stale-but-valid checkpoint therefore cannot lower the adopted value.
func (h *HighWater) AdoptPresented(cp succession.SignedEpochCheckpoint) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.verifyLocked(cp); err != nil {
		return err
	}
	cur, err := h.floorLocked(cp.IdentityID)
	if err != nil {
		return err
	}
	if cp.Epoch <= cur {
		return nil // never lowers; a stale replay is a no-op
	}
	return h.adoptLocked(cp.IdentityID, cp.Epoch)
}

// Reconcile verifies a pushed checkpoint and, if it is within the freshness bound,
// adopts max(floor, checkpoint epoch) and clears the identity's fail-closed state. A
// stale presentation still cannot lower the floor but does NOT reconcile (the
// identity stays fail closed): the control plane can withhold freshness but cannot
// fabricate or regress.
func (h *HighWater) Reconcile(cp succession.SignedEpochCheckpoint, now int64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.verifyLocked(cp); err != nil {
		return err
	}
	if h.freshness > 0 && now-cp.IssuedAt > h.freshness {
		return fmt.Errorf("%w: issued %d, now %d, bound %d", ErrStalePresentation, cp.IssuedAt, now, h.freshness)
	}
	cur, err := h.floorLocked(cp.IdentityID)
	if err != nil {
		return err
	}
	if cp.Epoch > cur {
		if err := h.adoptLocked(cp.IdentityID, cp.Epoch); err != nil {
			return err
		}
	}
	delete(h.needsReconcile, cp.IdentityID)
	return nil
}

// ProposeAdvance records an instance's acknowledgement of an epoch advance for
// identityID. The advance becomes durable (sealed) only once a quorum of DISTINCT
// instances has acknowledged it; it returns whether the advance is now durable. With
// no quorum configured (size <= 1) the first acknowledgement is durable.
func (h *HighWater) ProposeAdvance(identityID string, epoch uint64, instance string) (durable bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.needsReconcile[identityID] {
		return false, fmt.Errorf("%w: %q", ErrNotReconciled, identityID)
	}
	key := fmt.Sprintf("%s@%d", identityID, epoch)
	if h.acks[key] == nil {
		h.acks[key] = map[string]bool{}
	}
	h.acks[key][instance] = true
	need := h.quorumSize
	if need < 1 {
		need = 1
	}
	if len(h.acks[key]) < need {
		return false, nil
	}
	cur, err := h.floorLocked(identityID)
	if err != nil {
		return false, err
	}
	if epoch < cur {
		return false, fmt.Errorf("%w: %q epoch %d < floor %d", ErrRegress, identityID, epoch, cur)
	}
	if err := h.adoptLocked(identityID, epoch); err != nil {
		return false, err
	}
	delete(h.acks, key)
	return true, nil
}

// adoptLocked seals epoch for identityID and bumps the counter; monotonic.
func (h *HighWater) adoptLocked(identityID string, epoch uint64) error {
	if epoch > h.sealed[identityID] {
		h.sealed[identityID] = epoch
	}
	if h.counter != nil {
		if _, err := h.counter.Bump(identityID, epoch); err != nil {
			return fmt.Errorf("high-water: counter bump: %w", err)
		}
	}
	return nil
}

// verifyLocked cryptographically verifies a presented checkpoint against the trust
// anchor. A fabricated "newer" checkpoint with bad signatures is rejected.
func (h *HighWater) verifyLocked(cp succession.SignedEpochCheckpoint) error {
	if len(h.checkpointKeyDER) == 0 {
		return ErrNoCheckpointKey
	}
	if err := succession.VerifyEpochCheckpoint(h.checkpointKeyDER, cp); err != nil {
		return fmt.Errorf("%w: %v", ErrCheckpointUnverified, err)
	}
	return nil
}

// Sealed returns a copy of the current sealed floor map (for a follow-on instance to
// load), reflecting adopted advances.
func (h *HighWater) Sealed() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.sealed))
	for k, v := range h.sealed {
		out[k] = v
	}
	return out
}
