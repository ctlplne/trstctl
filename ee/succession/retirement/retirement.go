// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package retirement is the evidence-gated tail of the PCAS loop (PCAS-claims 2, 3, 8).
// A hybrid→pure-PQC cutover — and the retirement of the superseded predecessor key
// — proceeds only after a quorum of relying-party acknowledgements that are each
// (a) signed by the acknowledging RP, (b) bound to the identity and the epoch being
// acknowledged, and (c) recorded within a configured validity window; the quorum is
// evaluated per tenant from AN-2 ledger events. On success the predecessor is
// revoked (fail-closed) then zeroized through the core byok lifecycle, and an
// nhi.algorithm.retirement event is emitted that binds a digest of the satisfying
// acknowledgement set, so the condition is itself offline-verifiable. No PCAS
// retirement logic lives in core; this package consumes the core byok lifecycle and
// the AN-2 ledger only (INV-7, INV-9).
package retirement

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// ackDomain separates the RP-acknowledgement signing message from every other
// signed structure. It is frozen: changing it invalidates every prior ack.
const ackDomain = "trstctl/pcas/rp-ack/v1"

// Errors.
var (
	// ErrQuorumNotMet is returned when the acknowledgement quorum is not satisfied;
	// the cutover and retirement are refused and nothing is emitted (INV-7).
	ErrQuorumNotMet = errors.New("retirement: acknowledgement quorum not met; cutover refused")
	// ErrConfig is returned for an unusable controller configuration.
	ErrConfig = errors.New("retirement: invalid configuration")
)

// Target identifies the (tenant, identity, epoch) a cutover acknowledges: the epoch
// of the predecessor/hybrid credential being succeeded.
type Target struct {
	TenantID   string
	IdentityID string
	Epoch      uint64
}

// SignedAck is a relying party's signed post-quantum-capability acknowledgement.
// The signature is over AckMessage(TenantID, IdentityID, Epoch, RelyingParty), so
// it binds the identity and epoch and cannot be replayed onto another identity or
// epoch. RecordedAt is the AN-2 ledger time at which the ack was recorded; it
// governs the validity window.
type SignedAck struct {
	TenantID     string
	IdentityID   string
	Epoch        uint64
	RelyingParty string
	RecordedAt   time.Time
	Signature    []byte
}

// Roster maps a relying-party identifier to its SubjectPublicKeyInfo (PKIX/DER)
// verification key. Only acks from rostered RPs, verifying under the named key, are
// counted.
type Roster map[string][]byte

// QuorumPolicy is the cutover threshold and validity window.
type QuorumPolicy struct {
	// Threshold is the minimum number of distinct, valid, in-window RP acks.
	Threshold int
	// ValidityWindow bounds how long before evaluation an ack may have been
	// recorded and still count. Zero disables the window (any recorded ack counts).
	ValidityWindow time.Duration
}

// QuorumResult is the outcome of a per-tenant quorum evaluation.
type QuorumResult struct {
	Met        bool
	Count      int
	Threshold  int
	Satisfying []SignedAck // distinct, valid, in-window acks, sorted by RelyingParty
}

// AckMessage is the canonical, domain-separated, length-prefixed message a relying
// party signs to acknowledge (tenant, identity, epoch). Binding all three means a
// signature cannot be replayed across tenants, identities, or epochs (PCAS-claim-3).
func AckMessage(tenantID, identityID string, epoch uint64, relyingParty string) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(ackDomain))
	writeField(&b, []byte(tenantID))
	writeField(&b, []byte(identityID))
	writeUint(&b, epoch)
	writeField(&b, []byte(relyingParty))
	return b.Bytes()
}

// SignAck signs the acknowledgement message for a with signer, returning the
// signature to place in SignedAck.Signature. It is a helper for RP producers and
// tests; the signer routes through the core AN-3 crypto boundary.
func SignAck(signer crypto.Signer, tenantID, identityID string, epoch uint64, relyingParty string) ([]byte, error) {
	return signer.Sign(AckMessage(tenantID, identityID, epoch, relyingParty), crypto.SignOptions{Hash: crypto.SHA256})
}

// verify checks that ack is signed by its named relying party under the roster key.
func (r Roster) verify(ack SignedAck) error {
	pub, ok := r[ack.RelyingParty]
	if !ok || len(pub) == 0 {
		return fmt.Errorf("retirement: relying party %q is not rostered", ack.RelyingParty)
	}
	if len(ack.Signature) == 0 {
		return errors.New("retirement: acknowledgement is unsigned")
	}
	return crypto.VerifyMessage(pub, AckMessage(ack.TenantID, ack.IdentityID, ack.Epoch, ack.RelyingParty), ack.Signature)
}

// EvaluateQuorum tallies the acks that satisfy the cutover condition for target
// under policy at evalTime. An ack counts only if it targets the same tenant,
// identity, and epoch; verifies under its rostered RP key (PCAS-claim-3(a),(b)); and was
// recorded within the validity window (PCAS-claim-3(c)). Distinct RPs are counted once;
// the tally is confined to target.TenantID and never crosses tenants (INV-5). The
// returned Satisfying set is exactly the counted acks, sorted deterministically.
func EvaluateQuorum(acks []SignedAck, target Target, roster Roster, policy QuorumPolicy, evalTime time.Time) QuorumResult {
	seen := make(map[string]bool)
	var satisfying []SignedAck
	for _, ack := range acks {
		if ack.TenantID != target.TenantID || ack.IdentityID != target.IdentityID || ack.Epoch != target.Epoch {
			continue
		}
		if policy.ValidityWindow > 0 {
			if ack.RecordedAt.Before(evalTime.Add(-policy.ValidityWindow)) || ack.RecordedAt.After(evalTime) {
				continue // recorded outside the window preceding evaluation
			}
		}
		if err := roster.verify(ack); err != nil {
			continue // unsigned, wrong-key, or non-rostered acks are not counted
		}
		if seen[ack.RelyingParty] {
			continue // one RP contributes at most one ack to the quorum
		}
		seen[ack.RelyingParty] = true
		satisfying = append(satisfying, ack)
	}
	sort.Slice(satisfying, func(i, j int) bool { return satisfying[i].RelyingParty < satisfying[j].RelyingParty })
	return QuorumResult{
		Met:        len(satisfying) >= policy.Threshold && policy.Threshold > 0,
		Count:      len(satisfying),
		Threshold:  policy.Threshold,
		Satisfying: satisfying,
	}
}

// AckSetDigest is the digest binding a set of satisfying acknowledgements, hashed
// through the core AN-3 boundary. The set is sorted by relying party, then each ack
// is length-prefix encoded (tenant, identity, epoch, RP, signature), so an auditor
// with the same acks recomputes the same digest (PCAS-claim-3, offline-verifiable limb).
func AckSetDigest(acks []SignedAck) []byte {
	sorted := append([]SignedAck(nil), acks...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RelyingParty < sorted[j].RelyingParty })
	var b bytes.Buffer
	writeField(&b, []byte("trstctl/pcas/ack-set/v1"))
	writeUint(&b, uint64(len(sorted)))
	for _, a := range sorted {
		writeField(&b, []byte(a.TenantID))
		writeField(&b, []byte(a.IdentityID))
		writeUint(&b, a.Epoch)
		writeField(&b, []byte(a.RelyingParty))
		writeField(&b, a.Signature)
	}
	return crypto.SHA256Sum(b.Bytes())
}

// AcksFromEvents extracts signed acknowledgements from AN-2 ledger events, using
// each event's recorded time as the ack's RecordedAt. Non-ack events and events
// whose schema version is newer than this build understands are skipped, so the
// evaluation is forward-compatible (quorum is evaluated from ledger events).
func AcksFromEvents(evs []events.Event) ([]SignedAck, error) {
	var out []SignedAck
	for _, e := range evs {
		if e.Type != succession.TypeRPAck {
			continue
		}
		p, err := succession.Decode(e)
		if err != nil {
			return nil, fmt.Errorf("retirement: decode ack event: %w", err)
		}
		ack, ok := p.(succession.RPAckV1)
		if !ok {
			continue // Unknown (newer schema) — skip
		}
		out = append(out, SignedAck{
			TenantID:     ack.TenantID,
			IdentityID:   ack.IdentityID,
			Epoch:        ack.Epoch,
			RelyingParty: ack.RelyingParty,
			RecordedAt:   e.Time,
			Signature:    ack.AckSignature,
		})
	}
	return out, nil
}

// Predecessor is the retirable lifecycle of a superseded key. *byok.ManagedSigner
// satisfies it. Retirement calls Revoke (fail-closed) then Zeroize.
type Predecessor interface {
	Revoke(ctx context.Context, tenantID string) error
	Zeroize(ctx context.Context, tenantID string) error
}

// EventAppender is the AN-2 ledger sink. *events.Log satisfies it.
type EventAppender interface {
	Append(ctx context.Context, e events.Event) (events.Event, error)
}

// Successor is the pure-PQC posture the cutover advances to (PCAS-claim-2). The
// dual-signed succession record itself is minted by PCAS-05/08; the cutover records
// the evidence-gated posture advance and binds the record by reference.
type Successor struct {
	Epoch        uint64
	Algorithm    string
	Class        string // succession.ClassPurePQ for a pure-PQC cutover
	PublicKeyDER []byte
}

// CutoverRequest asks to advance target hybrid→pure-PQC and retire the predecessor,
// gated by Acks.
type CutoverRequest struct {
	Target        Target
	Acks          []SignedAck
	Predecessor   Predecessor
	Successor     Successor
	RetiredAlg    string
	SuccessionRef []byte // opaque reference to the dual-signed succession record (PCAS-04)

	// PreRetire, when set, is a precondition evaluated after the quorum is met and
	// the succession is announced, but BEFORE the predecessor is revoked/zeroized. A
	// non-nil error blocks retirement (the succession stands, the predecessor is left
	// usable). PCAS-14 supplies a re-wrap gate here so a confidentiality (KEM) key is
	// not retired until data protected under it has been re-wrapped under the
	// successor.
	PreRetire func(ctx context.Context) error
}

// CutoverResult is the outcome of an evidence-gated cutover.
type CutoverResult struct {
	QuorumMet    bool
	Quorum       QuorumResult
	AckSetDigest []byte
	Advanced     bool // pure-PQC succession announced on the ledger
	Retired      bool // predecessor revoked and zeroized
}

// Config wires a Controller.
type Config struct {
	Roster Roster
	Policy QuorumPolicy
	Ledger EventAppender // AN-2
}

// Controller runs evidence-gated cutovers.
type Controller struct {
	cfg Config
}

// New validates cfg and returns a Controller.
func New(cfg Config) (*Controller, error) {
	if cfg.Policy.Threshold <= 0 {
		return nil, fmt.Errorf("%w: quorum threshold must be positive", ErrConfig)
	}
	if len(cfg.Roster) == 0 {
		return nil, fmt.Errorf("%w: an RP roster is required", ErrConfig)
	}
	if cfg.Ledger == nil {
		return nil, fmt.Errorf("%w: an AN-2 ledger is required", ErrConfig)
	}
	return &Controller{cfg: cfg}, nil
}

// Execute evaluates the quorum for req.Target at evalTime and, only if it is met,
// advances the pure-PQC succession, retires the predecessor (revoke fail-closed →
// zeroize), and emits a retirement event binding the satisfying ack-set digest. If
// the quorum is not met it returns ErrQuorumNotMet and performs no state change:
// nothing is announced, and the predecessor is left untouched (PCAS-claims 2, 3, 8).
func (c *Controller) Execute(ctx context.Context, req CutoverRequest, evalTime time.Time) (CutoverResult, error) {
	q := EvaluateQuorum(req.Acks, req.Target, c.cfg.Roster, c.cfg.Policy, evalTime)
	if !q.Met {
		return CutoverResult{QuorumMet: false, Quorum: q}, ErrQuorumNotMet
	}
	digest := AckSetDigest(q.Satisfying)

	// PCAS-claim-2: announce the evidence-gated hybrid→pure-PQC succession before retiring
	// the predecessor, so the identity's new key is on the ledger first.
	if err := c.append(ctx, succession.SuccessionV1{
		IdentityID:            req.Target.IdentityID,
		TenantID:              req.Target.TenantID,
		PredecessorEpoch:      req.Target.Epoch,
		Epoch:                 req.Successor.Epoch,
		SuccessorAlgorithm:    req.Successor.Algorithm,
		SuccessorPublicKeyDER: req.Successor.PublicKeyDER,
		AlgorithmClass:        req.Successor.Class,
		RecordDigest:          req.SuccessionRef,
	}); err != nil {
		return CutoverResult{QuorumMet: true, Quorum: q, AckSetDigest: digest}, err
	}

	// Re-wrap (or any) precondition gates retirement: if it fails, the succession
	// stands but the predecessor is NOT retired (PCAS-14 re-wrap-before-retire).
	if req.PreRetire != nil {
		if err := req.PreRetire(ctx); err != nil {
			return CutoverResult{QuorumMet: true, Quorum: q, AckSetDigest: digest, Advanced: true}, fmt.Errorf("retirement: pre-retire gate: %w", err)
		}
	}

	// PCAS-claims 8, 16 / INV-9: revoke (fail-closed) THEN zeroize the
	// predecessor from its locked buffers.
	if req.Predecessor != nil {
		if err := req.Predecessor.Revoke(ctx, req.Target.TenantID); err != nil {
			return CutoverResult{QuorumMet: true, Quorum: q, AckSetDigest: digest, Advanced: true}, fmt.Errorf("retirement: revoke predecessor: %w", err)
		}
		if err := req.Predecessor.Zeroize(ctx, req.Target.TenantID); err != nil {
			return CutoverResult{QuorumMet: true, Quorum: q, AckSetDigest: digest, Advanced: true}, fmt.Errorf("retirement: zeroize predecessor: %w", err)
		}
	}

	// PCAS-claim-3: emit retirement binding the ack-set digest (offline-verifiable).
	if err := c.append(ctx, succession.RetirementV1{
		IdentityID:    req.Target.IdentityID,
		TenantID:      req.Target.TenantID,
		Epoch:         req.Target.Epoch,
		RetiredAlg:    req.RetiredAlg,
		SuccessionRef: req.SuccessionRef,
		AckSetDigest:  digest,
	}); err != nil {
		return CutoverResult{QuorumMet: true, Quorum: q, AckSetDigest: digest, Advanced: true, Retired: req.Predecessor != nil}, err
	}

	return CutoverResult{QuorumMet: true, Quorum: q, AckSetDigest: digest, Advanced: true, Retired: req.Predecessor != nil}, nil
}

func (c *Controller) append(ctx context.Context, p succession.Payload) error {
	ev, err := succession.Encode(p)
	if err != nil {
		return err
	}
	_, err = c.cfg.Ledger.Append(ctx, ev)
	return err
}

func writeField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}

func writeUint(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}
