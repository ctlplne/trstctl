// SPDX-License-Identifier: BUSL-1.1

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

const (
	TypeGatedDestructionRefused = "gated_destruction.refused"
	SchemaV1                    = 1
	defaultRefusalKeyID         = "vdec-gated-destruction-refusal"
	refusalConstraint           = "registered_minus_accounted_empty"
)

var (
	ErrInvalidEvidence = errors.New("vdec gate: invalid evidence")
	ErrRefused         = errors.New("vdec gate: destruction refused")
)

// RefusalAppendSink is the ledger-like append surface the signer uses for failed
// gates. *internal/events.Log has the same shape via eventspec aliasing, while the
// signer attach can use a local append-only file sink without linking NATS or SQL.
type RefusalAppendSink interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

// Config wires the signer-side VDEC destruction gate.
type Config struct {
	SignerID     string
	KeyID        string
	Algorithm    crypto.Algorithm
	Sink         RefusalAppendSink
	QuorumPolicy QuorumPolicy
	Now          func() time.Time
}

// Gate is attached to the isolated signer through signing.WithGatedDestruction.
// It owns only signer-local state: a refusal-signing key and an append sink.
type Gate struct {
	mu       sync.Mutex
	signerID string
	keyID    string
	key      *crypto.LockedSigner
	sink     RefusalAppendSink
	quorum   QuorumPolicy
	now      func() time.Time
}

func New(cfg Config) (*Gate, error) {
	alg := cfg.Algorithm
	if alg == "" {
		alg = crypto.ECDSAP256
	}
	key, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: refusal keygen: %w", err)
	}
	signerID := strings.TrimSpace(cfg.SignerID)
	if signerID == "" {
		signerID = "trstctl-signer"
	}
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		keyID = defaultRefusalKeyID
	}
	sink := cfg.Sink
	if sink == nil {
		sink = NewMemorySink()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Gate{signerID: signerID, keyID: keyID, key: key, sink: sink, quorum: cloneQuorumPolicy(cfg.QuorumPolicy), now: now}, nil
}

// VerifyGatedDestroy refuses until the set difference
// registered − (completed ∪ released ∪ erasure-designated) is empty in the
// dependency-state projection folded from the presented ledger segment.
func (g *Gate) VerifyGatedDestroy(ctx context.Context, req signing.GatedDestroyRequest) (signing.GatedDestroyDecision, error) {
	if err := ctx.Err(); err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.SubjectRef) == "" || req.LedgerPosition == 0 {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: tenant, subject ref, and ledger position are required", ErrInvalidEvidence)
	}
	if req.AssertedFinalEpoch == 0 {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: asserted final epoch is required", ErrInvalidEvidence)
	}
	segment, err := DecodeLedgerSegment(req.SatisfactionEvidence)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	if segment.FinalEpoch != 0 && segment.FinalEpoch != req.AssertedFinalEpoch {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: asserted final epoch %d does not match evidence epoch %d", ErrInvalidEvidence, req.AssertedFinalEpoch, segment.FinalEpoch)
	}
	bounded := BoundEvents(segment.Events, req.LedgerPosition)
	if len(req.AuditChainHead) > 0 && !bytes.Equal(req.AuditChainHead, AuditChainHead(bounded)) {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: audit chain head mismatch", ErrInvalidEvidence)
	}

	proj, err := depstate.Fold(bounded)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	state, ok := proj.Lookup(req.TenantID, req.SubjectRef)
	if !ok {
		state = depstate.KeyState{TenantID: req.TenantID, KeyID: req.SubjectRef, LedgerPosition: req.LedgerPosition}
	}
	requiredDigest, err := RequiredSetDigest(state)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	if len(req.RequiredSetDigest) > 0 && !bytes.Equal(req.RequiredSetDigest, requiredDigest) {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: required set digest mismatch", ErrInvalidEvidence)
	}
	if len(req.RequiredSet) > 0 {
		if err := VerifyRequiredSet(req.RequiredSet, state); err != nil {
			return signing.GatedDestroyDecision{}, err
		}
	}

	unaccounted := state.Unaccounted()
	if len(unaccounted) != 0 {
		return g.refuse(ctx, req, state, unaccounted)
	}
	quorumEvidence, err := g.verifyQuorum(req)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	return signing.GatedDestroyDecision{
		Approved:      true,
		Authorization: quorumEvidence,
		Evidence:      requiredDigest,
	}, nil
}

func (g *Gate) refuse(ctx context.Context, req signing.GatedDestroyRequest, state depstate.KeyState, unaccounted []depstate.Dependent) (signing.GatedDestroyDecision, error) {
	artifact, raw, err := g.signRefusal(req, state, unaccounted)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	appended, err := g.sink.Append(ctx, eventspec.Event{
		Type:          TypeGatedDestructionRefused,
		TenantID:      req.TenantID,
		SchemaVersion: SchemaV1,
		Data:          raw,
	})
	if err != nil {
		return signing.GatedDestroyDecision{}, fmt.Errorf("vdec gate: append refusal: %w", err)
	}
	appendedBytes, err := json.Marshal(appended)
	if err != nil {
		return signing.GatedDestroyDecision{}, fmt.Errorf("vdec gate: encode appended refusal event: %w", err)
	}
	_ = artifact
	return signing.GatedDestroyDecision{
		Approved:      false,
		RefusalRecord: raw,
		Evidence:      appendedBytes,
	}, nil
}

func (g *Gate) Destroy() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.key != nil {
		g.key.Destroy()
		g.key = nil
	}
}
