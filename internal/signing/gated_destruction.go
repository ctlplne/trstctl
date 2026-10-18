// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"io"
)

// GatedDestroyer is a generic destruction-precondition extension attached to the
// AN-4 signer. Core treats every evidence body as opaque public material: the
// attached edition implementation decides what the required/satisfied sets mean
// and may return an opaque signed refusal record.
type GatedDestroyer interface {
	VerifyGatedDestroy(context.Context, GatedDestroyRequest) (GatedDestroyDecision, error)
}

// GatedDestructionFinalizer is the optional second half of one signer-local
// destruction operation. It runs only after the custody handle has been
// destroyed and returns public evidence for that exact irreversible effect.
// Keeping finalization on the attached gate means core does not know an
// edition's record format, while the control plane cannot mint a success record
// without first passing through the signer-local destroy hook.
type GatedDestructionFinalizer interface {
	FinalizeGatedDestroy(context.Context, GatedDestroyRequest, GatedDestroyDecision) (GatedDestroyDecision, error)
}

// StreamingGatedDestroyer verifies large public evidence from a bounded reader.
// The signer hashes the exact bytes before calling this method, so an edition
// gate receives the same immutable evidence that the durable intent names.
type StreamingGatedDestroyer interface {
	VerifyGatedDestroyStream(context.Context, GatedDestroyRequest, io.Reader) (GatedDestroyDecision, error)
}

// GatedDestroyRequest carries public, generic destruction preconditions into the
// isolated signer. It carries no private key material and names no edition-specific
// feature. Handle is the signer-local custody handle to destroy only after the
// attached gate approves.
type GatedDestroyRequest struct {
	TenantID             string
	Handle               string
	SubjectRef           string
	AssertedFinalEpoch   uint64
	LedgerPosition       uint64
	RequiredSet          []byte
	RequiredSetDigest    []byte
	SatisfiedSet         []byte
	SatisfactionEvidence []byte
	// SatisfactionEvidenceDigest binds the exact streamed bytes to the signer
	// journal and refusal record. It is empty on the legacy unary RPC.
	SatisfactionEvidenceDigest []byte
	Authorization              []byte
	Approvals                  []byte
	AuditChainHead             []byte
	Context                    []byte
}

// GatedDestroyDecision is the generic verifier result. Core reads only Approved
// to enforce ordering; the remaining fields are opaque public records surfaced to
// the caller unaltered.
type GatedDestroyDecision struct {
	Approved      bool
	RefusalRecord []byte
	Authorization []byte
	Evidence      []byte
}

var ErrNoGatedDestroyer = errors.New("signing: no gated destroyer attached")

// WithGatedDestruction attaches a generic destruction gate to the signer. Core
// owns only the ordering seam; edition code supplied through the tagged attach
// seam owns the concrete verification semantics.
func WithGatedDestruction(g GatedDestroyer) ServerOption {
	return func(s *Server) {
		if g != nil {
			s.gatedDestroyer = g
		}
	}
}

func (s *Server) verifyGatedDestroy(ctx context.Context, req GatedDestroyRequest) (GatedDestroyDecision, error) {
	s.mu.Lock()
	g := s.gatedDestroyer
	s.mu.Unlock()
	if g == nil {
		return GatedDestroyDecision{}, ErrNoGatedDestroyer
	}
	return g.VerifyGatedDestroy(ctx, req)
}

func (s *Server) verifyGatedDestroyStream(ctx context.Context, req GatedDestroyRequest, evidence io.Reader) (GatedDestroyDecision, error) {
	s.mu.Lock()
	g := s.gatedDestroyer
	s.mu.Unlock()
	streaming, ok := g.(StreamingGatedDestroyer)
	if !ok {
		return GatedDestroyDecision{}, ErrNoGatedDestroyer
	}
	return streaming.VerifyGatedDestroyStream(ctx, req, evidence)
}

// gatedDestroy enforces the generic ordering: verify first, destroy only after an
// approving decision, and never call the supplied destroy hook on a refusal or
// verifier error. The destroy hook is signer-local in production.
func (s *Server) gatedDestroy(ctx context.Context, req GatedDestroyRequest, destroy func(context.Context, string) error, durable bool) (GatedDestroyDecision, error) {
	return s.gatedDestroyWithEvidence(ctx, req, nil, destroy, durable)
}

func (s *Server) gatedDestroyWithEvidence(ctx context.Context, req GatedDestroyRequest, evidence io.Reader, destroy func(context.Context, string) error, durable bool) (GatedDestroyDecision, error) {
	var operationID string
	var decision GatedDestroyDecision
	var err error
	if durable {
		s.gatedDestroyMu.Lock()
		defer s.gatedDestroyMu.Unlock()
		operationID, err = gatedDestroyOperationID(req)
		if err != nil {
			return GatedDestroyDecision{}, err
		}
		prior, state, found, err := s.loadGatedDestroyOperation(operationID, req)
		if err != nil {
			return GatedDestroyDecision{}, err
		}
		if found && state == "completed" {
			return prior, nil
		}
		if found {
			// The fsynced executing record is the signer-owned proof that this
			// exact request was already approved before a crash. Re-running a
			// mutable policy here could strand a key that was already zeroized.
			decision = prior
		} else {
			if evidence != nil {
				decision, err = s.verifyGatedDestroyStream(ctx, req, evidence)
			} else {
				decision, err = s.verifyGatedDestroy(ctx, req)
			}
			if err != nil {
				return GatedDestroyDecision{}, err
			}
			if !decision.Approved {
				if len(decision.RefusalRecord) != 0 {
					if err := s.recordGatedDestroyRefusal(operationID, req, decision); err != nil {
						return GatedDestroyDecision{}, err
					}
				}
				return decision, nil
			}
			if err := s.beginGatedDestroyOperation(operationID, req, decision); err != nil {
				return GatedDestroyDecision{}, err
			}
		}
	} else {
		if evidence != nil {
			decision, err = s.verifyGatedDestroyStream(ctx, req, evidence)
		} else {
			decision, err = s.verifyGatedDestroy(ctx, req)
		}
		if err != nil {
			return GatedDestroyDecision{}, err
		}
		if !decision.Approved {
			return decision, nil
		}
	}
	if destroy != nil {
		if err := destroy(ctx, req.Handle); err != nil {
			return decision, err
		}
	}
	s.mu.Lock()
	finalizer, canFinalize := s.gatedDestroyer.(GatedDestructionFinalizer)
	s.mu.Unlock()
	if canFinalize {
		decision, err = finalizer.FinalizeGatedDestroy(ctx, req, decision)
		if err != nil {
			return GatedDestroyDecision{}, err
		}
	}
	if durable {
		if err := s.completeGatedDestroyOperation(operationID, req, decision); err != nil {
			return GatedDestroyDecision{}, err
		}
	}
	return decision, nil
}
