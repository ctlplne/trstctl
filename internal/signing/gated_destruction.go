// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"context"
	"errors"
)

// GatedDestroyer is a generic destruction-precondition extension attached to the
// AN-4 signer. Core treats every evidence body as opaque public material: the
// attached edition implementation decides what the required/satisfied sets mean
// and may return an opaque signed refusal record.
type GatedDestroyer interface {
	VerifyGatedDestroy(context.Context, GatedDestroyRequest) (GatedDestroyDecision, error)
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
	Authorization        []byte
	Approvals            []byte
	AuditChainHead       []byte
	Context              []byte
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

// gatedDestroy enforces the generic ordering: verify first, destroy only after an
// approving decision, and never call the supplied destroy hook on a refusal or
// verifier error. The destroy hook is signer-local in production.
func (s *Server) gatedDestroy(ctx context.Context, req GatedDestroyRequest, destroy func(context.Context, string) error) (GatedDestroyDecision, error) {
	decision, err := s.verifyGatedDestroy(ctx, req)
	if err != nil {
		return GatedDestroyDecision{}, err
	}
	if !decision.Approved {
		return decision, nil
	}
	if destroy != nil {
		if err := destroy(ctx, req.Handle); err != nil {
			return decision, err
		}
	}
	return decision, nil
}
