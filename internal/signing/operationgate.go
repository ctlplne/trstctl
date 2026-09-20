// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
)

// OperationGate is a generic pre-operation verification extension attached to
// the AN-4 signer. Core treats all bodies as opaque public evidence; edition code
// decides what the operation means and whether it is authorized.
type OperationGate interface {
	VerifyOperation(context.Context, OperationRequest) (OperationDecision, error)
}

// OperationRequest carries public metadata and opaque evidence into the signer.
// It carries no private key material and names no edition-specific feature.
type OperationRequest struct {
	TenantID       string
	Operation      string
	SubjectRef     string
	IdempotencyKey string
	Preconditions  []byte
	Evidence       []byte
	Context        []byte
}

// OperationDecision is the generic verifier result. Core reads only Approved to
// enforce ordering; the remaining fields are opaque public records.
type OperationDecision struct {
	Approved      bool
	RefusalRecord []byte
	Authorization []byte
	Evidence      []byte
}

var ErrNoOperationGate = errors.New("signing: no operation gate attached")

// WithOperationGate attaches a generic operation gate to the signer. The concrete
// semantics live in edition code supplied by the tagged attach seam.
func WithOperationGate(g OperationGate) ServerOption {
	return func(s *Server) {
		if g != nil {
			s.operationGate = g
		}
	}
}

func (s *Server) verifyOperation(ctx context.Context, req OperationRequest) (OperationDecision, error) {
	s.mu.Lock()
	g := s.operationGate
	s.mu.Unlock()
	if g == nil {
		return OperationDecision{}, ErrNoOperationGate
	}
	return g.VerifyOperation(ctx, req)
}

func (s *Server) gatedOperation(ctx context.Context, req OperationRequest, keyOp func(context.Context, OperationDecision) error) (OperationDecision, error) {
	decision, err := s.verifyOperation(ctx, req)
	if err != nil {
		return OperationDecision{}, err
	}
	if !decision.Approved {
		return decision, nil
	}
	if keyOp != nil {
		if err := keyOp(ctx, decision); err != nil {
			return decision, err
		}
	}
	return decision, nil
}
