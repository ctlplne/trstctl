// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/transit"
)

type RewrapBoundary interface {
	Rewrap(ctx context.Context, tenantID, keyName, ciphertext string, aad []byte) (string, error)
}

type TransitBoundary struct {
	service interface {
		Rewrap(context.Context, string, string, string, []byte) (string, error)
	}
}

type CiphertextExecutor struct {
	boundary RewrapBoundary
	recorder *CompletionRecorder
}

type CiphertextRequest struct {
	Job            Job
	TransitKeyName string
	Ciphertext     string
	AAD            []byte
	SuccessorKeyID string
}

type CiphertextResult struct {
	Ciphertext string
	Completion CompletionResult
}

func NewTransitBoundary(service *transit.Service) (TransitBoundary, error) {
	if service == nil {
		return TransitBoundary{}, errors.New("reprotect: transit service is required")
	}
	return TransitBoundary{service: service}, nil
}

func (b TransitBoundary) Rewrap(ctx context.Context, tenantID, keyName, ciphertext string, aad []byte) (string, error) {
	if b.service == nil {
		return "", errors.New("reprotect: transit boundary is not configured")
	}
	return b.service.Rewrap(ctx, tenantID, keyName, ciphertext, aad)
}

func NewCiphertextExecutor(boundary RewrapBoundary, recorder *CompletionRecorder) (*CiphertextExecutor, error) {
	if boundary == nil {
		return nil, errors.New("reprotect: rewrap boundary is required")
	}
	if recorder == nil {
		return nil, ErrNilCompletionSink
	}
	return &CiphertextExecutor{boundary: boundary, recorder: recorder}, nil
}

func (e *CiphertextExecutor) Execute(ctx context.Context, req CiphertextRequest) (CiphertextResult, error) {
	if e == nil || e.boundary == nil || e.recorder == nil {
		return CiphertextResult{}, errors.New("reprotect: ciphertext executor is not configured")
	}
	if err := validateCiphertextRequest(req); err != nil {
		return CiphertextResult{}, err
	}
	next, err := e.boundary.Rewrap(ctx, req.Job.TenantID, req.TransitKeyName, req.Ciphertext, req.AAD)
	if err != nil {
		return CiphertextResult{}, err
	}
	completion, err := e.recorder.RecordCompletion(ctx, req.Job, req.SuccessorKeyID)
	if err != nil {
		return CiphertextResult{}, err
	}
	return CiphertextResult{Ciphertext: next, Completion: completion}, nil
}

func validateCiphertextRequest(req CiphertextRequest) error {
	if err := validateJob(req.Job); err != nil {
		return err
	}
	switch req.Job.Kind {
	case JobKindReEncrypt, JobKindReWrap:
	default:
		return fmt.Errorf("%w: ciphertext executor cannot handle job kind %s", ErrInvalidState, req.Job.Kind)
	}
	if req.TransitKeyName == "" || req.Ciphertext == "" {
		return fmt.Errorf("%w: transit key name and ciphertext are required", ErrInvalidState)
	}
	if req.SuccessorKeyID == "" {
		return fmt.Errorf("%w: successor_key_id is required", ErrInvalidState)
	}
	return nil
}
