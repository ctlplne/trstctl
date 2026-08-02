// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/dynsecret"
)

var ErrLeaseRevocationPending = errors.New("vdec reprotect: lease revocation still pending")

type LeaseRevocationEngine interface {
	Revoke(context.Context, string) error
	RunRevocations(context.Context) (int, error)
}

type LeaseRevocationQueue interface {
	Pending(context.Context) ([]dynsecret.RevokeItem, error)
}

// LeaseRevocationExecutor practices VDEC-claim-19: leased credentials registered
// at issuance are revoked through a durable queue, so a revocation interrupted by
// control-plane failure resumes on restart and stays idempotent at one completion
// event per lease.
type LeaseRevocationExecutor struct {
	engine   LeaseRevocationEngine
	queue    LeaseRevocationQueue
	recorder *CompletionRecorder
}

type LeaseRevocationRequest struct {
	Job     Job
	LeaseID string
}

type LeaseRevocationResult struct {
	LeaseID    string
	Drained    int
	Pending    bool
	Completion CompletionResult
}

func NewLeaseRevocationExecutor(engine LeaseRevocationEngine, queue LeaseRevocationQueue, recorder *CompletionRecorder) (*LeaseRevocationExecutor, error) {
	if engine == nil {
		return nil, errors.New("reprotect: lease revocation engine is required")
	}
	if queue == nil {
		return nil, errors.New("reprotect: lease revocation queue is required")
	}
	if recorder == nil {
		return nil, ErrNilCompletionSink
	}
	return &LeaseRevocationExecutor{engine: engine, queue: queue, recorder: recorder}, nil
}

func (e *LeaseRevocationExecutor) Execute(ctx context.Context, req LeaseRevocationRequest) (LeaseRevocationResult, error) {
	if e == nil || e.engine == nil || e.queue == nil || e.recorder == nil {
		return LeaseRevocationResult{}, errors.New("reprotect: lease revocation executor is not configured")
	}
	leaseID, err := validateLeaseRevocationRequest(req)
	if err != nil {
		return LeaseRevocationResult{}, err
	}
	result := LeaseRevocationResult{LeaseID: leaseID}
	alreadyPending, err := e.leasePending(ctx, leaseID)
	if err != nil {
		return result, err
	}
	if err := e.engine.Revoke(ctx, leaseID); err != nil {
		if !errors.Is(err, dynsecret.ErrLeaseNotFound) || !alreadyPending {
			return result, err
		}
	}
	drained, err := e.engine.RunRevocations(ctx)
	if err != nil {
		return result, err
	}
	result.Drained = drained
	pending, err := e.leasePending(ctx, leaseID)
	if err != nil {
		return result, err
	}
	result.Pending = pending
	if pending {
		return result, ErrLeaseRevocationPending
	}
	completion, err := e.recorder.RecordCompletion(ctx, req.Job, leaseRevokedSuccessorID(leaseID))
	if err != nil {
		return result, err
	}
	result.Completion = completion
	return result, nil
}

func validateLeaseRevocationRequest(req LeaseRevocationRequest) (string, error) {
	if err := validateJob(req.Job); err != nil {
		return "", err
	}
	if req.Job.Kind != JobKindRevokeLease || req.Job.Dependent.Class != depstate.DependentLeasedSecret {
		return "", fmt.Errorf("%w: lease revocation executor cannot handle job kind %s", ErrInvalidState, req.Job.Kind)
	}
	leaseID := strings.TrimSpace(req.LeaseID)
	if leaseID == "" {
		leaseID = strings.TrimSpace(req.Job.Dependent.ID)
	}
	if leaseID == "" {
		return "", fmt.Errorf("%w: lease_id is required", ErrInvalidState)
	}
	if leaseID != req.Job.Dependent.ID {
		return "", fmt.Errorf("%w: lease_id %s does not match dependent %s", ErrInvalidState, leaseID, req.Job.Dependent.ID)
	}
	return leaseID, nil
}

func (e *LeaseRevocationExecutor) leasePending(ctx context.Context, leaseID string) (bool, error) {
	items, err := e.queue.Pending(ctx)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.LeaseID == leaseID {
			return true, nil
		}
	}
	return false, nil
}

func leaseRevokedSuccessorID(leaseID string) string {
	return "lease-revoked:" + leaseID
}
