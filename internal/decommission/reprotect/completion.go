// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/decommission/depstate"
)

var ErrNilCompletionSink = errors.New("vdec reprotect: nil completion sink")

// CompletionEventSink appends completion evidence to the caller-owned event
// substrate. The recorder supplies idempotency; the sink supplies durability.
type CompletionEventSink interface {
	AppendReprotectionCompleted(context.Context, depstate.ReprotectionCompletedV1) error
}

// CompletionResult reports whether this delivery appended a new completion event.
type CompletionResult struct {
	Recorded bool
	Event    depstate.ReprotectionCompletedV1
}

type CompletionEvidence struct {
	SuccessorKeyID         string
	CredentialSupersession *depstate.CredentialSupersessionV1
}

// CompletionRecorder records at most one completion event for a job idempotency
// key and dependent identity pair.
//
// This is the idempotency half of VDEC-claim-14: a redelivered job yields at most
// one completion event for a dependent, so a dispatch interrupted by control-plane
// failure can resume from the durable queue without double-counting.
type CompletionRecorder struct {
	mu   sync.Mutex
	sink CompletionEventSink
	seen map[string]struct{}
}

func NewCompletionRecorder(sink CompletionEventSink) *CompletionRecorder {
	return &CompletionRecorder{sink: sink, seen: make(map[string]struct{})}
}

func (r *CompletionRecorder) RecordCompletion(ctx context.Context, job Job, successorKeyID string) (CompletionResult, error) {
	return r.RecordCompletionEvidence(ctx, job, CompletionEvidence{SuccessorKeyID: successorKeyID})
}

func (r *CompletionRecorder) RecordCompletionEvidence(ctx context.Context, job Job, evidence CompletionEvidence) (CompletionResult, error) {
	if r == nil || r.sink == nil {
		return CompletionResult{}, ErrNilCompletionSink
	}
	if err := validateJob(job); err != nil {
		return CompletionResult{}, err
	}
	if strings.TrimSpace(evidence.SuccessorKeyID) == "" {
		return CompletionResult{}, fmt.Errorf("%w: successor_key_id is required", ErrInvalidState)
	}
	if err := validateCompletionEvidence(job, evidence); err != nil {
		return CompletionResult{}, err
	}
	event := depstate.ReprotectionCompletedV1{
		TenantID:       job.TenantID,
		KeyID:          job.KeyID,
		JobID:          job.ID,
		Dependent:      job.Dependent,
		SuccessorKeyID: evidence.SuccessorKeyID,
	}
	if evidence.CredentialSupersession != nil {
		supersession := *evidence.CredentialSupersession
		event.CredentialSupersession = &supersession
	}
	key := completionKey(job)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[key]; ok {
		return CompletionResult{Recorded: false, Event: event}, nil
	}
	if err := r.sink.AppendReprotectionCompleted(ctx, event); err != nil {
		return CompletionResult{}, err
	}
	r.seen[key] = struct{}{}
	return CompletionResult{Recorded: true, Event: event}, nil
}

func validateCompletionEvidence(job Job, evidence CompletionEvidence) error {
	link := evidence.CredentialSupersession
	if link == nil {
		return nil
	}
	if job.Kind != JobKindReIssue || job.Dependent.Class != depstate.DependentCredential {
		return fmt.Errorf("%w: credential supersession evidence requires a credential reissue job", ErrInvalidState)
	}
	if strings.TrimSpace(link.OldCredentialID) == "" || strings.TrimSpace(link.NewCredentialID) == "" {
		return fmt.Errorf("%w: old and new credential ids are required", ErrInvalidState)
	}
	if link.OldCredentialID != job.Dependent.ID {
		return fmt.Errorf("%w: supersession old credential %s does not match dependent %s", ErrInvalidState, link.OldCredentialID, job.Dependent.ID)
	}
	if link.NewCredentialID == link.OldCredentialID {
		return fmt.Errorf("%w: supersession credential ids must differ", ErrInvalidState)
	}
	return nil
}

func completionKey(job Job) string {
	return job.TenantID + "\x00" + job.KeyID + "\x00" + job.IdempotencyKey + "\x00" + dependentKey(job.Dependent)
}
