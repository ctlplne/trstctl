// SPDX-License-Identifier: LicenseRef-trstctl-EE

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
)

var ErrConnectorNotConfigured = errors.New("xrec remediation: connector not configured")

// Executor performs one authorized corrective write. XREC-09c supplies the
// write-scoped connector implementation; XREC-09b wires the durable outbox and
// fail-closed dispatch path.
type Executor interface {
	ExecuteRemediation(context.Context, Job) error
}

// ExecutorFunc adapts a function to an Executor.
type ExecutorFunc func(context.Context, Job) error

// ExecuteRemediation calls f.
func (f ExecutorFunc) ExecuteRemediation(ctx context.Context, job Job) error {
	return f(ctx, job)
}

// Handler drains XREC remediation outbox jobs.
type Handler struct {
	executor Executor
}

// NewHandler returns a remediation outbox handler.
func NewHandler(executor Executor) *Handler {
	return &Handler{executor: executor}
}

// NewLicensedOutboxFactory returns the FeatureReconcile licensed-outbox factory.
// Until XREC-09c attaches the actual write-scoped connector, XREC remediation jobs
// fail closed instead of being acknowledged without a corrective write.
func NewLicensedOutboxFactory() editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		if d.Store == nil {
			return nil, fmt.Errorf("%w: nil store", ErrInvalidAuthorization)
		}
		return NewHandler(NewRegistry(NewStoreReceiptRecorder(d.Store))), nil
	}
}

// Deliver implements orchestrator.Handler for focused tests and direct workers.
func (h *Handler) Deliver(ctx context.Context, m orchestrator.Message) error {
	if m.Destination != OutboxDestination {
		return nil
	}
	if h.executor == nil {
		return ErrConnectorNotConfigured
	}
	job, err := DecodeJob(m.Payload)
	if err != nil {
		return err
	}
	if job.TenantID != m.TenantID || job.IdempotencyKey != m.IdempotencyKey {
		return fmt.Errorf("%w: job does not match outbox envelope", ErrInvalidAuthorization)
	}
	return h.executor.ExecuteRemediation(ctx, job)
}

// DeliverLicensed routes only the XREC remediation destination and lets the
// composed licensed-outbox chain try the next handler for all other messages.
func (h *Handler) DeliverLicensed(ctx context.Context, m orchestrator.Message) (bool, error) {
	if m.Destination != OutboxDestination {
		return false, nil
	}
	return true, h.Deliver(ctx, m)
}

// DecodeJob decodes and validates one outbox payload.
func DecodeJob(raw []byte) (Job, error) {
	var job Job
	if len(raw) == 0 {
		return Job{}, ErrInvalidAuthorization
	}
	if err := json.Unmarshal(raw, &job); err != nil {
		return Job{}, fmt.Errorf("xrec remediation: decode job: %w", err)
	}
	if job.TenantID == "" || job.PlanID == "" || job.PlanHash == "" || job.WitnessID == "" ||
		job.WitnessHash == "" || job.RecordKey.TenantID == "" || job.RecordKey.RecordType == "" ||
		job.RecordKey.StableID == "" || job.AuthorityID == "" || job.Operation == "" ||
		len(job.Authorization) == 0 || job.IdempotencyKey == "" {
		return Job{}, ErrInvalidAuthorization
	}
	return job, nil
}
