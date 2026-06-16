package audit

import (
	"context"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/events"
)

// logAuditor adapts the AN-2 event log to the auditsink.Auditor write seam. It is
// the REAL production adapter the subsystems' audit calls flow through once wired:
// an Audit becomes an events.Log.Append, and — this is the CODE-001 fix — the
// append error is RETURNED, not swallowed. A failed append (NATS down,
// backpressure, marshal error) therefore surfaces to the caller, where a
// source-of-truth path can fail closed and an after-the-fact path can log+count
// the drop (auditsink.Emit) rather than silently losing the event.
//
// Before this adapter the only auditsink.Auditor implementations were the Nop and
// the test Recorder, so every `_ = x.Audit(...)` discard was latent; this makes
// the write seam real and error-bearing, which is what makes handling the error
// at the call sites meaningful (CODE-001).
type logAuditor struct {
	log *events.Log
}

// NewAuditor returns an auditsink.Auditor backed by the event log. Each Audit
// appends an immutable event (the source of truth; the audit trail and read model
// are projections of it, AN-2) and returns the append error so the caller can act
// on a failed write instead of dropping it.
func NewAuditor(log *events.Log) auditsink.Auditor {
	return &logAuditor{log: log}
}

// Audit implements auditsink.Auditor by appending the event to the log. It
// returns the append error verbatim (CODE-001): callers must not discard it.
func (a *logAuditor) Audit(ctx context.Context, eventType, tenantID string, data []byte) error {
	_, err := a.log.Append(ctx, events.Event{
		Type:     eventType,
		TenantID: tenantID,
		Data:     data,
	})
	return err
}
