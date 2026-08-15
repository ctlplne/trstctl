// SPDX-License-Identifier: MPL-2.0

// Package auditsink is the minimal write-seam for audited events used across the
// workload-identity, incident-response, and SSH-CA subsystems (Epochs 11–13).
//
// AN-2 makes every issuance and remediation an audited event. The existing
// internal/audit package is the *read* side (query/search/export over the event
// log); this package is the tiny *write* interface those subsystems depend on so
// they do not have to import the NATS-backed event log directly (which would make
// them impossible to unit-test). The control-plane assembly wires an adapter from
// this interface to events.Log.Append; unit tests use the Recorder double.
package auditsink

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"trstctl.com/trstctl/internal/crypto"
)

// Auditor records an audited event. eventType is a dotted name
// (e.g. "spiffe.svid.issued"); tenantID scopes it (AN-1); data is a JSON payload.
type Auditor interface {
	Audit(ctx context.Context, eventType, tenantID string, data []byte) error
}

// droppedEvents counts audit/event-emit writes that failed and were NOT
// propagated to the caller — i.e. an AN-2 source-of-truth/audit event that the
// event log could not accept (NATS down, backpressure, marshal error) while the
// local side-effect already happened. A non-zero value is a lost-event integrity
// signal an operator must alarm on (CODE-001). It is process-wide and is surfaced
// as a metric by the control plane.
var droppedEvents atomic.Int64

// DroppedEvents returns the running count of dropped audit/event-emit writes
// (CODE-001). The control plane exports it as a gauge/counter; a test asserts it
// increments when an emit is dropped rather than silently swallowed.
func DroppedEvents() int64 { return droppedEvents.Load() }

// Emit records an audited event through a, and — crucially — does NOT silently
// discard a failed write the way a bare `_ = a.Audit(...)` does (CODE-001). On
// failure it increments the process-wide dropped-event counter and logs at WARN
// (when logger is non-nil) so a lost AN-2 source-of-truth/audit record is visible
// to operators. It returns the underlying error so a caller on a critical path
// can additionally fail closed; telemetry-grade callers may ignore the return,
// having already accounted for the drop via the counter+log.
//
// This is the sanctioned idiom for an after-the-fact emit (the local state change
// already committed): use Emit, never `_ = a.Audit(...)`. For an emit that IS the
// state of record (no local read model survives without it), propagate the error
// to the caller and fail the mutation.
func Emit(ctx context.Context, a Auditor, logger *slog.Logger, eventType, tenantID string, data []byte) error {
	if a == nil {
		return nil
	}
	data = wellFormedPayload(ctx, logger, eventType, tenantID, data)
	err := a.Audit(ctx, eventType, tenantID, data)
	if err != nil {
		droppedEvents.Add(1)
		if logger == nil {
			logger = slog.Default()
		}
		// The payload is deliberately NOT logged — it may carry sensitive material
		// (e.g. an encrypted secret envelope); only the type/tenant and the error
		// are recorded.
		logger.WarnContext(ctx, "audit event dropped: event-log append failed",
			slog.String("event_type", eventType),
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
	}
	return err
}

// malformedPayloads counts audit emits whose payload was not valid JSON and had
// to be substituted. Like droppedEvents this is an integrity signal, not a
// nuisance metric: it means some subsystem is producing audit records a
// downstream consumer cannot parse.
var malformedPayloads atomic.Int64

// MalformedAuditPayloads returns the running count of audit emits whose payload
// was rejected as malformed JSON and replaced.
func MalformedAuditPayloads() int64 { return malformedPayloads.Load() }

// wellFormedPayload guarantees the bytes handed to the auditor are valid JSON.
//
// Payloads across this codebase are overwhelmingly built with
// fmt.Sprintf(`{"k":%q,...}`, v). That looks safe and nearly is, but %q emits Go
// string syntax, not JSON: a control byte renders as \x1b and invalid UTF-8 as
// \xff, neither of which any JSON parser accepts. When v is client-supplied —
// an SSH key ID, an enrollment subject, a secret path — a hostile or merely
// sloppy value silently turns that issuance's audit record into bytes nothing
// downstream can read. Validating at every one of those call sites is a losing
// game; validating at the single seam they all pass through is not.
//
// A malformed payload is replaced rather than dropped. The event itself is the
// AN-2 record of something that actually happened, so losing it is worse than
// losing its detail. The substitute keeps the event and records the size and a
// digest of the original, which is enough to correlate with the emitting call
// site without reproducing bytes that may carry sensitive material — the same
// reason the drop path below does not log the payload.
func wellFormedPayload(ctx context.Context, logger *slog.Logger, eventType, tenantID string, data []byte) []byte {
	if len(data) == 0 || json.Valid(data) {
		return data
	}
	malformedPayloads.Add(1)
	digest := crypto.SHA256Hex(data)
	if logger == nil {
		logger = slog.Default()
	}
	logger.WarnContext(ctx, "audit payload was not valid JSON and was replaced",
		slog.String("event_type", eventType),
		slog.String("tenant_id", tenantID),
		slog.Int("payload_bytes", len(data)),
		slog.String("payload_sha256", digest),
	)
	replacement, err := json.Marshal(struct {
		Malformed     bool   `json:"trstctl_payload_malformed"`
		Bytes         int    `json:"original_bytes"`
		SHA256        string `json:"original_sha256"`
		OriginalEvent string `json:"event_type"`
	}{Malformed: true, Bytes: len(data), SHA256: digest, OriginalEvent: eventType})
	if err != nil {
		// json.Marshal of this struct cannot fail; keep the event anyway.
		return []byte(fmt.Sprintf(`{"trstctl_payload_malformed":true,"original_bytes":%d}`, len(data)))
	}
	return replacement
}

// AuditorFunc adapts a plain append function to the Auditor interface so a caller
// that holds a concrete event-log handle (e.g. *events.Log) can route an
// after-the-fact emit through Emit and get its dropped-event accounting + WARN log
// instead of swallowing the error with `_, _ = log.Append(...)` (CORRECT-004). The
// adapter exists here, not in the event-log package, so auditsink keeps no
// dependency on the NATS-backed log.
type AuditorFunc func(ctx context.Context, eventType, tenantID string, data []byte) error

// Audit implements Auditor.
func (f AuditorFunc) Audit(ctx context.Context, eventType, tenantID string, data []byte) error {
	if f == nil {
		return nil
	}
	return f(ctx, eventType, tenantID, data)
}

// Nop discards events. A safe default when no auditor is wired.
type Nop struct{}

// Audit implements Auditor.
func (Nop) Audit(context.Context, string, string, []byte) error { return nil }

// Record is one captured audit event.
type Record struct {
	Type     string
	TenantID string
	Data     []byte
}

// Recorder is a thread-safe in-memory Auditor for tests: it lets a test assert
// the expected audit events were emitted (the AN-2 "is audited" acceptance).
type Recorder struct {
	mu      sync.Mutex
	records []Record
}

// Audit implements Auditor.
func (r *Recorder) Audit(_ context.Context, eventType, tenantID string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	r.records = append(r.records, Record{Type: eventType, TenantID: tenantID, Data: cp})
	return nil
}

// Records returns a copy of all captured events.
func (r *Recorder) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.records))
	copy(out, r.records)
	return out
}

// Count returns how many captured events have the given type.
func (r *Recorder) Count(eventType string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.records {
		if rec.Type == eventType {
			n++
		}
	}
	return n
}
