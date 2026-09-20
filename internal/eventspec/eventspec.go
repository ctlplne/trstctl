// SPDX-License-Identifier: BUSL-1.1

// Package eventspec holds the pure, dependency-light type surface of the AN-2
// event log: the Event envelope, its Actor, and the default schema version. It
// imports only the standard library — no NATS, no SQL — so packages that need only
// to construct or read Event values (for example ee/succession's projection layer)
// can depend on it WITHOUT linking the embedded message bus. internal/events
// aliases these types so every existing events.Event / events.Actor reference keeps
// working, while the sacred signer's dependency closure (AN-4) stays free of
// github.com/nats-io. See internal/events for the JetStream-backed Log.
package eventspec

import "time"

// DefaultSchemaVersion is the schema version stamped on every appended event whose
// producer does not set one explicitly, and the version assumed for a legacy stored
// event that predates the field (SCHEMA-001). It is the baseline (v1) payload shape
// for each event type; bump the producer's SchemaVersion when an existing type's
// payload shape changes so a version-aware projector can tell old events from new
// ones on replay rather than silently mis-projecting them.
const DefaultSchemaVersion = 1

// Event is the immutable envelope appended to the AN-2 event log. The event log is
// the source of truth; both the relational read state and the audit trail are
// projections of these events.
type Event struct {
	ID       string    // unique event id (assigned on Append if empty)
	Type     string    // event type, e.g. "tenant.registered"
	TenantID string    // AN-1: every event carries its tenant
	Time     time.Time // emit time (assigned on Append if zero)
	Data     []byte    // opaque domain payload
	Sequence uint64    // stream sequence; assigned on Append and set on Replay
	Actor    *Actor    // who performed the mutation (R2.1); nil for system/background events

	// SchemaVersion is the payload-shape version of this event's Type (SCHEMA-001,
	// AN-2). It is assigned DefaultSchemaVersion on Append when left zero, and is
	// reconstructed on Replay (a legacy event with no stored version reads back as
	// DefaultSchemaVersion). A projector dispatches on (Type, SchemaVersion) so a
	// payload-shape change to an existing type cannot silently mis-project on a
	// rebuild — the new shape carries a new version and old events keep theirs.
	SchemaVersion int
}

// Actor identifies the authenticated caller responsible for an event — the "who" of
// the who-did-what-when-under-what-authorization audit trail (R2.1, F9). It is
// recorded on every event appended under a request context that carries it;
// background or system appends leave it nil (honestly unattributed rather than
// fabricated).
type Actor struct {
	Subject string   `json:"subject"`         // authenticated subject (token subject or OIDC sub)
	Roles   []string `json:"roles,omitempty"` // role names the subject acted under (the "authorization")
}
