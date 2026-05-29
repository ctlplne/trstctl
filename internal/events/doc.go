// Package events implements the AN-2 append-only event log: the source of
// truth for all state changes.
//
// It defines the event envelope schema and the append and replay operations
// over NATS JetStream (embedded and file-backed for single-node, external
// cluster for production). Both the relational read state and the audit trail
// are projections of this stream; nothing writes derived state directly.
//
// Open returns a Log per config.NATS; Append persists an Event durably and
// assigns its stream sequence, and Replay reads events back in order. The NATS
// dependency lives only in this package (the signer never links it).
package events
