// Package events implements the AN-2 append-only event log: the source of
// truth for all state changes.
//
// It defines the event envelope schema and the append and replay operations
// over NATS JetStream (embedded and file-backed for single-node, external
// cluster for production). Both the relational read state and the audit trail
// are projections of this stream; nothing writes derived state directly.
//
// Implementation begins in sprint S2.1; this file reserves the package.
package events
