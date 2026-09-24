// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"errors"
	"fmt"
	"trstctl.com/trstctl/internal/events"
)

// EventTypeArchived is the event appended after a retention run, recording that a
// segment of audit records was archived to cold storage and retired from the live
// audit-query view. The underlying AN-2 domain-event envelopes stay in JetStream:
// projection rebuild, privacy rewrite, and disaster recovery still need them.
const (
	EventTypeArchived = "audit.archived"

	// ArchivedEventSchemaVersion is version 2 because the original v1 event used
	// a tenant-local boundary and segment-local count. Those coordinates cannot
	// reconstruct a global event-log checkpoint after PostgreSQL loss.
	ArchivedEventSchemaVersion = 2
)

// ArchivedEvent is the durable, replayable payload of EventTypeArchived. It uses
// the global event-stream boundary and cumulative tenant record count so an
// event-only restore can reconstruct the exact logical audit checkpoint.
type ArchivedEvent struct {
	Count                 int    `json:"count"`
	BoundarySeq           uint64 `json:"boundary_sequence"`
	BoundaryHash          string `json:"boundary_hash"`
	ArchiveURI            string `json:"archive_uri"`
	SourceHistoryRetained bool   `json:"source_history_retained"`
}

// Summary reports what a retention run did — surfaced as metrics by the server.
type Summary struct {
	TenantsProcessed      int
	SegmentsArchived      int
	RecordsArchived       int
	RecordsSourceRetained int
	// RecordsPruned remains for metrics/API compatibility. It is always zero:
	// deleting audit records from the shared AN-2 source makes rebuild lossy.
	RecordsPruned int
}

// VerifyCheckpointSourceRetained proves that the exact tenant-event cardinality
// covered by a sealed audit checkpoint is still present in the shared AN-2 event
// source. The checkpoint hash is intentionally not recomputed: an authorized
// privacy rewrite may pseudonymize the retained hidden prefix while preserving
// every stream position and envelope identity. Cardinality through the fixed
// global boundary still detects any legacy physical prune because no later append
// can occupy an earlier stream position.
func VerifyCheckpointSourceRetained(
	ctx context.Context,
	log *events.Log,
	checkpoint Checkpoint,
) error {
	if log == nil {
		return errors.New("audit: retained-source verification requires an event log")
	}
	if checkpoint.TenantID == "" || checkpoint.BoundarySeq == 0 ||
		checkpoint.RecordCount <= 0 || checkpoint.BoundaryHash == "" ||
		checkpoint.ArchiveURI == "" {
		return errors.New("audit: retained-source verification requires a complete checkpoint")
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		return fmt.Errorf("audit: read event head for retained-source verification: %w", err)
	}
	if checkpoint.BoundarySeq > head {
		return fmt.Errorf(
			"audit: checkpoint boundary %d is outside event head %d",
			checkpoint.BoundarySeq, head,
		)
	}
	count := 0
	if err := log.ReplayThrough(ctx, 1, checkpoint.BoundarySeq, func(event events.Event) error {
		if event.TenantID == checkpoint.TenantID {
			count++
		}
		return nil
	}); err != nil {
		return fmt.Errorf("audit: verify retained checkpoint source: %w", err)
	}
	if count != checkpoint.RecordCount {
		return fmt.Errorf(
			"audit: checkpoint source history is incomplete for tenant %s: retained %d of %d events through sequence %d; refusing lossy retention/rebuild",
			checkpoint.TenantID, count, checkpoint.RecordCount, checkpoint.BoundarySeq,
		)
	}
	return nil
}
