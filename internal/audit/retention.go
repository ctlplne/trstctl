// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
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

// Archiver writes a signed, offline-verifiable audit segment to durable cold
// storage and returns a locator. DirArchiver writes to a local directory
// (Audit.ArchiveDir); an S3-compatible archiver is the production target and
// plugs in here unchanged — this interface is the seam.
type Archiver interface {
	Archive(ctx context.Context, tenantID string, boundarySeq uint64, signedBundle string) (uri string, err error)
}

// DirArchiver writes each segment as <dir>/<tenant>/audit-<boundarySeq>.jws with
// owner-only permissions. The file is a compact JWS — the offline-verifiable
// evidence an auditor recovers and checks with VerifyBundle and the service's
// verification keys.
type DirArchiver struct{ Dir string }

// Archive writes the signed bundle and returns its path.
func (a DirArchiver) Archive(_ context.Context, tenantID string, boundarySeq uint64, signedBundle string) (string, error) {
	if a.Dir == "" {
		return "", errors.New("audit: archive dir is empty")
	}
	dir := filepath.Join(a.Dir, tenantID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("audit: create archive dir: %w", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("audit-%020d.jws", boundarySeq))
	if err := os.WriteFile(path, []byte(signedBundle), 0o600); err != nil {
		return "", fmt.Errorf("audit: write archive %q: %w", path, err)
	}
	return path, nil
}

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

// RetentionWorker archives audit records older than Retention and advances the
// live audit-query floor while preserving the AN-2 source envelopes needed for
// projection rebuild. One run, per tenant: take the leading due records, sign
// them as an offline-verifiable bundle, VERIFY it, archive it, SEAL the survivors'
// chain checkpoint, and emit an audit event. Search starts after the checkpoint,
// so the segment leaves the served hot view; JetStream retains it for recovery.
type RetentionWorker struct {
	svc       *Service
	log       *events.Log
	archiver  Archiver
	sink      CheckpointSink
	retention time.Duration
	now       func() time.Time
}

// NewRetentionWorker constructs the worker. svc must be the audit service wired
// with the same checkpoint source as sink, so a run's freshly sealed boundary is
// the anchor the next query and the next run see.
func NewRetentionWorker(svc *Service, log *events.Log, archiver Archiver, sink CheckpointSink, retention time.Duration) *RetentionWorker {
	return &RetentionWorker{svc: svc, log: log, archiver: archiver, sink: sink, retention: retention, now: time.Now}
}

// RunOnce performs one retention pass across all tenants and reports what it did.
// A nil/zero retention is a no-op. It is bounded by the caller (the server runs it
// on the AN-7 background cadence, not per request).
func (w *RetentionWorker) RunOnce(ctx context.Context) (Summary, error) {
	var sum Summary
	if w.retention <= 0 {
		return sum, nil
	}
	cutoff := w.now().Add(-w.retention)
	tenants, err := w.liveTenants(ctx)
	if err != nil {
		return sum, err
	}
	for _, tenant := range tenants {
		n, err := w.archiveTenant(ctx, tenant, cutoff)
		if err != nil {
			return sum, fmt.Errorf("audit retention: tenant %s: %w", tenant, err)
		}
		if n > 0 {
			sum.TenantsProcessed++
			sum.SegmentsArchived++
			sum.RecordsArchived += n
			sum.RecordsSourceRetained += n
		}
	}
	return sum, nil
}

// liveTenants returns the distinct tenants that currently have events in the log.
func (w *RetentionWorker) liveTenants(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	err := w.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != "" && !seen[e.TenantID] {
			seen[e.TenantID] = true
			out = append(out, e.TenantID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// archiveTenant archives one tenant's records older than cutoff, advances the
// logical live-query floor, and returns how many were processed.
func (w *RetentionWorker) archiveTenant(ctx context.Context, tenantID string, cutoff time.Time) (int, error) {
	var archived int
	err := w.log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		var err error
		archived, err = w.archiveTenantUnderOperation(operationCtx, tenantID, cutoff)
		return err
	})
	return archived, err
}

func (w *RetentionWorker) archiveTenantUnderOperation(
	ctx context.Context,
	tenantID string,
	cutoff time.Time,
) (int, error) {
	// A legacy process may have physically pruned the shared source after sealing a
	// checkpoint. Never finish that destructive operation: prove the complete
	// tenant prefix is still present before advancing retention. Missing source
	// history is a rebuild/DR blocker and must remain visible.
	if w.svc.checkpoints != nil {
		checkpoint, ok, err := w.svc.checkpoints.LatestAuditCheckpoint(ctx, tenantID)
		if err != nil {
			return 0, err
		}
		if ok {
			if err := VerifyCheckpointSourceRetained(ctx, w.log, checkpoint); err != nil {
				return 0, err
			}
			if err := w.ensureArchivedEvent(ctx, checkpoint); err != nil {
				return 0, err
			}
		}
	}

	var (
		segment  []Record
		boundary Record
		uri      string
	)
	// Pin one shared generation from Search through signed archive durability.
	// The outer operation lock prevents another retention/rewrite operation from
	// cutting over after this view releases and before the checkpoint is sealed.
	err := w.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		// Survivors past the last sealed boundary, already hash-linked from it.
		recs, err := w.svc.Search(readCtx, Query{TenantID: tenantID})
		if err != nil {
			return err
		}
		// The archivable segment is the leading run older than the cutoff. Taking a
		// contiguous-by-sequence prefix guarantees the remaining suffix is a clean
		// continuation whose hashes are unchanged.
		k := 0
		for k < len(recs) && !recs[k].Time.After(cutoff) {
			k++
		}
		if k == 0 {
			return nil
		}
		segment = recs[:k]
		boundary = segment[len(segment)-1]

		// The seed the survivors (and thus this segment) were hashed from — the prior
		// checkpoint's boundary, or genesis.
		_, prevSeed, _, err := w.svc.searchSeed(readCtx, tenantID)
		if err != nil {
			return err
		}
		if boundary.StreamSequence == 0 {
			return errors.New("audit: retention boundary is missing stream sequence")
		}

		// 1) Archive: sign the segment as a self-contained, offline-verifiable bundle.
		signed, err := w.signSegment(tenantID, prevSeed, boundary.Hash, segment)
		if err != nil {
			return err
		}
		// 2) Verify it recovers and its chain checks out BEFORE advancing the
		// served-view checkpoint.
		if _, err := VerifyRetentionBundle(signed, w.svc.VerificationKeys()); err != nil {
			return fmt.Errorf("archived segment failed verification — checkpoint not advanced: %w", err)
		}
		uri, err = w.archiver.Archive(readCtx, tenantID, boundary.Sequence, signed)
		return err
	})
	if err != nil {
		return 0, err
	}
	if len(segment) == 0 {
		return 0, nil
	}
	checkpoint := Checkpoint{
		TenantID: tenantID, BoundarySeq: boundary.StreamSequence, BoundaryHash: boundary.Hash,
		RecordCount: int(boundary.Sequence), ArchiveURI: uri, // #nosec G115 -- event sequence/count fits int64 by construction; bounded by the log (CWE-190)
	}
	for _, r := range segment {
		if r.StreamSequence == 0 {
			return 0, fmt.Errorf("audit: record %d missing stream sequence", r.Sequence)
		}
	}
	// 3) Append the replayable checkpoint event first. If PostgreSQL fails next,
	// projection/retry can reconstruct the row from this deterministic event.
	if err := w.ensureArchivedEvent(ctx, checkpoint); err != nil {
		return 0, err
	}
	// 4) Seal the logical audit-query boundary. SaveAuditCheckpoint takes the
	// shared backup fence in production, so a full backup includes either the old
	// checkpoint or this one while the complete event source is identical.
	if err := w.sink.SaveAuditCheckpoint(ctx, checkpoint); err != nil {
		return 0, err
	}
	return len(segment), nil
}

func (w *RetentionWorker) ensureArchivedEvent(ctx context.Context, checkpoint Checkpoint) error {
	found := false
	if err := w.log.Replay(ctx, checkpoint.BoundarySeq+1, func(event events.Event) error {
		if event.TenantID != checkpoint.TenantID || event.Type != EventTypeArchived {
			return nil
		}
		var payload ArchivedEvent
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return fmt.Errorf("decode audit archive event at sequence %d: %w", event.Sequence, err)
		}
		if event.SchemaVersion == ArchivedEventSchemaVersion &&
			payload.SourceHistoryRetained &&
			payload.BoundarySeq == checkpoint.BoundarySeq &&
			payload.BoundaryHash == checkpoint.BoundaryHash &&
			payload.ArchiveURI == checkpoint.ArchiveURI &&
			payload.Count == checkpoint.RecordCount {
			found = true
		}
		return nil
	}); err != nil {
		return err
	}
	if found {
		return nil
	}
	payload := ArchivedEvent{
		Count:                 checkpoint.RecordCount,
		BoundarySeq:           checkpoint.BoundarySeq,
		BoundaryHash:          checkpoint.BoundaryHash,
		ArchiveURI:            checkpoint.ArchiveURI,
		SourceHistoryRetained: true,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	idDigest := crypto.SHA256Hex([]byte(fmt.Sprintf(
		"%s\x00%d\x00%s\x00%s",
		checkpoint.TenantID,
		checkpoint.BoundarySeq,
		checkpoint.BoundaryHash,
		checkpoint.ArchiveURI,
	)))
	if _, err := w.log.Append(ctx, events.Event{
		ID:            "audit-archive-" + idDigest,
		Type:          EventTypeArchived,
		TenantID:      checkpoint.TenantID,
		SchemaVersion: ArchivedEventSchemaVersion,
		Data:          data,
	}); err != nil {
		return fmt.Errorf("append archive event: %w", err)
	}
	return nil
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

// signSegment marshals and signs the segment as a continuation Bundle whose
// PrevHash chains it onto the previous archived segment (or genesis).
func (w *RetentionWorker) signSegment(tenantID, prevHash, head string, segment []Record) (string, error) {
	payload, err := json.Marshal(Bundle{
		TenantID:    tenantID,
		GeneratedAt: w.now().UTC(),
		Query:       Query{TenantID: tenantID},
		Records:     segment,
		Count:       len(segment),
		PrevHash:    prevHash,
		ChainHead:   head,
	})
	if err != nil {
		return "", err
	}
	return w.svc.signer.SignArtifact(jose.ArtifactAuditRetention, payload)
}
