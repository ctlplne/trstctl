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

	"trstctl.com/trstctl/internal/events"
)

// EventTypeArchived is the event appended after a retention run, recording that a
// segment of audit records was archived to cold storage and pruned from the hot
// log. It is itself an audit record (a survivor of the prune), so the action is
// observable in the trail it maintains.
const EventTypeArchived = "audit.archived"

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

// retentionEvent is the payload of an EventTypeArchived event.
type retentionEvent struct {
	Count        int    `json:"count"`
	BoundarySeq  uint64 `json:"boundary_sequence"`
	BoundaryHash string `json:"boundary_hash"`
	ArchiveURI   string `json:"archive_uri"`
}

// Summary reports what a retention run did — surfaced as metrics by the server.
type Summary struct {
	TenantsProcessed int
	SegmentsArchived int
	RecordsArchived  int
	RecordsPruned    int
}

// RetentionWorker archives and prunes audit records older than Retention while
// keeping the tamper-evident chain verifiable across the prune (R4.4). It is the
// runtime consumer that makes Audit.Retention/ArchiveDir do real work instead of
// being inert config. One run, per tenant: take the leading run of records older
// than the window, sign it as an offline-verifiable bundle, VERIFY it recovers,
// archive it to cold storage, SEAL a signed checkpoint (the survivors' new chain
// anchor), then DELETE those events from the hot log and emit an audit event. The
// archived bundle plus the live log remain the authoritative history.
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
			sum.RecordsPruned += n
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

// archiveTenant archives+prunes one tenant's records older than cutoff and returns
// how many were processed (0 if nothing was due).
func (w *RetentionWorker) archiveTenant(ctx context.Context, tenantID string, cutoff time.Time) (int, error) {
	// Survivors past the last sealed boundary, already hash-linked from it.
	recs, err := w.svc.Search(ctx, Query{TenantID: tenantID})
	if err != nil {
		return 0, err
	}
	// The archivable segment is the leading run older than the cutoff. Taking a
	// contiguous-by-sequence prefix guarantees the remaining suffix is a clean
	// continuation whose hashes are unchanged.
	k := 0
	for k < len(recs) && !recs[k].Time.After(cutoff) {
		k++
	}
	if k == 0 {
		return 0, nil
	}
	segment := recs[:k]
	boundary := segment[len(segment)-1]

	// The seed the survivors (and thus this segment) were hashed from — the prior
	// checkpoint's boundary, or genesis.
	_, prevSeed, err := w.svc.searchSeed(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	// 1) Archive: sign the segment as a self-contained, offline-verifiable bundle.
	signed, err := w.signSegment(tenantID, prevSeed, boundary.Hash, segment)
	if err != nil {
		return 0, err
	}
	// 2) Verify it recovers and its chain checks out BEFORE pruning anything.
	if _, err := VerifyBundle(signed, w.svc.VerificationKeys()); err != nil {
		return 0, fmt.Errorf("archived segment failed verification — not pruning: %w", err)
	}
	uri, err := w.archiver.Archive(ctx, tenantID, boundary.Sequence, signed)
	if err != nil {
		return 0, err
	}
	// 3) Seal the checkpoint — the survivors' new chain anchor.
	if err := w.sink.SaveAuditCheckpoint(ctx, Checkpoint{
		TenantID: tenantID, BoundarySeq: boundary.Sequence, BoundaryHash: boundary.Hash,
		RecordCount: len(segment), ArchiveURI: uri,
	}); err != nil {
		return 0, err
	}
	// 4) Prune the archived events from the hot log (the only delete in the system,
	// and only after archive+verify+seal — AN-2 exception, R4.4).
	for _, r := range segment {
		if err := w.log.Delete(ctx, r.Sequence); err != nil {
			return 0, fmt.Errorf("prune seq %d: %w", r.Sequence, err)
		}
	}
	// 5) Emit an audit event recording the run (observable and itself auditable).
	data, err := json.Marshal(retentionEvent{
		Count: len(segment), BoundarySeq: boundary.Sequence, BoundaryHash: boundary.Hash, ArchiveURI: uri,
	})
	if err != nil {
		return 0, err
	}
	if _, err := w.log.Append(ctx, events.Event{Type: EventTypeArchived, TenantID: tenantID, Data: data}); err != nil {
		return 0, fmt.Errorf("append archive event: %w", err)
	}
	return len(segment), nil
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
	return w.svc.signer.Sign(payload)
}
