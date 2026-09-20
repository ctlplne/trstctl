// SPDX-License-Identifier: BUSL-1.1

// Package backup serializes the event log — the AN-2 source of truth — to a
// portable, versioned, INTEGRITY-PROTECTED stream, and restores it into a fresh
// log. Because the relational read model is a pure projection of the log (R1.1),
// restoring the log and rebuilding the projections reconstructs the whole control
// plane after a disaster (R2.4). The backup carries the full event envelope,
// including the recorded actor (R2.1), so the recovered audit trail is intact.
//
// Integrity (OPS-006). A backup is a disaster-recovery artifact for a credential
// and audit platform; a tampered or truncated backup that restores without
// complaint is an integrity hole. Every stream therefore ends with a trailer line
// carrying a SHA-256 over all preceding bytes (header + records), so a bit-flip,
// a truncation, or a removed record is detected on restore and rejected
// fail-closed. When an integrity key is supplied (WriteLogWithKey), the trailer
// also carries an HMAC-SHA256 over the same bytes, so an attacker who can rewrite
// the stream cannot forge a matching trailer without the key. All hashing/MAC
// routes through the crypto boundary (internal/crypto, AN-3).
package backup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/schedulerhistory"
)

const (
	formatTag  = "trstctl-event-log-backup"
	trailerTag = "trstctl-event-log-backup-trailer"
	version    = 1 // legacy contiguous format; retained for safe v1 reads
)

const (
	exactHistoryVersion = 2
	exactHistoryLayout  = "exact-sequence-v1"
)

// ErrRestoreTargetNotEmpty means a restore was pointed at a log that already
// contains events. Plain --restore keeps failing closed on this error; full DR
// restore can catch it and perform an explicit byte-for-byte resume check.
var ErrRestoreTargetNotEmpty = errors.New("backup: restore target log is not empty (restore into a fresh event store)")

// EventLogBackupSummary is the mutation-free structural preflight result for one
// event artifact. Full restore compares EventCutSequence with the independently
// verified PostgreSQL artifact before either datastore is changed.
type EventLogBackupSummary struct {
	EventCutSequence    uint64
	Records             int
	HistoryEntries      int
	ExactSequenceLayout bool
	HasGaps             bool
}

// header is the first line of a backup stream — a self-describing, versioned
// envelope so a restore can refuse a stranger's file or a future format.
type header struct {
	Format           string    `json:"format"`
	Version          int       `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	EventCutSequence uint64    `json:"event_cut_sequence,omitempty"`
	HistoryLayout    string    `json:"history_layout,omitempty"`
}

// record is one exact event-log position as written to the backup. New backups
// carry kind+sequence+subject+message_id+stored, while retaining the decoded event
// fields so an older reader can still safely restore a contiguous stream. A gap
// record carries sequence..gap_through and no event fields; older readers reject
// it because type and tenant_id are absent instead of silently renumbering it.
type record struct {
	Kind          string          `json:"kind,omitempty"`
	Sequence      uint64          `json:"sequence,omitempty"`
	GapThrough    uint64          `json:"gap_through,omitempty"`
	Subject       string          `json:"subject,omitempty"`
	MessageID     string          `json:"message_id,omitempty"`
	Stored        []byte          `json:"stored,omitempty"`
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	TenantID      string          `json:"tenant_id"`
	SchemaVersion int             `json:"v,omitempty"`
	Time          time.Time       `json:"time"`
	Data          json.RawMessage `json:"data,omitempty"`
	Actor         *events.Actor   `json:"actor,omitempty"`
}

// trailer is the final line of a backup stream — the integrity check over every
// byte that precedes it (OPS-006). SHA256 is always present; HMACSHA256 is present
// only when the backup was written with an integrity key. Records is the event
// count, a cheap structural cross-check.
type trailer struct {
	Format           string `json:"format"`
	SHA256           string `json:"sha256"`
	HMACSHA256       string `json:"hmac_sha256,omitempty"`
	Records          int    `json:"records"`
	Entries          int    `json:"entries,omitempty"`
	EventCutSequence uint64 `json:"event_cut_sequence,omitempty"`
	HistoryLayout    string `json:"history_layout,omitempty"`
}

// WriteLog streams every event in log to w as a versioned, SHA-256-integrity-
// protected backup and returns the count. The format is newline-delimited JSON: a
// header line, one record per event in append order, and a trailing integrity
// line. It is equivalent to WriteLogWithKey(ctx, log, w, nil) — a keyless
// (checksum-only) backup.
func WriteLog(ctx context.Context, log *events.Log, w io.Writer) (int, error) {
	return WriteLogWithKey(ctx, log, w, nil)
}

// WriteLogWithKey is WriteLog with an optional integrity key. When key is
// non-empty the trailer additionally carries an HMAC-SHA256 over the stream,
// binding the backup to the key so a tamperer who can recompute the SHA-256
// cannot forge the trailer. The MAC routes through the crypto boundary (AN-3).
func WriteLogWithKey(ctx context.Context, log *events.Log, w io.Writer, key []byte) (int, error) {
	cut, err := log.LastSequence(ctx)
	if err != nil {
		return 0, err
	}
	return WriteLogWithKeyThrough(ctx, log, w, key, cut)
}

// VerifyEventLogBackup verifies a checksum-only event artifact without mutating a
// target log. A keyed artifact's SHA-256 is checked, but callers that possess the
// deployment integrity key should use VerifyEventLogBackupWithKey to require its
// HMAC as well.
func VerifyEventLogBackup(r io.Reader) (EventLogBackupSummary, error) {
	return VerifyEventLogBackupWithKey(r, nil)
}

// VerifyEventLogBackupWithKey performs the same spool-backed integrity,
// structure, exact-order, and gap validation as RestoreLogWithKey, then returns
// the declared cut. It never opens or writes NATS.
func VerifyEventLogBackupWithKey(r io.Reader, key []byte) (EventLogBackupSummary, error) {
	return VerifyEventLogBackupWithAuditCheckpoints(r, key, nil)
}

// VerifyEventLogBackupWithAuditCheckpoints performs the normal mutation-free
// event-artifact verification and additionally proves every logical
// audit-retention checkpoint still has its complete tenant source prefix. Full
// restore supplies the independently authenticated PostgreSQL checkpoint
// summaries here before it changes any file or datastore.
func VerifyEventLogBackupWithAuditCheckpoints(
	r io.Reader,
	key []byte,
	checkpoints []AuditCheckpointBoundary,
) (EventLogBackupSummary, error) {
	h, spool, tr, err := readAndVerify(r, key)
	if err != nil {
		return EventLogBackupSummary{}, err
	}
	defer spool.cleanup()
	if err := validateVerifiedStream(h, tr, spool.records, spool.entries); err != nil {
		return EventLogBackupSummary{}, err
	}
	summary := EventLogBackupSummary{
		EventCutSequence:    h.EventCutSequence,
		Records:             spool.records,
		HistoryEntries:      spool.entries,
		ExactSequenceLayout: h.HistoryLayout == exactHistoryLayout,
		HasGaps:             h.EventCutSequence > uint64(spool.records), // #nosec G115 -- record counts bounded by the event log; fits both int and uint64 (CWE-190)
	}
	if err := verifyCheckpointPrefixesInSpool(h, spool, checkpoints); err != nil {
		return EventLogBackupSummary{}, err
	}
	return summary, nil
}

func verifyCheckpointPrefixesInSpool(
	h header,
	spool *restoreSpool,
	checkpoints []AuditCheckpointBoundary,
) error {
	if len(checkpoints) == 0 {
		return nil
	}
	byTenant := make(map[string]AuditCheckpointBoundary, len(checkpoints))
	for _, checkpoint := range checkpoints {
		if checkpoint.TenantID == "" || checkpoint.BoundarySeq == 0 ||
			checkpoint.RecordCount <= 0 || checkpoint.BoundarySeq > h.EventCutSequence {
			return fmt.Errorf(
				"backup: audit checkpoint for tenant %q is outside event cut %d or incomplete",
				checkpoint.TenantID, h.EventCutSequence,
			)
		}
		if prior, ok := byTenant[checkpoint.TenantID]; ok &&
			prior.BoundarySeq != checkpoint.BoundarySeq {
			return fmt.Errorf("backup: duplicate latest audit checkpoint for tenant %s", checkpoint.TenantID)
		}
		byTenant[checkpoint.TenantID] = checkpoint
	}
	if err := spool.rewind(); err != nil {
		return err
	}
	counts := make(map[string]int, len(byTenant))
	sc := bufio.NewScanner(bufio.NewReader(spool.file))
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	legacySequence := uint64(0)
	for sc.Scan() {
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("backup: decode retained-source record: %w", err)
		}
		sequence := rec.Sequence
		if h.HistoryLayout == "" {
			legacySequence++
			sequence = legacySequence
		}
		checkpoint, ok := byTenant[rec.TenantID]
		if !ok || rec.Kind == "gap" || sequence > checkpoint.BoundarySeq {
			continue
		}
		counts[rec.TenantID]++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("backup: scan retained-source records: %w", err)
	}
	for tenantID, checkpoint := range byTenant {
		if counts[tenantID] != checkpoint.RecordCount {
			return fmt.Errorf(
				"backup: audit checkpoint source history is incomplete for tenant %s: artifact retains %d of %d events through sequence %d; refusing before any restore mutation",
				tenantID, counts[tenantID], checkpoint.RecordCount, checkpoint.BoundarySeq,
			)
		}
	}
	return nil
}

// WriteLogThrough writes a log backup bounded to event sequence cut. Events
// appended after cut are deliberately excluded, giving full DR a single event-log
// boundary to pair with the PostgreSQL state artifact.
func WriteLogThrough(ctx context.Context, log *events.Log, w io.Writer, cut uint64) (int, error) {
	return WriteLogWithKeyThrough(ctx, log, w, nil, cut)
}

// WriteLogWithKeyThrough is WriteLogThrough with optional HMAC integrity.
func WriteLogWithKeyThrough(ctx context.Context, log *events.Log, w io.Writer, key []byte, cut uint64) (int, error) {
	if log == nil {
		return 0, errors.New("backup: event log is required")
	}
	var records int
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		// Inspect the complete pinned cut before emitting even the header. A writer
		// cannot retract bytes, so detecting the unsafe record while streaming would
		// already have created a partial export artifact.
		if err := log.ExportBackupHistoryThrough(readCtx, cut, func(history events.BackupHistoryRecord) error {
			if history.IsGap() {
				return nil
			}
			version := history.Event.SchemaVersion
			if version == 0 {
				version = schedulerhistory.LegacySchemaVersion
			}
			unsafe, inspectErr := schedulerhistory.RequiresSanitation(
				history.Event.Type, version, history.Event.Data,
			)
			if inspectErr != nil || unsafe {
				return schedulerhistory.ErrSanitationRequired
			}
			return nil
		}); err != nil {
			return err
		}
		var err error
		records, err = writeSanitizedLogWithKeyThrough(readCtx, log, w, key, cut)
		return err
	})
	return records, err
}

func writeSanitizedLogWithKeyThrough(ctx context.Context, log *events.Log, w io.Writer, key []byte, cut uint64) (int, error) {
	bw := bufio.NewWriter(w)
	// Tee every byte we write into a digest so the trailer covers the exact stream.
	dig := newDigest(key)
	mw := io.MultiWriter(bw, dig)
	enc := json.NewEncoder(mw)

	if err := enc.Encode(header{
		Format: formatTag, Version: exactHistoryVersion, CreatedAt: time.Now().UTC(),
		EventCutSequence: cut, HistoryLayout: exactHistoryLayout,
	}); err != nil {
		return 0, err
	}
	records := 0
	entries := 0
	err := log.ExportBackupHistoryThrough(ctx, cut, func(history events.BackupHistoryRecord) error {
		rec := record{
			Sequence:   history.Sequence,
			GapThrough: history.GapThrough,
		}
		if history.IsGap() {
			rec.Kind = "gap"
		} else {
			rec.Kind = "event"
			rec.Subject = history.Subject
			rec.MessageID = history.MessageID
			rec.Stored = append([]byte(nil), history.Stored...)
			rec.ID = history.Event.ID
			rec.Type = history.Event.Type
			rec.TenantID = history.Event.TenantID
			rec.SchemaVersion = history.Event.SchemaVersion
			rec.Time = history.Event.Time
			rec.Data = json.RawMessage(history.Event.Data)
			rec.Actor = history.Event.Actor
			records++
		}
		if err := writeRecordLine(mw, rec); err != nil {
			return err
		}
		entries++
		return nil
	})
	if err != nil {
		return records, err
	}

	// The trailer is written to bw only (NOT into the digest): it carries the hash
	// of everything before it.
	tr := trailer{
		Format: trailerTag, SHA256: dig.sumHex(), Records: records, Entries: entries,
		EventCutSequence: cut, HistoryLayout: exactHistoryLayout,
	}
	if len(key) > 0 {
		tr.HMACSHA256 = dig.macHex()
	}
	if err := json.NewEncoder(bw).Encode(tr); err != nil {
		return records, err
	}
	return records, bw.Flush()
}

// writeRecordLine keeps the decoded data field byte-identical to the event data
// inside Stored. encoding/json normally compacts a json.RawMessage returned by a
// Marshaler, which would make the redundant legacy-compatible fields disagree
// with the authoritative stored envelope for JSON containing whitespace.
func writeRecordLine(w io.Writer, rec record) error {
	data := append(json.RawMessage(nil), rec.Data...)
	rec.Data = nil
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		if !json.Valid(data) {
			return errors.New("backup: event data is not valid JSON")
		}
		line = append(line[:len(line)-1], []byte(`,"data":`)...)
		line = append(line, data...)
		line = append(line, '}')
	}
	line = append(line, '\n')
	if _, err := w.Write(line); err != nil {
		return err
	}
	return nil
}

// RestoreLog reads a backup stream from r, VERIFIES its integrity trailer, and —
// only if the trailer matches — appends its events, in order, into log, which must
// be empty so a misdirected restore cannot duplicate a stream. It preserves each
// event's id, time, and actor; the sequence is reassigned contiguously by the log.
// It is equivalent to RestoreLogWithKey(ctx, log, r, nil): it accepts a
// checksum-only backup, and accepts a keyed backup but does not verify its MAC.
// Use RestoreLogWithKey to require a valid MAC. A truncated, bit-flipped, or
// trailer-less stream is rejected fail-closed.
func RestoreLog(ctx context.Context, log *events.Log, r io.Reader) (int, error) {
	return RestoreLogWithKey(ctx, log, r, nil)
}

// RestoreLogWithKey is RestoreLog that additionally requires a valid HMAC-SHA256
// under key: a backup written without a MAC, or whose MAC does not verify, is
// rejected. The integrity check (SHA-256 and, when key is set, the MAC) is
// performed BEFORE any event is appended, so a tampered backup never mutates the
// target log.
func RestoreLogWithKey(ctx context.Context, log *events.Log, r io.Reader, key []byte) (int, error) {
	// Parse and verify the stream while spooling record lines to disk. We still
	// verify integrity BEFORE appending anything, but memory stays bounded by the
	// largest line rather than the whole backup.
	h, spool, tr, err := readAndVerify(r, key)
	if err != nil {
		return 0, err
	}
	defer spool.cleanup()
	if err := validateVerifiedStream(h, tr, spool.records, spool.entries); err != nil {
		return 0, err
	}

	if h.HistoryLayout == exactHistoryLayout {
		n, err := restoreExactHistory(
			ctx, log, h.EventCutSequence, tr.SHA256, key, spool,
		)
		if errors.Is(err, events.ErrBackupHistoryPrefixMismatch) {
			return n, errors.Join(ErrRestoreTargetNotEmpty, err)
		}
		return n, err
	}

	// A legacy artifact has already passed checksum/HMAC and contiguous 1..N
	// validation. Convert it to the existing exact restore source instead of
	// exposing a second append API that could bypass the live schema floor.
	n, err := restoreVerifiedBackupHistory(
		ctx, log, h.EventCutSequence, tr.SHA256, key,
		func(yield func(events.BackupHistoryRecord) error) error {
			if err := spool.rewind(); err != nil {
				return err
			}
			sc := bufio.NewScanner(bufio.NewReader(spool.file))
			sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
			sequence := uint64(0)
			for sc.Scan() {
				sequence++
				var rec record
				if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
					return fmt.Errorf("backup: replay spooled record %d: %w", sequence, err)
				}
				history, err := events.LegacyBackupHistoryRecord(ctx, sequence, events.Event{
					ID: rec.ID, Type: rec.Type, TenantID: rec.TenantID,
					SchemaVersion: rec.SchemaVersion, Time: rec.Time,
					Data: []byte(rec.Data), Actor: rec.Actor,
				})
				if err != nil {
					return fmt.Errorf("backup: prepare legacy record %d: %w", sequence, err)
				}
				if err := yield(history); err != nil {
					return err
				}
			}
			return sc.Err()
		})
	if errors.Is(err, events.ErrBackupHistoryPrefixMismatch) || errors.Is(err, events.ErrBackupHistoryNotPristine) {
		return n, errors.Join(ErrRestoreTargetNotEmpty, err)
	}
	return n, err
}

func restoreExactHistory(
	ctx context.Context,
	log *events.Log,
	cut uint64,
	artifactDigest string,
	key []byte,
	spool *restoreSpool,
) (int, error) {
	n, err := restoreVerifiedBackupHistory(
		ctx, log, cut, artifactDigest, key,
		func(yield func(events.BackupHistoryRecord) error) error {
			if err := spool.rewind(); err != nil {
				return err
			}
			sc := bufio.NewScanner(bufio.NewReader(spool.file))
			sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
			entry := 0
			for sc.Scan() {
				entry++
				var rec record
				if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
					return fmt.Errorf("backup: replay spooled entry %d: %w", entry, err)
				}
				history := events.BackupHistoryRecord{
					Sequence:   rec.Sequence,
					GapThrough: rec.GapThrough,
					Subject:    rec.Subject,
					MessageID:  rec.MessageID,
					Stored:     append([]byte(nil), rec.Stored...),
				}
				if err := yield(history); err != nil {
					return err
				}
			}
			if err := sc.Err(); err != nil {
				return fmt.Errorf("backup: replay spooled exact history: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return n, fmt.Errorf("backup: restore exact event history: %w", err)
	}
	return n, nil
}

// VerifyLogMatchesWithKey verifies a backup stream and compares it to a log that
// is already populated, without appending anything. Full restore uses this as its
// resume proof after an interrupted first attempt: same backup + same log means it
// can continue to PostgreSQL import; any different stream is a new restore and
// fails closed.
func VerifyLogMatchesWithKey(ctx context.Context, log *events.Log, r io.Reader, key []byte) (int, error) {
	h, spool, tr, err := readAndVerify(r, key)
	if err != nil {
		return 0, err
	}
	defer spool.cleanup()
	if err := validateVerifiedStream(h, tr, spool.records, spool.entries); err != nil {
		return 0, err
	}
	if err := spool.rewind(); err != nil {
		return 0, err
	}
	if h.HistoryLayout == exactHistoryLayout {
		return verifyExactHistoryMatches(ctx, log, h.EventCutSequence, spool, tr)
	}
	sc := bufio.NewScanner(bufio.NewReader(spool.file))
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	n := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return fmt.Errorf("backup: resume compare stream: %w", err)
			}
			return fmt.Errorf("backup: resume mismatch: target log has more events than backup")
		}
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("backup: resume decode record %d: %w", n+1, err)
		}
		if !eventMatchesRecord(e, rec) {
			return fmt.Errorf("backup: resume mismatch at event %d", n+1)
		}
		n++
		return nil
	}); err != nil {
		return n, err
	}
	if sc.Scan() {
		return n, fmt.Errorf("backup: resume mismatch: backup has more events than target log")
	}
	if err := sc.Err(); err != nil {
		return n, fmt.Errorf("backup: resume compare stream: %w", err)
	}
	if n != tr.Records {
		return n, fmt.Errorf("backup: resume mismatch: matched %d events but trailer claims %d", n, tr.Records)
	}
	return n, nil
}

func restoreVerifiedBackupHistory(
	ctx context.Context,
	log *events.Log,
	cut uint64,
	artifactDigest string,
	key []byte,
	source events.BackupHistorySource,
) (int, error) {
	if len(key) == 0 {
		return log.RestoreBackupHistory(ctx, cut, artifactDigest, source)
	}
	historyDigest, err := events.BackupHistoryDigest(ctx, cut, source)
	if err != nil {
		return 0, fmt.Errorf("backup: digest verified restore history: %w", err)
	}
	authorization, err := crypto.BackupRestoreAuthorization(
		key,
		crypto.BackupRestoreIntent{
			EventCutSequence: cut,
			ArtifactSHA256:   artifactDigest,
			HistorySHA256:    historyDigest,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("backup: authorize verified artifact restore: %w", err)
	}
	defer authorization.Destroy()
	return log.RestoreAuthorizedBackupHistory(
		ctx, cut, artifactDigest, authorization, source,
	)
}

// SanitationReceiptVerifier cryptographically opens one history-continuity
// receipt and returns its signed report. The backup package owns exact artifact
// comparison; the caller owns the deployment audit key and signature policy.
type SanitationReceiptVerifier func(context.Context, events.Event) (events.TenantDataRewriteReport, error)

// VerifyLogMatchesSanitizedSchedulerHistoryWithKey is the only permitted
// non-exact full-restore resume proof. It first HMAC-verifies the original
// artifact, then permits precisely the deterministic AUD-116 error-token rewrite
// below its cut and one profiled, signed continuity receipt per affected tenant.
// VerifyLogMatchesWithKey remains byte-exact and is deliberately not weakened.
func VerifyLogMatchesSanitizedSchedulerHistoryWithKey(
	ctx context.Context,
	log *events.Log,
	r io.Reader,
	key []byte,
	verifyReceipt SanitationReceiptVerifier,
) (int, error) {
	if len(key) == 0 {
		return 0, errors.New("backup: scheduler sanitation resume requires an HMAC integrity key")
	}
	if verifyReceipt == nil {
		return 0, errors.New("backup: scheduler sanitation resume requires a continuity receipt verifier")
	}
	h, spool, tr, err := readAndVerify(r, key)
	if err != nil {
		return 0, err
	}
	defer spool.cleanup()
	if err := validateVerifiedStream(h, tr, spool.records, spool.entries); err != nil {
		return 0, err
	}
	if h.HistoryLayout != exactHistoryLayout {
		return 0, errors.New("backup: scheduler sanitation resume requires exact-sequence history")
	}
	var records int
	err = log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		if err := spool.rewind(); err != nil {
			return err
		}
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return fmt.Errorf("backup: scheduler sanitation resume read target head: %w", err)
		}
		if head <= h.EventCutSequence {
			return errors.New("backup: scheduler sanitation resume target is not a signed descendant")
		}

		scanner := bufio.NewScanner(bufio.NewReader(spool.file))
		scanner.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
		affected := make(map[string]int)
		var affectedOrder []string
		var receipts []events.BackupHistoryRecord
		var reports []events.TenantDataRewriteReport
		receiptIndex := 0
		entries := 0
		err = log.ExportBackupHistoryThrough(readCtx, head, func(history events.BackupHistoryRecord) error {
			if history.Sequence <= h.EventCutSequence {
				if !scanner.Scan() {
					return errors.New("backup: scheduler sanitation resume target has more source entries than artifact")
				}
				entries++
				var rec record
				if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
					return fmt.Errorf("backup: scheduler sanitation resume decode entry %d: %w", entries, err)
				}
				if history.IsGap() {
					if !historyMatchesRecord(history, rec) {
						return fmt.Errorf("backup: scheduler sanitation resume gap mismatch at entry %d", entries)
					}
					return nil
				}
				records++
				version := rec.SchemaVersion
				if version == 0 {
					version = schedulerhistory.LegacySchemaVersion
				}
				if rec.Type != schedulerhistory.EventType || version != schedulerhistory.LegacySchemaVersion {
					if !historyMatchesRecord(history, rec) {
						return fmt.Errorf("backup: scheduler sanitation resume changed unrelated entry %d", entries)
					}
					return nil
				}
				expectedData, changed, rewriteErr := schedulerhistory.RewriteLegacyRun(rec.Data)
				if rewriteErr != nil {
					return schedulerhistory.ErrSanitationRequired
				}
				if !changed {
					if !historyMatchesRecord(history, rec) {
						return fmt.Errorf("backup: scheduler sanitation resume changed canonical entry %d", entries)
					}
					return nil
				}
				affected[rec.TenantID]++
				if !sanitizedHistoryMatchesRecord(history, rec, expectedData) {
					return fmt.Errorf("backup: scheduler sanitation resume changed envelope semantics at entry %d", entries)
				}
				return nil
			}

			if affectedOrder == nil {
				if scanner.Scan() {
					return errors.New("backup: scheduler sanitation resume artifact has entries past its declared cut")
				}
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("backup: scheduler sanitation resume scan artifact: %w", err)
				}
				for tenantID := range affected {
					affectedOrder = append(affectedOrder, tenantID)
				}
				sort.Strings(affectedOrder)
			}
			if history.IsGap() || receiptIndex >= len(affectedOrder) {
				return errors.New("backup: scheduler sanitation resume has an unrelated post-cut entry")
			}
			report, verifyErr := verifyReceipt(readCtx, history.Event)
			if verifyErr != nil {
				return errors.New("backup: scheduler sanitation resume continuity receipt did not verify")
			}
			expectedTenant := affectedOrder[receiptIndex]
			if report.Profile != schedulerhistory.RewriteProfile ||
				history.Event.TenantID != expectedTenant || report.TenantID != expectedTenant ||
				report.ChangedEvents != affected[expectedTenant] ||
				report.ReceiptSequence != history.Sequence ||
				report.SourceCutSequence+1 != report.ReceiptSequence ||
				report.SourceCutSequence != h.EventCutSequence+uint64(receiptIndex) { // #nosec G115 -- receiptIndex starts at zero and is bounded by len(affectedOrder) above (CWE-190).
				return errors.New("backup: scheduler sanitation resume continuity receipt policy mismatch")
			}
			receipts = append(receipts, cloneBackupHistoryRecord(history))
			reports = append(reports, report)
			receiptIndex++
			return nil
		})
		if err != nil {
			return err
		}
		if scanner.Scan() {
			return errors.New("backup: scheduler sanitation resume artifact has unmatched history entries")
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("backup: scheduler sanitation resume scan artifact: %w", err)
		}
		if records != tr.Records || entries != tr.Entries || len(affected) == 0 ||
			receiptIndex != len(affectedOrder) {
			return errors.New("backup: scheduler sanitation resume cardinality mismatch")
		}

		activeStream, activeGeneration, err := log.ActiveHistoryIdentity(readCtx)
		if err != nil {
			return fmt.Errorf("backup: scheduler sanitation resume read active generation: %w", err)
		}
		if err := events.ValidateTenantDataRewriteLineage(reports, activeStream, activeGeneration); err != nil {
			return errors.New("backup: scheduler sanitation resume signed generation lineage mismatch")
		}
		affectedIndex := make(map[string]int, len(affectedOrder))
		for index, tenantID := range affectedOrder {
			affectedIndex[tenantID] = index
		}
		for index, report := range reports {
			pairs := schedulerHistoryRewriteProofPairs(
				spool, h.EventCutSequence, affectedIndex, index, receipts,
			)
			if err := events.VerifyTenantDataRewriteDigestProof(report, pairs); err != nil {
				return errors.New("backup: scheduler sanitation resume signed content proof mismatch")
			}
		}
		return nil
	})
	return records, err
}

func sanitizedHistoryMatchesRecord(
	history events.BackupHistoryRecord,
	rec record,
	expectedData []byte,
) bool {
	expected, err := backupHistoryRecordForProof(rec, expectedData)
	if err != nil || history.IsGap() || expected.IsGap() {
		return false
	}
	return history.Sequence == expected.Sequence && history.Subject == expected.Subject &&
		history.MessageID == expected.MessageID && bytes.Equal(history.Stored, expected.Stored)
}

func schedulerHistoryRewriteProofPairs(
	spool *restoreSpool,
	artifactCut uint64,
	affectedIndex map[string]int,
	stage int,
	receipts []events.BackupHistoryRecord,
) events.TenantDataRewriteHistoryPairs {
	return func(yield func(source, target events.BackupHistoryRecord) error) error {
		if yield == nil || spool == nil || stage < 0 || stage > len(receipts) {
			return errors.New("backup: scheduler sanitation proof source is incomplete")
		}
		if err := spool.rewind(); err != nil {
			return err
		}
		scanner := bufio.NewScanner(bufio.NewReader(spool.file))
		scanner.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
		for scanner.Scan() {
			var rec record
			if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
				return errors.New("backup: scheduler sanitation proof artifact record is malformed")
			}
			if rec.Sequence > artifactCut || (rec.Kind == "gap" && rec.GapThrough > artifactCut) {
				return errors.New("backup: scheduler sanitation proof artifact exceeds its cut")
			}
			index, affected := affectedIndex[rec.TenantID]
			version := rec.SchemaVersion
			if version == 0 {
				version = events.DefaultSchemaVersion
			}
			profiled := affected && rec.Type == schedulerhistory.EventType &&
				version == schedulerhistory.LegacySchemaVersion
			sourceData := rec.Data
			targetData := rec.Data
			if profiled && index < stage {
				var err error
				sourceData, _, err = schedulerhistory.RewriteLegacyRun(rec.Data)
				if err != nil {
					return schedulerhistory.ErrSanitationRequired
				}
			}
			if profiled && index <= stage {
				var err error
				targetData, _, err = schedulerhistory.RewriteLegacyRun(rec.Data)
				if err != nil {
					return schedulerhistory.ErrSanitationRequired
				}
			}
			source, err := backupHistoryRecordForProof(rec, sourceData)
			if err != nil {
				return err
			}
			target, err := backupHistoryRecordForProof(rec, targetData)
			if err != nil {
				return err
			}
			if err := yield(source, target); err != nil {
				return err
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("backup: scheduler sanitation proof scan artifact: %w", err)
		}
		for index := 0; index < stage; index++ {
			receipt := receipts[index]
			if err := yield(receipt, receipt); err != nil {
				return err
			}
		}
		return nil
	}
}

func backupHistoryRecordForProof(rec record, data []byte) (events.BackupHistoryRecord, error) {
	if rec.Kind == "gap" {
		return events.BackupHistoryRecord{Sequence: rec.Sequence, GapThrough: rec.GapThrough}, nil
	}
	version := rec.SchemaVersion
	if version == 0 {
		version = events.DefaultSchemaVersion
	}
	stored := rec.Stored
	if !bytes.Equal(data, rec.Data) {
		var err error
		stored, err = events.RewriteStoredEnvelopeDataExact(rec.Stored, rec.Data, data)
		if err != nil {
			return events.BackupHistoryRecord{}, fmt.Errorf("backup: rewrite scheduler sanitation proof envelope: %w", err)
		}
	}
	return events.BackupHistoryRecord{
		Sequence: rec.Sequence, Subject: rec.Subject, MessageID: rec.MessageID,
		Stored: append([]byte(nil), stored...),
		Event: events.Event{
			Sequence: rec.Sequence, ID: rec.ID, Type: rec.Type, TenantID: rec.TenantID,
			SchemaVersion: version, Time: rec.Time, Data: append([]byte(nil), data...), Actor: rec.Actor,
		},
	}, nil
}

func cloneBackupHistoryRecord(record events.BackupHistoryRecord) events.BackupHistoryRecord {
	clone := record
	clone.Stored = append([]byte(nil), record.Stored...)
	clone.Event.Data = append([]byte(nil), record.Event.Data...)
	return clone
}

func verifyExactHistoryMatches(
	ctx context.Context,
	log *events.Log,
	cut uint64,
	spool *restoreSpool,
	tr trailer,
) (int, error) {
	head, err := log.LastSequence(ctx)
	if err != nil {
		return 0, fmt.Errorf("backup: resume read target head: %w", err)
	}
	if head != cut {
		return 0, fmt.Errorf(
			"backup: resume mismatch: target head %d differs from backup cut %d",
			head, cut,
		)
	}
	sc := bufio.NewScanner(bufio.NewReader(spool.file))
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	entries := 0
	records := 0
	err = log.ExportBackupHistoryThrough(ctx, cut, func(history events.BackupHistoryRecord) error {
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return fmt.Errorf("backup: resume compare exact stream: %w", err)
			}
			return errors.New("backup: resume mismatch: target history has more entries than backup")
		}
		entries++
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("backup: resume decode entry %d: %w", entries, err)
		}
		if !historyMatchesRecord(history, rec) {
			return fmt.Errorf(
				"backup: resume mismatch at exact history entry %d (sequence %d)",
				entries, history.Sequence,
			)
		}
		if !history.IsGap() {
			records++
		}
		return nil
	})
	if err != nil {
		return records, err
	}
	if sc.Scan() {
		return records, errors.New("backup: resume mismatch: backup has more history entries than target")
	}
	if err := sc.Err(); err != nil {
		return records, fmt.Errorf("backup: resume compare exact stream: %w", err)
	}
	if records != tr.Records || entries != tr.Entries {
		return records, fmt.Errorf(
			"backup: resume mismatch: matched %d records/%d entries but trailer claims %d/%d",
			records, entries, tr.Records, tr.Entries,
		)
	}
	return records, nil
}

func historyMatchesRecord(history events.BackupHistoryRecord, rec record) bool {
	if history.Sequence != rec.Sequence || history.GapThrough != rec.GapThrough {
		return false
	}
	if history.IsGap() {
		return rec.Kind == "gap"
	}
	return rec.Kind == "event" &&
		history.Subject == rec.Subject &&
		history.MessageID == rec.MessageID &&
		bytes.Equal(history.Stored, rec.Stored)
}

func validateVerifiedStream(h header, tr trailer, records, entries int) error {
	if h.Format != formatTag {
		return fmt.Errorf("backup: not a trstctl event-log backup (format %q)", h.Format)
	}
	if h.Version != version && h.Version != exactHistoryVersion {
		return fmt.Errorf(
			"backup: unsupported backup version %d (want %d or legacy %d)",
			h.Version, exactHistoryVersion, version,
		)
	}
	if h.EventCutSequence != tr.EventCutSequence {
		return fmt.Errorf("backup: integrity: header event cut %d but trailer event cut %d", h.EventCutSequence, tr.EventCutSequence)
	}
	if h.HistoryLayout != tr.HistoryLayout {
		return fmt.Errorf(
			"backup: integrity: header history layout %q but trailer history layout %q",
			h.HistoryLayout, tr.HistoryLayout,
		)
	}
	if tr.Records != records {
		return fmt.Errorf("backup: integrity: trailer claims %d records but stream has %d", tr.Records, records)
	}
	switch h.HistoryLayout {
	case exactHistoryLayout:
		if h.Version != exactHistoryVersion {
			return fmt.Errorf(
				"backup: legacy version %d cannot declare exact history layout %q",
				h.Version, h.HistoryLayout,
			)
		}
		if tr.Entries != entries {
			return fmt.Errorf(
				"backup: integrity: trailer claims %d history entries but stream has %d",
				tr.Entries, entries,
			)
		}
	case "":
		if h.Version != version {
			return fmt.Errorf(
				"backup: version %d is missing required exact history layout",
				h.Version,
			)
		}
		// Legacy v1 records did not carry sequence, subject, or gap identity. They
		// are safe to restore only when the cut proves a contiguous 1..N stream;
		// otherwise renumbering would detach PostgreSQL checkpoint boundaries.
		if entries != records || h.EventCutSequence != uint64(records) { // #nosec G115 -- record counts bounded by the event log; fits both int and uint64 (CWE-190)
			return fmt.Errorf(
				"backup: legacy event history lacks exact sequences/gaps (cut=%d records=%d); refusing unsafe restore",
				h.EventCutSequence, records,
			)
		}
	default:
		return fmt.Errorf("backup: unsupported history layout %q", h.HistoryLayout)
	}
	return nil
}

func eventMatchesRecord(e events.Event, rec record) bool {
	if e.ID != rec.ID || e.Type != rec.Type || e.TenantID != rec.TenantID || e.SchemaVersion != rec.SchemaVersion {
		return false
	}
	if !e.Time.Equal(rec.Time) {
		return false
	}
	if !rawJSONEqual(e.Data, rec.Data) {
		return false
	}
	return reflect.DeepEqual(e.Actor, rec.Actor)
}

func rawJSONEqual(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

func validateDecodedRecord(h header, rec record, covered *uint64) (bool, error) {
	if h.HistoryLayout == "" {
		if rec.Type == "" {
			return false, errors.New("event type is required")
		}
		if rec.TenantID == "" {
			return false, errors.New("tenant_id is required")
		}
		return true, nil
	}
	if h.HistoryLayout != exactHistoryLayout {
		return false, fmt.Errorf("unsupported history layout %q", h.HistoryLayout)
	}
	if covered == nil || *covered == ^uint64(0) || rec.Sequence != *covered+1 {
		var previous uint64
		if covered != nil {
			previous = *covered
		}
		return false, fmt.Errorf(
			"exact history ordering: got sequence %d after %d",
			rec.Sequence, previous,
		)
	}

	switch rec.Kind {
	case "gap":
		if rec.GapThrough < rec.Sequence || rec.GapThrough > h.EventCutSequence {
			return false, fmt.Errorf(
				"malformed exact history gap %d..%d for cut %d",
				rec.Sequence, rec.GapThrough, h.EventCutSequence,
			)
		}
		if rec.Subject != "" || rec.MessageID != "" || len(rec.Stored) != 0 ||
			rec.ID != "" || rec.Type != "" || rec.TenantID != "" ||
			rec.SchemaVersion != 0 || !rec.Time.IsZero() || len(rec.Data) != 0 ||
			rec.Actor != nil {
			return false, fmt.Errorf(
				"malformed exact history gap %d..%d carries live-event fields",
				rec.Sequence, rec.GapThrough,
			)
		}
		*covered = rec.GapThrough
		return false, nil
	case "event":
		if rec.Sequence > h.EventCutSequence {
			return false, fmt.Errorf(
				"exact history event sequence %d is beyond cut %d",
				rec.Sequence, h.EventCutSequence,
			)
		}
		if rec.GapThrough != 0 {
			return false, fmt.Errorf("exact history event %d carries a gap boundary", rec.Sequence)
		}
		if rec.Subject == "" || strings.TrimSpace(rec.Subject) != rec.Subject ||
			!strings.HasPrefix(rec.Subject, "events.") ||
			strings.ContainsAny(rec.Subject, " \t\r\n*>") {
			return false, fmt.Errorf("exact history event %d has invalid subject %q", rec.Sequence, rec.Subject)
		}
		if rec.MessageID == "" {
			return false, fmt.Errorf("exact history event %d has no canonical message_id", rec.Sequence)
		}
		if len(rec.Stored) == 0 {
			return false, fmt.Errorf("exact history event %d has no stored envelope", rec.Sequence)
		}
		if err := validateStoredRecordIdentity(rec); err != nil {
			return false, err
		}
		*covered = rec.Sequence
		return true, nil
	default:
		return false, fmt.Errorf("exact history entry %d has unknown kind %q", rec.Sequence, rec.Kind)
	}
}

func validateStoredRecordIdentity(rec record) error {
	var stored struct {
		ID            string        `json:"id"`
		Type          string        `json:"type"`
		TenantID      string        `json:"tenant_id"`
		Time          time.Time     `json:"time"`
		SchemaVersion int           `json:"v,omitempty"`
		Data          []byte        `json:"data,omitempty"`
		Actor         *events.Actor `json:"actor,omitempty"`
	}
	if err := json.Unmarshal(rec.Stored, &stored); err != nil {
		return fmt.Errorf("exact history event %d has invalid stored envelope: %w", rec.Sequence, err)
	}
	if stored.ID == "" || stored.Type == "" || stored.TenantID == "" {
		return fmt.Errorf("exact history event %d has an incomplete stored envelope", rec.Sequence)
	}
	if rec.MessageID != stored.ID || rec.ID != stored.ID {
		return fmt.Errorf(
			"exact history event %d canonical message_id/id does not match stored event id",
			rec.Sequence,
		)
	}
	schemaVersion := stored.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = events.DefaultSchemaVersion
	}
	if rec.Type != stored.Type ||
		rec.TenantID != stored.TenantID ||
		rec.SchemaVersion != schemaVersion ||
		!rec.Time.Equal(stored.Time) ||
		!bytes.Equal(rec.Data, stored.Data) ||
		!reflect.DeepEqual(rec.Actor, stored.Actor) {
		return fmt.Errorf(
			"exact history event %d decoded fields do not match its stored envelope",
			rec.Sequence,
		)
	}
	if rec.Subject != "events."+stored.Type &&
		!strings.HasSuffix(rec.Subject, "."+stored.Type) {
		return fmt.Errorf(
			"exact history event %d subject %q does not route stored event type %q",
			rec.Sequence, rec.Subject, stored.Type,
		)
	}
	return nil
}

// readAndVerify streams the backup, recomputes the SHA-256 (and, when key is set,
// the HMAC) over every byte up to the trailer line, and verifies those digests
// against the trailer. Validated record lines are spooled to a temporary file and
// replayed only after this function succeeds, so restore never holds the full
// backup or decoded record set in memory and never mutates the target on a corrupt
// trailer.
func readAndVerify(r io.Reader, key []byte) (h header, spool *restoreSpool, tr trailer, err error) {
	var (
		haveHdr bool
		haveTr  bool
		covered uint64
	)
	spool, err = newRestoreSpool()
	if err != nil {
		return h, nil, tr, err
	}
	cleanupSpool := spool
	defer func() {
		if err != nil && cleanupSpool != nil {
			cleanupSpool.cleanup()
			spool = nil
		}
	}()
	dig := newDigest(key)
	sc := bufio.NewScanner(bufio.NewReader(r))
	// Backups can carry large event payloads; raise the line cap well above the
	// 64 KiB default so a big single event is not a spurious integrity failure.
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)

	for sc.Scan() {
		if haveTr {
			// Nothing may follow the trailer; trailing bytes mean tampering/append.
			return h, nil, tr, errors.New("backup: integrity: data found after the trailer line")
		}
		line := sc.Bytes()
		// Probe the discriminator without consuming the bytes for the digest.
		var probe struct {
			Format string `json:"format"`
		}
		_ = json.Unmarshal(line, &probe)

		switch {
		case !haveHdr:
			if err := json.Unmarshal(line, &h); err != nil {
				return h, nil, tr, fmt.Errorf("backup: read header: %w", err)
			}
			haveHdr = true
			feed(dig, line)
		case probe.Format == trailerTag:
			if err := json.Unmarshal(line, &tr); err != nil {
				return h, nil, tr, fmt.Errorf("backup: read trailer: %w", err)
			}
			haveTr = true
			// The trailer line itself is NOT fed into the digest.
		default:
			var rec record
			if err := json.Unmarshal(line, &rec); err != nil {
				return h, nil, tr, fmt.Errorf("backup: decode entry %d: %w", spool.entries+1, err)
			}
			live, err := validateDecodedRecord(h, rec, &covered)
			if err != nil {
				if h.HistoryLayout == exactHistoryLayout {
					return h, nil, tr, fmt.Errorf(
						"backup: integrity: decode entry %d: %w",
						spool.entries+1, err,
					)
				}
				return h, nil, tr, fmt.Errorf("backup: decode entry %d: %w", spool.entries+1, err)
			}
			feed(dig, line)
			if err := spool.writeLine(line, live); err != nil {
				return h, nil, tr, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return h, nil, tr, fmt.Errorf("backup: read stream: %w", err)
	}
	if !haveHdr {
		return h, nil, tr, errors.New("backup: read header: empty stream")
	}
	if !haveTr {
		// A backup with no trailer is unverifiable — treat it as corrupt/truncated
		// and refuse it (fail closed), rather than restoring unchecked bytes.
		return h, nil, tr, errors.New("backup: integrity trailer missing (stream truncated or not a trstctl backup); refusing to restore")
	}
	if h.HistoryLayout == exactHistoryLayout && covered != h.EventCutSequence {
		return h, nil, tr, fmt.Errorf(
			"backup: exact history ordering covers through %d, want cut %d",
			covered, h.EventCutSequence,
		)
	}

	// Verify SHA-256 (always) using constant-time comparison.
	wantSum, err := hex.DecodeString(tr.SHA256)
	if err != nil || len(wantSum) == 0 {
		return h, nil, tr, errors.New("backup: integrity: trailer has no valid sha256")
	}
	if !crypto.ConstantTimeEqual(dig.sum(), wantSum) {
		return h, nil, tr, errors.New("backup: integrity check FAILED — the backup is corrupt or has been tampered with (sha256 mismatch); refusing to restore")
	}

	// Verify HMAC when an integrity key was supplied.
	if len(key) > 0 {
		if tr.HMACSHA256 == "" {
			return h, nil, tr, errors.New("backup: integrity: an integrity key was provided but the backup carries no HMAC; refusing to restore")
		}
		wantMAC, err := hex.DecodeString(tr.HMACSHA256)
		if err != nil || len(wantMAC) == 0 {
			return h, nil, tr, errors.New("backup: integrity: trailer has no valid hmac_sha256")
		}
		if !crypto.ConstantTimeEqual(dig.mac(), wantMAC) {
			return h, nil, tr, errors.New("backup: integrity check FAILED — the backup's HMAC does not verify under the configured integrity key; refusing to restore")
		}
	}

	if err := spool.sync(); err != nil {
		return h, nil, tr, err
	}
	return h, spool, tr, nil
}

// digest accumulates the bytes of a backup stream and produces the trailer's
// SHA-256 and (when keyed) HMAC-SHA256, all via the crypto boundary (AN-3). The
// scanner strips newlines, so feed() re-adds the '\n' that the writer emitted
// after each line — keeping the read-side bytes identical to the write-side.
type digest struct {
	inner *crypto.SHA256HMACDigest
}

func newDigest(key []byte) *digest {
	return &digest{inner: crypto.NewSHA256HMACDigest(key)}
}

// Write makes *digest an io.Writer so the WRITE path can tee the exact encoded
// bytes (json.Encoder already appends '\n') straight into the digest.
func (d *digest) Write(p []byte) (int, error) {
	return d.inner.Write(p)
}

func (d *digest) sum() []byte    { return d.inner.SHA256Sum() }
func (d *digest) sumHex() string { return d.inner.SHA256Hex() }
func (d *digest) mac() []byte    { return d.inner.HMACSHA256() }
func (d *digest) macHex() string { return d.inner.HMACSHA256Hex() }

// feed appends a scanned line plus the newline the writer emitted after it, so the
// read-side digest covers exactly the write-side bytes.
func feed(d *digest, line []byte) {
	_, _ = d.Write(line)
	_, _ = d.Write([]byte{'\n'})
}

type restoreSpool struct {
	file    *os.File
	records int
	entries int
}

func newRestoreSpool() (*restoreSpool, error) {
	f, err := os.CreateTemp("", "trstctl-event-restore-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("backup: create restore spool: %w", err)
	}
	return &restoreSpool{file: f}, nil
}

func (s *restoreSpool) writeLine(line []byte, live bool) error {
	if _, err := s.file.Write(line); err != nil {
		return fmt.Errorf("backup: write restore spool: %w", err)
	}
	if _, err := s.file.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("backup: write restore spool: %w", err)
	}
	s.entries++
	if live {
		s.records++
	}
	return nil
}

func (s *restoreSpool) sync() error {
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("backup: sync restore spool: %w", err)
	}
	return nil
}

func (s *restoreSpool) rewind() error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("backup: rewind restore spool: %w", err)
	}
	return nil
}

func (s *restoreSpool) cleanup() {
	if s == nil || s.file == nil {
		return
	}
	name := s.file.Name()
	_ = s.file.Close()
	_ = os.Remove(name)
}
