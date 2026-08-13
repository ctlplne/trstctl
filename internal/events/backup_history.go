// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tenancy"
)

const (
	backupGapSubject                 = "events.__trstctl_backup_gap"
	backupRestoreMetadataDigest      = "trstctl.restore.artifact_sha256"
	backupRestoreMetadataCut         = "trstctl.restore.event_cut_sequence"
	backupRestoreMetadataRoute       = "trstctl.restore.original_route"
	backupRestoreMetadataRouteDigest = "trstctl.restore.original_route_sha256"
	backupRestoreSubjectPrefix       = "__trstctl_backup_restore"
	backupHistoryDigestDomain        = "trstctl/backup-history-source/v1"
)

// ErrBackupHistoryNotPristine means an exact-history restore was pointed at a
// JetStream generation that has already consumed at least one sequence. A stream
// whose messages were all deleted is still not pristine: its next sequence would
// not be one, so restoring into it would silently move every checkpoint.
var ErrBackupHistoryNotPristine = errors.New("events: backup restore target history is not pristine")

// ErrBackupHistoryPrefixMismatch means an interrupted exact restore was retried
// with an artifact whose sequence layout or stored bytes do not match the prefix
// already present in JetStream. The restore stops before appending past the first
// mismatch; a different backup is never treated as a resume.
var ErrBackupHistoryPrefixMismatch = errors.New("events: backup restore target prefix differs from verified backup")

// ErrBackupRestoreAuthorizationRequired means the live schema floor is active
// and an exact restore was attempted without a deployment-key authorization
// bound to that artifact's cut, SHA-256 digest, and exact staged history source.
var ErrBackupRestoreAuthorizationRequired = errors.New("events: authenticated backup restore authority is required")

// ErrBackupRestoreIncomplete means an exact restore durably bound the active
// stream to one authenticated artifact but did not reach and clear that
// artifact's cut. Ordinary serving, backup, sanitation, and rebuild paths must
// stop; only the restore path holding the matching capability may resume it.
var ErrBackupRestoreIncomplete = errors.New("events: authenticated backup restore is incomplete")

// BackupHistoryRecord is one exact position in the active JetStream generation.
// A live record carries the original stored envelope, subject, and canonical
// Nats-Msg-Id. A gap compactly covers Sequence through GapThrough, inclusive.
// Gaps are first-class because audit-retention checkpoints refer to stream
// sequence numbers even after the corresponding live message has been pruned.
type BackupHistoryRecord struct {
	Sequence   uint64
	GapThrough uint64
	Subject    string
	MessageID  string
	Stored     []byte
	Event      Event
}

// IsGap reports whether this record is a compact deleted-sequence range.
func (r BackupHistoryRecord) IsGap() bool {
	return r.GapThrough != 0
}

// BackupHistorySource streams already verified records to an exact-history
// restore. The source must cover every position from one through the declared cut
// exactly once, representing deleted positions with gap records.
type BackupHistorySource func(yield func(BackupHistoryRecord) error) error

// RequireNoPendingBackupRestore fails when the active generation still carries
// the durable exact-restore binding. It intentionally exposes no digest: callers
// only need to know that normal history use is unsafe until restore resumes.
func (l *Log) RequireNoPendingBackupRestore(ctx context.Context) error {
	if l == nil {
		return ErrBackupRestoreIncomplete
	}
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, stream, err := l.resolveActiveStream(readCtx)
		if err != nil {
			return fmt.Errorf("events: inspect pending backup restore: %w", err)
		}
		return l.requireNoPendingBackupRestoreStream(readCtx, stream)
	})
}

func (l *Log) requireNoPendingBackupRestoreStream(
	ctx context.Context,
	stream jetstream.Stream,
) error {
	info, err := cachedInfoForResolvedStream(stream)
	if err != nil {
		return fmt.Errorf("events: inspect pending backup restore metadata: %w", err)
	}
	if backupRestoreMetadataPending(info.Config.Metadata) {
		return ErrBackupRestoreIncomplete
	}
	return nil
}

func backupRestoreMetadataPending(metadata map[string]string) bool {
	return metadata[backupRestoreMetadataDigest] != "" ||
		metadata[backupRestoreMetadataCut] != "" ||
		metadata[backupRestoreMetadataRoute] != "" ||
		metadata[backupRestoreMetadataRouteDigest] != ""
}

type backupRestoreRoute struct {
	Subjects         []string                          `json:"subjects"`
	SubjectTransform *jetstream.SubjectTransformConfig `json:"subject_transform,omitempty"`
}

func encodeBackupRestoreRoute(cfg jetstream.StreamConfig) (string, error) {
	route := backupRestoreRoute{Subjects: append([]string(nil), cfg.Subjects...)}
	if len(route.Subjects) == 0 {
		return "", errors.New("events: backup restore source has no subject route")
	}
	if cfg.SubjectTransform != nil {
		transform := *cfg.SubjectTransform
		route.SubjectTransform = &transform
	}
	payload, err := json.Marshal(route)
	if err != nil {
		return "", errors.New("events: encode backup restore source route")
	}
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

func decodeBackupRestoreRoute(encoded, digest string) (backupRestoreRoute, error) {
	if encoded == "" || digest == "" || crypto.SHA256Hex([]byte(encoded)) != digest {
		return backupRestoreRoute{}, errors.New("events: backup restore source route integrity mismatch")
	}
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return backupRestoreRoute{}, errors.New("events: backup restore source route is not valid base64")
	}
	var route backupRestoreRoute
	if err := json.Unmarshal(payload, &route); err != nil {
		return backupRestoreRoute{}, errors.New("events: decode backup restore source route")
	}
	if len(route.Subjects) == 0 {
		return backupRestoreRoute{}, errors.New("events: backup restore source route has no subjects")
	}
	return route, nil
}

func backupRestoreFilter(artifactDigest string) (string, error) {
	decoded, err := hex.DecodeString(artifactDigest)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("events: backup restore artifact digest is not valid SHA-256")
	}
	return backupRestoreSubjectPrefix + "." + artifactDigest + "." + subjectFilter, nil
}

func backupRestorePublishSubject(artifactDigest, subject string) (string, error) {
	if strings.TrimSpace(subject) == "" ||
		!strings.HasPrefix(subject, "events.") ||
		strings.ContainsAny(subject, " \t\r\n*>") {
		return "", errors.New("events: backup restore source subject is invalid")
	}
	if _, err := backupRestoreFilter(artifactDigest); err != nil {
		return "", err
	}
	return backupRestoreSubjectPrefix + "." + artifactDigest + "." + subject, nil
}

func backupRestoreRouteIsFrozen(cfg jetstream.StreamConfig, artifactDigest string) bool {
	filter, err := backupRestoreFilter(artifactDigest)
	return err == nil && len(cfg.Subjects) == 1 && cfg.Subjects[0] == filter &&
		cfg.SubjectTransform != nil && cfg.SubjectTransform.Source == filter &&
		cfg.SubjectTransform.Destination == subjectFilter
}

// pendingBackupRestoreStream finds the generation that an interrupted exact
// restore removed from the ordinary events.> route. This is deliberately based
// on durable stream metadata instead of process-local cache: another replica may
// have installed the binding after this Log last resolved the active generation.
func (l *Log) pendingBackupRestoreStream(
	ctx context.Context,
) (string, jetstream.Stream, bool, error) {
	var pendingName string
	lister := l.js.ListStreams(ctx)
	for info := range lister.Info() {
		if !backupRestoreMetadataPending(info.Config.Metadata) {
			continue
		}
		if pendingName != "" {
			return "", nil, false, errors.New("events: multiple pending backup restore generations")
		}
		if err := validatePendingBackupRestoreConfig(info.Config); err != nil {
			return "", nil, false, fmt.Errorf(
				"events: pending backup restore stream %q: %w",
				info.Config.Name, err,
			)
		}
		pendingName = info.Config.Name
	}
	if err := lister.Err(); err != nil {
		return "", nil, false, fmt.Errorf("events: list pending backup restores: %w", err)
	}
	if pendingName == "" {
		return "", nil, false, nil
	}
	stream, err := l.js.Stream(ctx, pendingName)
	if err != nil {
		return "", nil, false, fmt.Errorf(
			"events: open pending backup restore stream %q: %w", pendingName, err,
		)
	}
	return pendingName, stream, true, nil
}

func validatePendingBackupRestoreConfig(cfg jetstream.StreamConfig) error {
	metadata := cfg.Metadata
	digest := metadata[backupRestoreMetadataDigest]
	cut := metadata[backupRestoreMetadataCut]
	route := metadata[backupRestoreMetadataRoute]
	routeDigest := metadata[backupRestoreMetadataRouteDigest]
	if digest == "" || cut == "" {
		return errors.New("backup restore artifact binding is incomplete")
	}
	if _, err := strconv.ParseUint(cut, 10, 64); err != nil {
		return errors.New("backup restore cut is invalid")
	}
	if route == "" && routeDigest == "" {
		// Compatibility with the first AUD-116 implementation. It persisted the
		// exact artifact/cut binding but had not yet installed the broker route.
		// The matching authorized resume upgrades it under the exclusive cutover.
		return nil
	}
	if route == "" || routeDigest == "" {
		return errors.New("backup restore broker route metadata is incomplete")
	}
	if _, err := decodeBackupRestoreRoute(route, routeDigest); err != nil {
		return err
	}
	if !backupRestoreRouteIsFrozen(cfg, digest) {
		return errors.New("backup restore broker route is not frozen")
	}
	return nil
}

func backupRestoreRouteNeedsUpgrade(cfg jetstream.StreamConfig) bool {
	return backupRestoreMetadataPending(cfg.Metadata) &&
		cfg.Metadata[backupRestoreMetadataRoute] == "" &&
		cfg.Metadata[backupRestoreMetadataRouteDigest] == ""
}

// freezeLegacyBackupRestoreRoute upgrades the digest+cut-only binding written by
// the first AUD-116 implementation. The caller must own the exclusive history
// cutover: removing events.> is the broker linearization point after which an old
// replica cannot extend the artifact-bound prefix through its ordinary subject.
func (l *Log) freezeLegacyBackupRestoreRoute(
	ctx context.Context,
	name string,
	stream jetstream.Stream,
	info *jetstream.StreamInfo,
) (jetstream.Stream, error) {
	if err := validatePendingBackupRestoreConfig(info.Config); err != nil {
		return nil, err
	}
	if !backupRestoreRouteNeedsUpgrade(info.Config) {
		return stream, nil
	}
	artifactDigest := info.Config.Metadata[backupRestoreMetadataDigest]
	route, err := encodeBackupRestoreRoute(info.Config)
	if err != nil {
		return nil, err
	}
	filter, err := backupRestoreFilter(artifactDigest)
	if err != nil {
		return nil, err
	}
	cfg := cloneStreamConfig(info.Config)
	cfg.Metadata[backupRestoreMetadataRoute] = route
	cfg.Metadata[backupRestoreMetadataRouteDigest] = crypto.SHA256Hex([]byte(route))
	cfg.Subjects = []string{filter}
	cfg.SubjectTransform = &jetstream.SubjectTransformConfig{
		Source: filter, Destination: subjectFilter,
	}
	updated, err := l.js.UpdateStream(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("events: freeze legacy backup restore broker route: %w", err)
	}
	l.setActiveStreamNamed(name, updated)
	return updated, nil
}

type backupHistoryDigestRecord struct {
	Sequence   uint64 `json:"sequence"`
	GapThrough uint64 `json:"gap_through,omitempty"`
	Subject    string `json:"subject,omitempty"`
	MessageID  string `json:"message_id,omitempty"`
	Stored     []byte `json:"stored,omitempty"`
}

func (record backupHistoryDigestRecord) backupRecord() BackupHistoryRecord {
	return BackupHistoryRecord{
		Sequence: record.Sequence, GapThrough: record.GapThrough,
		Subject: record.Subject, MessageID: record.MessageID,
		Stored: append([]byte(nil), record.Stored...),
	}
}

// BackupHistoryDigest validates source and returns a canonical SHA-256 chain for
// every exact field the restore transaction consumes. It lets the integrity-
// verified backup reader mint a capability that is useless with any transplanted
// history source, even when the outer artifact digest and cut are reused.
func BackupHistoryDigest(
	ctx context.Context,
	cut uint64,
	source BackupHistorySource,
) (string, error) {
	return consumeBackupHistory(ctx, cut, source, nil)
}

func consumeBackupHistory(
	ctx context.Context,
	cut uint64,
	source BackupHistorySource,
	consume func(backupHistoryDigestRecord) error,
) (string, error) {
	if source == nil {
		return "", errors.New("events: backup history source is required")
	}
	digest := crypto.SHA256Hex([]byte(backupHistoryDigestDomain))
	var covered uint64
	var callbackErr error
	err := source(func(record BackupHistoryRecord) error {
		if callbackErr != nil {
			return callbackErr
		}
		if err := ctx.Err(); err != nil {
			callbackErr = err
			return err
		}
		if covered == ^uint64(0) || record.Sequence != covered+1 {
			callbackErr = fmt.Errorf(
				"events: backup history ordering: got sequence %d after %d",
				record.Sequence, covered,
			)
			return callbackErr
		}
		canonical := backupHistoryDigestRecord{
			Sequence: record.Sequence, GapThrough: record.GapThrough,
			Subject: record.Subject, MessageID: record.MessageID,
			Stored: append([]byte(nil), record.Stored...),
		}
		if record.IsGap() {
			if record.GapThrough < record.Sequence || record.GapThrough > cut {
				callbackErr = fmt.Errorf(
					"events: malformed backup gap %d..%d for cut %d",
					record.Sequence, record.GapThrough, cut,
				)
				return callbackErr
			}
			if record.Subject != "" || record.MessageID != "" || len(record.Stored) != 0 {
				callbackErr = fmt.Errorf(
					"events: malformed backup gap %d..%d carries live-message fields",
					record.Sequence, record.GapThrough,
				)
				return callbackErr
			}
			covered = record.GapThrough
		} else {
			if record.Sequence > cut {
				callbackErr = fmt.Errorf(
					"events: backup event sequence %d is beyond cut %d",
					record.Sequence, cut,
				)
				return callbackErr
			}
			if err := validateBackupLiveRecord(record); err != nil {
				callbackErr = err
				return err
			}
			covered = record.Sequence
		}
		digest = digestChain(digest, canonical)
		if digest == "" {
			callbackErr = errors.New("events: digest canonical backup history")
			return callbackErr
		}
		if consume != nil {
			if err := consume(canonical); err != nil {
				callbackErr = err
				return err
			}
		}
		return nil
	})
	if callbackErr != nil {
		return "", callbackErr
	}
	if err != nil {
		return "", err
	}
	if covered != cut {
		return "", fmt.Errorf(
			"events: backup history covers through %d, want exact cut %d",
			covered, cut,
		)
	}
	digest = digestChain(digest, struct {
		Cut uint64 `json:"cut"`
	}{Cut: cut})
	if digest == "" {
		return "", errors.New("events: finalize canonical backup history digest")
	}
	return digest, nil
}

type authorizedBackupHistorySpool struct {
	file *os.File
}

func spoolAuthorizedBackupHistory(
	ctx context.Context,
	cut uint64,
	source BackupHistorySource,
) (*authorizedBackupHistorySpool, string, error) {
	file, err := os.CreateTemp("", "trstctl-authorized-event-restore-*.jsonl")
	if err != nil {
		return nil, "", fmt.Errorf("events: create authorized restore spool: %w", err)
	}
	spool := &authorizedBackupHistorySpool{file: file}
	encoder := json.NewEncoder(file)
	digest, err := consumeBackupHistory(ctx, cut, source, func(record backupHistoryDigestRecord) error {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("events: write authorized restore spool: %w", err)
		}
		return nil
	})
	if err != nil {
		spool.cleanup()
		return nil, "", err
	}
	if err := file.Sync(); err != nil {
		spool.cleanup()
		return nil, "", fmt.Errorf("events: sync authorized restore spool: %w", err)
	}
	return spool, digest, nil
}

func (spool *authorizedBackupHistorySpool) source(
	yield func(BackupHistoryRecord) error,
) error {
	if _, err := spool.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("events: rewind authorized restore spool: %w", err)
	}
	decoder := json.NewDecoder(spool.file)
	for {
		var record backupHistoryDigestRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("events: read authorized restore spool: %w", err)
		}
		if err := yield(record.backupRecord()); err != nil {
			return err
		}
	}
}

func (spool *authorizedBackupHistorySpool) cleanup() {
	if spool == nil || spool.file == nil {
		return
	}
	name := spool.file.Name()
	_ = spool.file.Close()
	_ = os.Remove(name)
}

// LegacyBackupHistoryRecord converts one integrity-verified, contiguous v1
// artifact record into the exact-history representation consumed by
// RestoreBackupHistory. It does not mutate a log and is not an append bypass:
// only the existing restore transaction may publish the returned stored bytes.
func LegacyBackupHistoryRecord(
	ctx context.Context,
	sequence uint64,
	event Event,
) (BackupHistoryRecord, error) {
	if sequence == 0 || event.ID == "" || event.Type == "" || event.TenantID == "" || event.Time.IsZero() {
		return BackupHistoryRecord{}, errors.New("events: legacy backup record has an incomplete source envelope")
	}
	if event.SchemaVersion == 0 {
		event.SchemaVersion = DefaultSchemaVersion
	}
	subject, err := tenancy.EventSubject(ctx, event.TenantID, subjectPrefix, event.Type)
	if err != nil {
		return BackupHistoryRecord{}, err
	}
	stored, err := json.Marshal(storedEvent{
		ID: event.ID, Type: event.Type, TenantID: event.TenantID, Time: event.Time,
		SchemaVersion: event.SchemaVersion, Data: event.Data, Actor: event.Actor,
	})
	if err != nil {
		return BackupHistoryRecord{}, errors.New("events: encode legacy backup source envelope")
	}
	return BackupHistoryRecord{
		Sequence: sequence, Subject: subject, MessageID: event.ID,
		Stored: stored, Event: event,
	}, nil
}

// ExportBackupHistoryThrough pins one active generation and emits its exact
// sequence layout through cut. The callback receives compact gap ranges as well
// as live raw messages. cut may be zero only for the empty prefix, and it may
// never be beyond the generation's current head.
func (l *Log) ExportBackupHistoryThrough(
	ctx context.Context,
	cut uint64,
	yield func(BackupHistoryRecord) error,
) error {
	if yield == nil {
		return errors.New("events: backup history export callback is required")
	}
	return l.withHistoryRead(ctx, func(ctx context.Context) error {
		name, stream, err := l.resolveActiveStream(ctx)
		if err != nil {
			return fmt.Errorf("events: resolve backup generation: %w", err)
		}
		info, err := l.infoForStream(ctx, stream)
		if err != nil {
			return fmt.Errorf("events: backup generation info: %w", err)
		}
		if backupRestoreMetadataPending(info.Config.Metadata) {
			return ErrBackupRestoreIncomplete
		}
		if cut > info.State.LastSeq {
			return fmt.Errorf(
				"events: backup cut %d is beyond active generation head %d",
				cut, info.State.LastSeq,
			)
		}
		// Once startup closes the live schema floor, an old writer or direct broker
		// publisher must not make Export leak a prefix before an unsafe later event
		// is discovered. Inspect the complete cut before invoking yield once.
		if l.rejectLegacySchedulerRuns.Load() {
			if err := l.preflightLegacySchedulerHistory(ctx, stream, cut); err != nil {
				return err
			}
		}

		var gapStart uint64
		flushGap := func(through uint64) error {
			if gapStart == 0 {
				return nil
			}
			record := BackupHistoryRecord{Sequence: gapStart, GapThrough: through}
			gapStart = 0
			return yield(record)
		}
		for sequence := uint64(1); sequence <= cut; sequence++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			raw, err := stream.GetMsg(ctx, sequence)
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				if gapStart == 0 {
					gapStart = sequence
				}
				continue
			}
			if err != nil {
				return fmt.Errorf("events: export backup seq %d: %w", sequence, err)
			}
			if err := flushGap(sequence - 1); err != nil {
				return err
			}
			event, err := decodeStored(raw.Data, raw.Sequence)
			if err != nil {
				return err
			}
			if event.ID == "" || event.Type == "" || event.TenantID == "" {
				return fmt.Errorf("events: backup seq %d has an incomplete event envelope", sequence)
			}
			messageIDs := raw.Header.Values(jetstream.MsgIDHeader)
			if len(messageIDs) != 1 || messageIDs[0] == "" {
				return fmt.Errorf(
					"events: backup seq %d must carry exactly one canonical %s",
					sequence, jetstream.MsgIDHeader,
				)
			}
			if messageIDs[0] != event.ID {
				return fmt.Errorf(
					"events: backup seq %d message id %q does not match event id %q",
					sequence, messageIDs[0], event.ID,
				)
			}
			if strings.TrimSpace(raw.Subject) == "" {
				return fmt.Errorf("events: backup seq %d has no subject", sequence)
			}
			if err := yield(BackupHistoryRecord{
				Sequence:  sequence,
				Subject:   raw.Subject,
				MessageID: messageIDs[0],
				Stored:    append([]byte(nil), raw.Data...),
				Event:     event,
			}); err != nil {
				return err
			}
		}
		if cut > 0 {
			if err := flushGap(cut); err != nil {
				return err
			}
		}
		current, err := l.activeStreamName(ctx)
		if err != nil {
			return fmt.Errorf("events: verify backup generation: %w", err)
		}
		if current != name {
			return fmt.Errorf(
				"%w: backup started on %s and ended on %s",
				ErrGenerationChanged, name, current,
			)
		}
		return nil
	})
}

// BackupHistoryPristine reports whether the active generation has never consumed
// a sequence. Checking Replay alone is insufficient because an all-gap stream has
// no live messages but still has a non-zero sequence head.
func (l *Log) BackupHistoryPristine(ctx context.Context) (bool, error) {
	var pristine bool
	err := l.withHistoryRead(ctx, func(ctx context.Context) error {
		_, stream, err := l.resolveActiveStream(ctx)
		if err != nil {
			return err
		}
		info, err := l.infoForStream(ctx, stream)
		if err != nil {
			return err
		}
		pristine = info.State.LastSeq == 0 && info.State.Msgs == 0
		return nil
	})
	return pristine, err
}

// RestoreBackupHistory installs the exact verified history supplied by source. It
// is prefix-resumable: positions already present must match byte-for-byte, while
// already-deleted gaps are accepted. A reserved gap marker left live by a crash
// between publish and secure-delete is recognized only at its exact sequence and
// removed before restore continues. It serializes against backup reads,
// retention, and generation rewrites.
func (l *Log) RestoreBackupHistory(
	ctx context.Context,
	cut uint64,
	artifactDigest string,
	source BackupHistorySource,
) (int, error) {
	if l.rejectLegacySchedulerRuns.Load() {
		return 0, ErrBackupRestoreAuthorizationRequired
	}
	return l.restoreBackupHistory(ctx, cut, artifactDigest, source)
}

// RestoreAuthorizedBackupHistory is the recovery-only form of
// RestoreBackupHistory. authorization is an opaque HMAC capability over this
// exact artifact cut/digest and the canonical history source digest under the
// independently configured deployment authorizer when crossing the live schema
// floor. The source is validated and copied into a private spool before
// authorization is accepted; restore consumes only that spool, closing callback
// time-of-check/time-of-use swaps. Before the floor exists, keyed public restores
// retain their historical API behavior because ordinary RestoreBackupHistory is
// still allowed; the typed grant continues to bind the validated source.
func (l *Log) RestoreAuthorizedBackupHistory(
	ctx context.Context,
	cut uint64,
	artifactDigest string,
	authorization *crypto.BackupRestoreGrant,
	source BackupHistorySource,
) (int, error) {
	if source == nil {
		return 0, errors.New("events: backup history restore source is required")
	}
	if strings.TrimSpace(artifactDigest) == "" {
		return 0, errors.New("events: backup history restore requires a verified artifact digest")
	}
	if l.history == nil {
		return 0, errors.New("events: backup history restore requires a history coordinator")
	}
	intent := authorization.Intent()
	if intent.EventCutSequence != cut || intent.ArtifactSHA256 != artifactDigest {
		return 0, ErrBackupRestoreAuthorizationRequired
	}
	if l.rejectLegacySchedulerRuns.Load() &&
		(l.backupRestoreAuthorizer == nil || !l.backupRestoreAuthorizer.Verify(authorization)) {
		return 0, ErrBackupRestoreAuthorizationRequired
	}
	spool, historyDigest, err := spoolAuthorizedBackupHistory(ctx, cut, source)
	if err != nil {
		return 0, err
	}
	defer spool.cleanup()
	if intent.HistorySHA256 != historyDigest {
		return 0, ErrBackupRestoreAuthorizationRequired
	}
	// The floor is installed once during startup, but recheck after the bounded
	// source preflight so even an unexpected concurrent activation cannot use the
	// ordinary keyed-restore compatibility path to cross it without the locked-key
	// verifier.
	if l.rejectLegacySchedulerRuns.Load() &&
		(l.backupRestoreAuthorizer == nil || !l.backupRestoreAuthorizer.Verify(authorization)) {
		return 0, ErrBackupRestoreAuthorizationRequired
	}
	return l.restoreBackupHistory(ctx, cut, artifactDigest, spool.source)
}

func (l *Log) restoreBackupHistory(
	ctx context.Context,
	cut uint64,
	artifactDigest string,
	source BackupHistorySource,
) (int, error) {
	if source == nil {
		return 0, errors.New("events: backup history restore source is required")
	}
	if strings.TrimSpace(artifactDigest) == "" {
		return 0, errors.New("events: backup history restore requires a verified artifact digest")
	}
	if l.history == nil {
		return 0, errors.New("events: backup history restore requires a history coordinator")
	}

	restored := 0
	err := l.withBackupRestoreOperation(ctx, func(ctx context.Context) error {
		return l.history.WithCutover(ctx, func(ctx context.Context) error {
			name, stream, err := l.resolveActiveStream(ctx)
			if err != nil {
				return fmt.Errorf("events: resolve backup restore generation: %w", err)
			}
			info, err := l.infoForStream(ctx, stream)
			if err != nil {
				return fmt.Errorf("events: backup restore generation info: %w", err)
			}
			head := info.State.LastSeq
			if head > cut {
				return fmt.Errorf(
					"%w: target head %d is beyond backup cut %d",
					ErrBackupHistoryPrefixMismatch, head, cut,
				)
			}
			var restoreBound bool
			stream, restoreBound, err = l.bindBackupRestoreIdentity(
				ctx, name, stream, info, cut, artifactDigest,
			)
			if err != nil {
				return err
			}

			var covered uint64
			err = source(func(record BackupHistoryRecord) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if covered == ^uint64(0) || record.Sequence != covered+1 {
					return fmt.Errorf(
						"events: backup history ordering: got sequence %d after %d",
						record.Sequence, covered,
					)
				}
				if record.IsGap() {
					if record.GapThrough < record.Sequence || record.GapThrough > cut {
						return fmt.Errorf(
							"events: malformed backup gap %d..%d for cut %d",
							record.Sequence, record.GapThrough, cut,
						)
					}
					if record.Subject != "" || record.MessageID != "" || len(record.Stored) != 0 {
						return fmt.Errorf(
							"events: malformed backup gap %d..%d carries live-message fields",
							record.Sequence, record.GapThrough,
						)
					}
					for sequence := record.Sequence; sequence <= record.GapThrough; sequence++ {
						if sequence <= head {
							raw, err := stream.GetMsg(ctx, sequence)
							if errors.Is(err, jetstream.ErrMsgNotFound) {
								continue
							}
							if err != nil {
								return fmt.Errorf("events: inspect restored backup gap %d: %w", sequence, err)
							}
							if !isBackupGapMarker(raw, sequence) {
								return fmt.Errorf(
									"%w: backup expects gap at sequence %d but target has a live message",
									ErrBackupHistoryPrefixMismatch, sequence,
								)
							}
							if !restoreBound {
								return fmt.Errorf(
									"%w: completed markerless target retains a live gap marker at sequence %d",
									ErrBackupHistoryPrefixMismatch, sequence,
								)
							}
							if err := stream.SecureDeleteMsg(ctx, sequence); err != nil {
								return fmt.Errorf("events: finish secure-delete backup gap %d: %w", sequence, err)
							}
							continue
						}
						if sequence != head+1 {
							return fmt.Errorf(
								"events: backup gap sequence %d does not continue target head %d",
								sequence, head,
							)
						}
						if err := l.restoreBackupGap(
							ctx, name, stream, sequence, artifactDigest,
						); err != nil {
							return err
						}
						head = sequence
					}
					covered = record.GapThrough
					return nil
				}
				if record.Sequence > cut {
					return fmt.Errorf(
						"events: backup event sequence %d is beyond cut %d",
						record.Sequence, cut,
					)
				}
				if err := validateBackupLiveRecord(record); err != nil {
					return err
				}
				if record.Sequence <= head {
					raw, err := stream.GetMsg(ctx, record.Sequence)
					if errors.Is(err, jetstream.ErrMsgNotFound) {
						return fmt.Errorf(
							"%w: backup expects a live message at sequence %d but target has a gap",
							ErrBackupHistoryPrefixMismatch, record.Sequence,
						)
					}
					if err != nil {
						return fmt.Errorf("events: inspect restored backup seq %d: %w", record.Sequence, err)
					}
					if err := matchBackupLiveRecord(raw, record); err != nil {
						return err
					}
					covered = record.Sequence
					restored++
					return nil
				}
				if record.Sequence != head+1 {
					return fmt.Errorf(
						"events: backup event sequence %d does not continue target head %d",
						record.Sequence, head,
					)
				}
				restoreSubject, err := backupRestorePublishSubject(
					artifactDigest, record.Subject,
				)
				if err != nil {
					return fmt.Errorf("events: route backup restore seq %d: %w", record.Sequence, err)
				}
				ack, err := l.js.PublishMsg(
					ctx,
					&nats.Msg{
						Subject: restoreSubject,
						Data:    append([]byte(nil), record.Stored...),
					},
					jetstream.WithMsgID(record.MessageID),
					jetstream.WithExpectStream(name),
					jetstream.WithExpectLastSequence(covered),
				)
				if err != nil {
					return fmt.Errorf("events: restore backup seq %d: %w", record.Sequence, err)
				}
				if ack.Duplicate || ack.Stream != name || ack.Sequence != record.Sequence {
					return fmt.Errorf(
						"events: restore backup seq %d acknowledged stream=%s sequence=%d duplicate=%t",
						record.Sequence, ack.Stream, ack.Sequence, ack.Duplicate,
					)
				}
				covered = record.Sequence
				head = record.Sequence
				restored++
				return nil
			})
			if err != nil {
				return err
			}
			if covered != cut {
				return fmt.Errorf(
					"events: backup history covers through %d, want exact cut %d",
					covered, cut,
				)
			}
			finalInfo, err := l.infoForStream(ctx, stream)
			if err != nil {
				return fmt.Errorf("events: verify restored backup head: %w", err)
			}
			if finalInfo.State.LastSeq != cut {
				return fmt.Errorf(
					"events: restored backup head %d does not match cut %d",
					finalInfo.State.LastSeq, cut,
				)
			}
			if restoreBound {
				if err := l.clearBackupRestoreIdentity(
					ctx, name, stream, artifactDigest, cut,
				); err != nil {
					return err
				}
			}
			return nil
		})
	})
	return restored, err
}

func (l *Log) bindBackupRestoreIdentity(
	ctx context.Context,
	name string,
	stream jetstream.Stream,
	info *jetstream.StreamInfo,
	cut uint64,
	artifactDigest string,
) (jetstream.Stream, bool, error) {
	metadata := info.Config.Metadata
	boundDigest := metadata[backupRestoreMetadataDigest]
	boundCut := metadata[backupRestoreMetadataCut]
	if boundDigest != "" || boundCut != "" {
		if boundDigest != artifactDigest || boundCut != strconv.FormatUint(cut, 10) {
			return nil, false, fmt.Errorf(
				"%w: partial restore is bound to artifact %q/cut %q, got %q/cut %d",
				ErrBackupHistoryPrefixMismatch,
				boundDigest, boundCut, artifactDigest, cut,
			)
		}
		if backupRestoreRouteIsFrozen(info.Config, artifactDigest) {
			if _, err := decodeBackupRestoreRoute(
				metadata[backupRestoreMetadataRoute],
				metadata[backupRestoreMetadataRouteDigest],
			); err != nil {
				return nil, false, err
			}
			return stream, true, nil
		}
		if !backupRestoreRouteNeedsUpgrade(info.Config) {
			return nil, false, errors.New("events: backup restore broker route is inconsistent")
		}
		updated, err := l.freezeLegacyBackupRestoreRoute(ctx, name, stream, info)
		if err != nil {
			return nil, false, err
		}
		return updated, true, nil
	}
	if info.State.LastSeq == cut && cut != 0 {
		// A completed exact restore clears its temporary binding before the
		// independent PostgreSQL phase. A full-DR retry may therefore arrive at a
		// markerless completed event log. It is allowed only as a read-only full
		// prefix verification; the caller still compares every live/gap position.
		return stream, false, nil
	}
	if info.State.LastSeq != 0 || info.State.Msgs != 0 {
		return nil, false, fmt.Errorf(
			"%w: non-pristine target has no durable restore-artifact binding",
			ErrBackupHistoryPrefixMismatch,
		)
	}
	route, err := encodeBackupRestoreRoute(info.Config)
	if err != nil {
		return nil, false, err
	}
	filter, err := backupRestoreFilter(artifactDigest)
	if err != nil {
		return nil, false, err
	}
	cfg := cloneStreamConfig(info.Config)
	if cfg.Metadata == nil {
		cfg.Metadata = make(map[string]string)
	}
	cfg.Metadata[backupRestoreMetadataDigest] = artifactDigest
	cfg.Metadata[backupRestoreMetadataCut] = strconv.FormatUint(cut, 10)
	cfg.Metadata[backupRestoreMetadataRoute] = route
	cfg.Metadata[backupRestoreMetadataRouteDigest] = crypto.SHA256Hex([]byte(route))
	cfg.Subjects = []string{filter}
	cfg.SubjectTransform = &jetstream.SubjectTransformConfig{
		Source: filter, Destination: subjectFilter,
	}
	updated, err := l.js.UpdateStream(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("events: bind backup restore artifact to stream %s: %w", name, err)
	}
	l.setActiveStreamNamed(name, updated)
	updatedInfo, err := l.infoForStream(ctx, updated)
	if err != nil {
		return nil, false, fmt.Errorf("events: verify backup restore broker fence: %w", err)
	}
	if updatedInfo.State.LastSeq != 0 || updatedInfo.State.Msgs != 0 {
		// An ordinary publish that reached the broker before UpdateStream is
		// linearized before this restore. Put its original route back and require
		// the caller to retry from a pristine target instead of stranding an
		// artifact binding around history the artifact did not authorize.
		if clearErr := l.clearBackupRestoreIdentity(
			ctx, name, updated, artifactDigest, cut,
		); clearErr != nil {
			return nil, false, errors.Join(
				ErrBackupHistoryNotPristine,
				fmt.Errorf("events: release raced backup restore binding: %w", clearErr),
			)
		}
		return nil, false, ErrBackupHistoryNotPristine
	}
	return updated, true, nil
}

func (l *Log) clearBackupRestoreIdentity(
	ctx context.Context,
	name string,
	stream jetstream.Stream,
	artifactDigest string,
	cut uint64,
) error {
	info, err := l.infoForStream(ctx, stream)
	if err != nil {
		return fmt.Errorf("events: read completed backup restore metadata: %w", err)
	}
	if info.Config.Metadata[backupRestoreMetadataDigest] != artifactDigest ||
		info.Config.Metadata[backupRestoreMetadataCut] != strconv.FormatUint(cut, 10) {
		return errors.New("events: completed backup restore artifact binding changed before clear")
	}
	if !backupRestoreRouteIsFrozen(info.Config, artifactDigest) {
		return errors.New("events: completed backup restore broker route changed before clear")
	}
	route, err := decodeBackupRestoreRoute(
		info.Config.Metadata[backupRestoreMetadataRoute],
		info.Config.Metadata[backupRestoreMetadataRouteDigest],
	)
	if err != nil {
		return err
	}
	cfg := cloneStreamConfig(info.Config)
	delete(cfg.Metadata, backupRestoreMetadataDigest)
	delete(cfg.Metadata, backupRestoreMetadataCut)
	delete(cfg.Metadata, backupRestoreMetadataRoute)
	delete(cfg.Metadata, backupRestoreMetadataRouteDigest)
	if len(cfg.Metadata) == 0 {
		cfg.Metadata = nil
	}
	cfg.Subjects = append([]string(nil), route.Subjects...)
	if route.SubjectTransform == nil {
		cfg.SubjectTransform = nil
	} else {
		transform := *route.SubjectTransform
		cfg.SubjectTransform = &transform
	}
	updated, err := l.js.UpdateStream(ctx, cfg)
	if err != nil {
		return fmt.Errorf("events: clear completed backup restore artifact binding: %w", err)
	}
	l.setActiveStreamNamed(name, updated)
	return nil
}

func validateBackupLiveRecord(record BackupHistoryRecord) error {
	if record.GapThrough != 0 {
		return fmt.Errorf("events: backup live record %d carries a gap boundary", record.Sequence)
	}
	if strings.TrimSpace(record.Subject) == "" {
		return fmt.Errorf("events: backup live record %d has no subject", record.Sequence)
	}
	if strings.TrimSpace(record.MessageID) == "" {
		return fmt.Errorf("events: backup live record %d has no canonical message id", record.Sequence)
	}
	if len(record.Stored) == 0 {
		return fmt.Errorf("events: backup live record %d has no stored envelope", record.Sequence)
	}
	event, err := decodeStored(record.Stored, record.Sequence)
	if err != nil {
		return err
	}
	if event.ID == "" || event.Type == "" || event.TenantID == "" {
		return fmt.Errorf("events: backup live record %d has an incomplete event envelope", record.Sequence)
	}
	if event.ID != record.MessageID {
		return fmt.Errorf(
			"events: backup live record %d message id %q does not match stored event id %q",
			record.Sequence, record.MessageID, event.ID,
		)
	}
	return nil
}

func matchBackupLiveRecord(raw *jetstream.RawStreamMsg, record BackupHistoryRecord) error {
	if raw == nil ||
		raw.Sequence != record.Sequence ||
		raw.Subject != record.Subject ||
		!bytes.Equal(raw.Data, record.Stored) {
		return fmt.Errorf(
			"%w: live message at sequence %d differs in subject or stored bytes",
			ErrBackupHistoryPrefixMismatch, record.Sequence,
		)
	}
	messageIDs := raw.Header.Values(jetstream.MsgIDHeader)
	if len(messageIDs) != 1 || messageIDs[0] != record.MessageID {
		return fmt.Errorf(
			"%w: live message at sequence %d has a different canonical message id",
			ErrBackupHistoryPrefixMismatch, record.Sequence,
		)
	}
	return nil
}

func backupGapMessageID(sequence uint64) string {
	return fmt.Sprintf("__trstctl_backup_gap_%d", sequence)
}

func isBackupGapMarker(raw *jetstream.RawStreamMsg, sequence uint64) bool {
	if raw == nil ||
		raw.Sequence != sequence ||
		raw.Subject != backupGapSubject ||
		len(raw.Data) != 0 {
		return false
	}
	messageIDs := raw.Header.Values(jetstream.MsgIDHeader)
	return len(messageIDs) == 1 && messageIDs[0] == backupGapMessageID(sequence)
}

func (l *Log) restoreBackupGap(
	ctx context.Context,
	streamName string,
	stream jetstream.Stream,
	sequence uint64,
	artifactDigest string,
) error {
	restoreSubject, err := backupRestorePublishSubject(artifactDigest, backupGapSubject)
	if err != nil {
		return fmt.Errorf("events: route backup gap %d: %w", sequence, err)
	}
	ack, err := l.js.Publish(
		ctx,
		restoreSubject,
		nil,
		jetstream.WithMsgID(backupGapMessageID(sequence)),
		jetstream.WithExpectStream(streamName),
		jetstream.WithExpectLastSequence(sequence-1),
	)
	if err != nil {
		return fmt.Errorf("events: materialize backup gap %d: %w", sequence, err)
	}
	if ack.Duplicate || ack.Stream != streamName || ack.Sequence != sequence {
		return fmt.Errorf(
			"events: materialize backup gap %d acknowledged stream=%s sequence=%d duplicate=%t",
			sequence, ack.Stream, ack.Sequence, ack.Duplicate,
		)
	}
	if err := stream.SecureDeleteMsg(ctx, sequence); err != nil {
		return fmt.Errorf("events: secure-delete backup gap %d: %w", sequence, err)
	}
	return nil
}
