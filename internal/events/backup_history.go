// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	backupGapSubject            = "events.__trstctl_backup_gap"
	backupRestoreMetadataDigest = "trstctl.restore.artifact_sha256"
	backupRestoreMetadataCut    = "trstctl.restore.event_cut_sequence"
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
		if cut > info.State.LastSeq {
			return fmt.Errorf(
				"events: backup cut %d is beyond active generation head %d",
				cut, info.State.LastSeq,
			)
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
	err := l.withRewriteOperation(ctx, func(ctx context.Context) error {
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
						if err := l.restoreBackupGap(ctx, name, stream, sequence); err != nil {
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
				ack, err := l.js.PublishMsg(
					ctx,
					&nats.Msg{
						Subject: record.Subject,
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
		return stream, true, nil
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
	cfg := cloneStreamConfig(info.Config)
	if cfg.Metadata == nil {
		cfg.Metadata = make(map[string]string)
	}
	cfg.Metadata[backupRestoreMetadataDigest] = artifactDigest
	cfg.Metadata[backupRestoreMetadataCut] = strconv.FormatUint(cut, 10)
	updated, err := l.js.UpdateStream(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("events: bind backup restore artifact to stream %s: %w", name, err)
	}
	l.setActiveStreamNamed(name, updated)
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
	cfg := cloneStreamConfig(info.Config)
	delete(cfg.Metadata, backupRestoreMetadataDigest)
	delete(cfg.Metadata, backupRestoreMetadataCut)
	if len(cfg.Metadata) == 0 {
		cfg.Metadata = nil
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
) error {
	ack, err := l.js.Publish(
		ctx,
		backupGapSubject,
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
