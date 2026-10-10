// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/schedulerhistory"
)

// schedulerSafetySnapshot reads a fresh broker handle. JetStream mutates a
// handle's CachedInfo during Info, while GetMsg reads that cache, so the handle
// used by the replay must never be refreshed in place.
type schedulerSafetyState struct {
	StreamSnapshot
	created time.Time
}

func (l *Log) schedulerSafetySnapshot(ctx context.Context) (schedulerSafetyState, error) {
	name, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return schedulerSafetyState{}, err
	}
	info, err := cachedInfoForResolvedStream(stream)
	if err != nil {
		return schedulerSafetyState{}, err
	}
	if backupRestoreMetadataPending(info.Config.Metadata) {
		return schedulerSafetyState{}, ErrBackupRestoreIncomplete
	}
	generation := streamGeneration(info)
	if generation == "" {
		return schedulerSafetyState{}, errors.New("events: scheduler safety stream has no generation")
	}
	return schedulerSafetyState{StreamSnapshot: StreamSnapshot{
		Name: name, Generation: generation,
		FirstSequence: info.State.FirstSeq, LastSequence: info.State.LastSeq,
		Messages: info.State.Msgs, Bytes: info.State.Bytes,
		NumDeleted: info.State.NumDeleted,
	}, created: info.Created}, nil
}

// appendOnlySince accepts exactly the source change for which a verified
// prefix remains valid. A deletion, retention cut, rewritten generation, or
// replacement prefix requires a complete sanitation pass before callbacks.
func appendOnlySince(old, next schedulerSafetyState) bool {
	if old.Name != next.Name || old.Generation != next.Generation ||
		!old.created.Equal(next.created) ||
		old.LastSequence > next.LastSequence || old.Messages > next.Messages ||
		old.Bytes > next.Bytes || old.NumDeleted != next.NumDeleted {
		return false
	}
	if old.LastSequence == 0 {
		if next.LastSequence > 0 && next.FirstSequence != 1 {
			return false
		}
	} else if old.FirstSequence != next.FirstSequence {
		return false
	}
	return next.Messages-old.Messages == next.LastSequence-old.LastSequence
}

func (l *Log) preflightSchedulerPrefix(ctx context.Context, stream jetstream.Stream, through uint64) error {
	l.legacySafetyMu.Lock()
	defer l.legacySafetyMu.Unlock()
	before, err := l.schedulerSafetySnapshot(ctx)
	if err != nil {
		return err
	}
	readInfo, err := cachedInfoForResolvedStream(stream)
	if err != nil {
		return err
	}
	if before.Name != readInfo.Config.Name ||
		before.Generation != streamGeneration(readInfo) ||
		!before.created.Equal(readInfo.Created) || through > before.LastSequence {
		return fmt.Errorf("%w: scheduler preflight stream or cut changed", ErrGenerationChanged)
	}
	from := uint64(1)
	if l.legacySafetyPresent && appendOnlySince(l.legacySafety, before) {
		if through <= l.legacySafeThrough {
			return nil
		}
		from = l.legacySafeThrough + 1
	}
	if err := readRetainedEventsThrough(ctx, stream, from, through, func(event Event) error {
		unsafe, inspectErr := schedulerhistory.RequiresSanitation(event.Type, event.SchemaVersion, event.Data)
		if inspectErr != nil || unsafe {
			return schedulerhistory.ErrSanitationRequired
		}
		return nil
	}); err != nil {
		l.legacySafetyPresent = false
		return err
	}
	after, err := l.schedulerSafetySnapshot(ctx)
	if err != nil {
		l.legacySafetyPresent = false
		return err
	}
	if !appendOnlySince(before, after) {
		l.legacySafetyPresent = false
		return fmt.Errorf("%w: scheduler preflight history changed", ErrGenerationChanged)
	}
	l.legacySafety = after
	l.legacySafeThrough = through
	l.legacySafetyPresent = true
	return nil
}

// CheckedHead returns the source head only after the scheduler-history floor
// has covered it. Callers that bind an operation to a watermark must use this
// instead of a replay or raw LastSequence metadata.
func (l *Log) CheckedHead(ctx context.Context) (uint64, error) {
	var head uint64
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, stream, cut, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		if err := l.preflightLegacySchedulerHistory(readCtx, stream, cut); err != nil {
			return err
		}
		head = cut
		return nil
	})
	return head, err
}
