// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	eventIDIndexPrefix    = "TRSTCTL_EVENT_IDS_"
	eventIDIndexSubject   = "trstctl_event_ids"
	eventIDIndexBatch     = uint64(256)
	eventIDIndexReadLimit = uint64(1024)
)

// ErrEventIDIndexBehind means the source has advanced beyond the bounded
// request-side catch-up. The next retry resumes at the durable cursor; absence
// is never inferred from an index that has not inspected the pinned source cut.
var ErrEventIDIndexBehind = errors.New("events: event identity index is behind source history")

type eventIDIndexEntry struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
	Conflict bool   `json:"conflict,omitempty"`
}

type eventIDIndexCursor struct {
	Through uint64 `json:"through"`
}

func eventIDSourceEpoch(state schedulerSafetyState) string {
	first := state.FirstSequence
	if state.LastSequence == 0 {
		first = 1 // Empty and first-append states belong to the same epoch.
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", state.Name,
		state.Generation, state.created.UTC().Format(time.RFC3339Nano), first, state.NumDeleted)
	return strings.ToUpper(crypto.SHA256Hex([]byte(key)))
}

func eventIDKeySubject(epoch, id string) string {
	return eventIDIndexSubject + "." + epoch + ".key." + crypto.SHA256Hex([]byte(id))
}

func eventIDCursorSubject(epoch string) string {
	return eventIDIndexSubject + "." + epoch + ".cursor"
}

// eventIDIndexFor resolves only a generation-specific, file-backed projection.
// A replacement source cannot see an old generation's identity entries, even if
// its head and event IDs happen to match. The index contains sequence/digest
// facts, never event payloads or credential material.
func (l *Log) eventIDIndexFor(ctx context.Context, state schedulerSafetyState) (jetstream.Stream, string, error) {
	if l.desiredReplicas < 1 {
		return nil, "", errors.New("events: identity projection is unavailable on a read-only external source")
	}
	epoch := eventIDSourceEpoch(state)
	name := eventIDIndexPrefix + epoch
	stream, err := l.js.Stream(ctx, name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		stream, err = l.js.CreateStream(ctx, jetstream.StreamConfig{
			Name: name, Subjects: []string{eventIDIndexSubject + "." + epoch + ".>"},
			Storage: jetstream.FileStorage, Replicas: l.desiredReplicas,
			MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: 1, AllowDirect: true,
			Metadata: map[string]string{
				"trstctl.source_epoch": epoch,
				"trstctl.source_name":  state.Name,
			},
		})
		if err != nil {
			// Another replica may have created the same epoch after our probe.
			// Re-read and validate its config; never rewrite an existing index.
			stream, err = l.js.Stream(ctx, name)
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("events: open identity projection %s: %w", name, err)
	}
	info, err := cachedInfoForResolvedStream(stream)
	if err != nil {
		return nil, "", err
	}
	if info.Config.Name != name || info.Config.Storage != jetstream.FileStorage ||
		info.Config.Replicas != l.desiredReplicas || info.Config.MaxMsgsPerSubject != 1 ||
		info.Config.Retention != jetstream.LimitsPolicy || info.Config.MaxMsgs != -1 ||
		info.Config.MaxBytes != -1 || info.Config.MaxAge != 0 || info.Config.NoAck ||
		info.Config.Mirror != nil || len(info.Config.Sources) != 0 ||
		info.Config.SubjectTransform != nil || info.Config.RePublish != nil ||
		info.Config.AllowRollup || info.Config.AllowMsgTTL ||
		info.Config.SubjectDeleteMarkerTTL != 0 || info.Config.AllowMsgSchedules ||
		len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != eventIDIndexSubject+"."+epoch+".>" ||
		info.Config.Metadata["trstctl.source_epoch"] != epoch ||
		info.Config.Metadata["trstctl.source_name"] != state.Name {
		return nil, "", errors.New("events: identity projection durability or source epoch differs from required configuration")
	}
	return stream, epoch, nil
}

func readEventIDCursor(ctx context.Context, stream jetstream.Stream, epoch string) (uint64, uint64, error) {
	raw, err := stream.GetLastMsgForSubject(ctx, eventIDCursorSubject(epoch))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	var cursor eventIDIndexCursor
	if err := json.Unmarshal(raw.Data, &cursor); err != nil {
		return 0, 0, fmt.Errorf("events: decode identity projection cursor: %w", err)
	}
	return cursor.Through, raw.Sequence, nil
}

func readEventIDEntry(ctx context.Context, stream jetstream.Stream, epoch, eventID string) (eventIDIndexEntry, uint64, bool, error) {
	raw, err := stream.GetLastMsgForSubject(ctx, eventIDKeySubject(epoch, eventID))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return eventIDIndexEntry{}, 0, false, nil
	}
	if err != nil {
		return eventIDIndexEntry{}, 0, false, err
	}
	var entry eventIDIndexEntry
	if err := json.Unmarshal(raw.Data, &entry); err != nil {
		return eventIDIndexEntry{}, 0, false, fmt.Errorf("events: decode identity projection entry: %w", err)
	}
	if entry.Sequence == 0 || len(entry.Digest) != 64 {
		return eventIDIndexEntry{}, 0, false, errors.New("events: malformed identity projection entry")
	}
	return entry, raw.Sequence, true, nil
}

func (l *Log) indexEventID(ctx context.Context, source, index jetstream.Stream, epoch string, raw *jetstream.RawStreamMsg) error {
	event, err := decodeStored(raw.Data, raw.Sequence)
	if err != nil {
		return err
	}
	if event.ID == "" {
		return nil
	}
	subject := eventIDKeySubject(epoch, event.ID)
	newEntry := eventIDIndexEntry{Sequence: raw.Sequence, Digest: crypto.SHA256Hex(raw.Data)}
	payload, err := json.Marshal(newEntry)
	if err != nil {
		return err
	}
	if _, err := l.js.Publish(ctx, subject, payload,
		jetstream.WithExpectStream(index.CachedInfo().Config.Name), jetstream.WithExpectLastSequencePerSubject(0)); err == nil {
		return nil
	}
	// The first-write CAS failed. Read the winner and compare its immutable
	// canonical envelope. Unique IDs use one broker write, not a read and write.
	for attempt := 0; attempt < 4; attempt++ {
		entry, last, found, err := readEventIDEntry(ctx, index, epoch, event.ID)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("events: identity projection rejected a first entry without a canonical winner")
		}
		canonicalRaw, err := source.GetMsg(ctx, entry.Sequence)
		if err != nil {
			return fmt.Errorf("events: identity projection canonical seq %d: %w", entry.Sequence, err)
		}
		if crypto.SHA256Hex(canonicalRaw.Data) != entry.Digest {
			return errors.New("events: identity projection differs from retained canonical envelope")
		}
		canonical, err := decodeStored(canonicalRaw.Data, entry.Sequence)
		if err != nil || canonical.ID != event.ID {
			return errors.New("events: identity projection canonical ID differs from retained history")
		}
		if sameRetainedEvent(canonical, event) || entry.Conflict {
			return nil
		}
		entry.Conflict = true
		payload, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if _, err := l.js.Publish(ctx, subject, payload,
			jetstream.WithExpectStream(index.CachedInfo().Config.Name), jetstream.WithExpectLastSequencePerSubject(last)); err == nil {
			return nil
		}
	}
	return errors.New("events: identity projection concurrent update did not converge")
}

// indexEventIDsThrough writes each event identity before its covered cursor.
// A crash between those writes only repeats an idempotent indexed entry. The
// caller holds a history read view, and each invocation processes a finite cut.
func (l *Log) indexEventIDsThrough(ctx context.Context, source jetstream.Stream, state schedulerSafetyState, through uint64) (uint64, error) {
	index, epoch, err := l.eventIDIndexFor(ctx, state)
	if err != nil {
		return 0, err
	}
	covered, cursorSequence, err := readEventIDCursor(ctx, index, epoch)
	if err != nil {
		return 0, err
	}
	if covered > state.LastSequence {
		return 0, errors.New("events: identity projection cursor is beyond source head")
	}
	if through <= covered {
		return covered, nil
	}
	if err := readRetainedThrough(ctx, source, covered+1, through, func(raw *jetstream.RawStreamMsg) error {
		return l.indexEventID(ctx, source, index, epoch, raw)
	}); err != nil {
		return covered, err
	}
	after, err := l.schedulerSafetySnapshot(ctx)
	if err != nil {
		return covered, err
	}
	if !appendOnlySince(state, after) || eventIDSourceEpoch(after) != epoch {
		return covered, ErrGenerationChanged
	}
	payload, err := json.Marshal(eventIDIndexCursor{Through: through})
	if err != nil {
		return covered, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := l.js.Publish(ctx, eventIDCursorSubject(epoch), payload,
			jetstream.WithExpectStream(index.CachedInfo().Config.Name),
			jetstream.WithExpectLastSequencePerSubject(cursorSequence)); err == nil {
			return through, nil
		}
		// Every entry through this cut was already written. A competing
		// replica may have advanced an earlier cursor; CAS from its durable
		// sequence without replaying the source or moving the cursor back.
		current, sequence, err := readEventIDCursor(ctx, index, epoch)
		if err != nil {
			return covered, err
		}
		if current >= through {
			return current, nil
		}
		cursorSequence = sequence
	}
	return covered, errors.New("events: identity projection cursor contention did not converge")
}

func (l *Log) warmEventIDIndex(ctx context.Context) error {
	// A concurrent privacy rewrite must not delete the old index while startup
	// is rebuilding it. The shared history view pins one source generation until
	// both its cursor and the obsolete-index cleanup are durable.
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, source, head, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		state, err := l.schedulerSafetySnapshot(readCtx)
		if err != nil {
			return err
		}
		l.idIndexMu.Lock()
		defer l.idIndexMu.Unlock()
		for {
			index, epoch, err := l.eventIDIndexFor(readCtx, state)
			if err != nil {
				return err
			}
			covered, _, err := readEventIDCursor(readCtx, index, epoch)
			if err != nil {
				return err
			}
			if covered > head {
				current, err := l.schedulerSafetySnapshot(readCtx)
				if err != nil {
					return err
				}
				if !appendOnlySince(state, current) || current.LastSequence < covered {
					return errors.New("events: identity projection cursor exceeds source head during startup")
				}
			}
			if covered >= head {
				return l.deleteEventIDIndexesExcept(readCtx, state.Name, epoch)
			}
			cut := min(head, covered+eventIDIndexBatch)
			if _, err := l.indexEventIDsThrough(readCtx, source, state, cut); err != nil {
				return err
			}
		}
	})
}

// deleteEventIDIndexesExcept removes obsolete identity facts at a history
// cutover or during cold recovery. An erased event ID must not survive in an
// older generation's hash subject after its source stream has been scrubbed.
// The caller owns the history cutover/read view; it never deletes the active
// epoch. This enumerates only stream metadata, not the event source.
func (l *Log) deleteEventIDIndexesExcept(ctx context.Context, sourceName, keepEpoch string) error {
	if sourceName == "" {
		return errors.New("events: identity projection cleanup requires a source stream")
	}
	lister := l.js.StreamNames(ctx, jetstream.WithStreamListSubject(eventIDIndexSubject+".>"))
	for name := range lister.Name() {
		if !strings.HasPrefix(name, eventIDIndexPrefix) || name == eventIDIndexPrefix+keepEpoch {
			continue
		}
		stream, err := l.js.Stream(ctx, name)
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("events: inspect identity projection %s: %w", name, err)
		}
		info, err := cachedInfoForResolvedStream(stream)
		if err != nil {
			return err
		}
		if info.Config.Metadata["trstctl.source_name"] != sourceName {
			continue
		}
		if err := l.js.DeleteStream(ctx, name); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			return fmt.Errorf("events: delete obsolete identity projection %s: %w", name, err)
		}
	}
	if err := lister.Err(); err != nil {
		return fmt.Errorf("events: list identity projections: %w", err)
	}
	return nil
}

func (l *Log) discardEventIDIndexesAtCutover(ctx context.Context, sourceName string) error {
	l.idIndexMu.Lock()
	defer l.idIndexMu.Unlock()
	if err := l.deleteEventIDIndexesExcept(ctx, sourceName, ""); err != nil {
		return err
	}
	return nil
}
