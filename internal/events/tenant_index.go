// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/crypto"
)

const (
	tenantIndexPrefix    = "TRSTCTL_TENANT_EVENTS_V3_"
	tenantIndexSubject   = "trstctl_tenant_events_v3"
	tenantIndexBatch     = uint64(256)
	tenantIndexReadLimit = uint64(1024)
)

// ErrTenantIndexBehind means a bounded request caught up part of the durable
// projection but not the caller's source cut. Retrying resumes from its last
// persisted entry. An incomplete index never makes an absent tenant event safe.
var ErrTenantIndexBehind = errors.New("events: tenant event index is behind source history")

type tenantIndexEntry struct {
	SourceSequence uint64 `json:"source_sequence"`
	Digest         string `json:"digest"`
}

func tenantIndexEventRoot(epoch, tenantID string) string {
	return tenantIndexSubject + "." + epoch + ".tenant." + crypto.SHA256Hex([]byte(normalizedTenantScope(tenantID)))
}

// PostgreSQL treats UUID spellings as one tenant. Derived event indexes must
// use the same scope while preserving the original source envelope bytes.
// Historical non-UUID administrative scopes remain exact strings.
func normalizedTenantScope(tenantID string) string {
	if parsed, err := uuid.Parse(tenantID); err == nil && parsed != uuid.Nil {
		return parsed.String()
	}
	return tenantID
}

func tenantIndexEventSubject(epoch, tenantID string) string {
	return tenantIndexEventRoot(epoch, tenantID) + ".>"
}

func tenantIndexTypedEventSubject(epoch, tenantID, eventType string) string {
	return tenantIndexEventRoot(epoch, tenantID) + ".type." + crypto.SHA256Hex([]byte(eventType))
}

func tenantIndexCursorSubject(epoch string) string {
	return tenantIndexSubject + "." + epoch + ".cursor"
}

func (l *Log) tenantIndexFor(ctx context.Context, state schedulerSafetyState) (jetstream.Stream, string, error) {
	if l.desiredReplicas < 1 {
		return nil, "", errors.New("events: tenant projection is unavailable on a read-only external source")
	}
	epoch := eventIDSourceEpoch(state)
	name := tenantIndexPrefix + epoch
	stream, err := l.js.Stream(ctx, name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		stream, err = l.js.CreateStream(ctx, jetstream.StreamConfig{
			Name: name, Subjects: []string{tenantIndexSubject + "." + epoch + ".>"},
			Storage: jetstream.FileStorage, Replicas: l.desiredReplicas,
			MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
			DenyDelete: true, DenyPurge: true, AllowDirect: true,
			Metadata: map[string]string{
				"trstctl.source_epoch": epoch,
				"trstctl.source_name":  state.Name,
			},
		})
		if err != nil {
			stream, err = l.js.Stream(ctx, name) // another replica may have won creation
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("events: open tenant projection %s: %w", name, err)
	}
	info, err := cachedInfoForResolvedStream(stream)
	if err != nil {
		return nil, "", err
	}
	if info.Config.Name != name || info.Config.Storage != jetstream.FileStorage ||
		info.Config.Replicas != l.desiredReplicas || info.Config.Retention != jetstream.LimitsPolicy ||
		info.Config.MaxMsgs != -1 || info.Config.MaxBytes != -1 || info.Config.MaxAge != 0 ||
		info.Config.MaxMsgsPerSubject != -1 || !info.Config.DenyDelete || !info.Config.DenyPurge ||
		info.Config.NoAck || info.Config.Mirror != nil || len(info.Config.Sources) != 0 ||
		info.Config.SubjectTransform != nil || info.Config.RePublish != nil ||
		info.Config.AllowRollup || info.Config.AllowMsgTTL || info.Config.AllowMsgSchedules ||
		len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != tenantIndexSubject+"."+epoch+".>" ||
		info.Config.Metadata["trstctl.source_epoch"] != epoch ||
		info.Config.Metadata["trstctl.source_name"] != state.Name || info.State.NumDeleted != 0 {
		return nil, "", errors.New("events: tenant projection durability or source epoch differs from required configuration")
	}
	return stream, epoch, nil
}

func tenantIndexHead(ctx context.Context, stream jetstream.Stream) (uint64, uint64, uint64, error) {
	info, err := stream.Info(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	if info.State.NumDeleted != 0 || info.State.LastSeq != info.State.Msgs {
		return 0, 0, 0, errors.New("events: tenant projection has a missing index entry")
	}
	if info.State.Msgs == 0 {
		return 0, 0, 0, nil
	}
	raw, err := stream.GetMsg(ctx, info.State.LastSeq)
	if err != nil {
		return 0, 0, 0, err
	}
	entry, err := decodeTenantIndexEntry(raw)
	if err != nil {
		return 0, 0, 0, err
	}
	return entry.SourceSequence, info.State.LastSeq, info.State.Msgs, nil
}

func decodeTenantIndexEntry(raw *jetstream.RawStreamMsg) (tenantIndexEntry, error) {
	if raw == nil {
		return tenantIndexEntry{}, errors.New("events: tenant projection entry is absent")
	}
	var entry tenantIndexEntry
	if err := json.Unmarshal(raw.Data, &entry); err != nil {
		return tenantIndexEntry{}, fmt.Errorf("events: decode tenant projection entry: %w", err)
	}
	if entry.SourceSequence == 0 ||
		(len(entry.Digest) != 64 && (entry.Digest != "" || !strings.HasSuffix(raw.Subject, ".cursor"))) {
		return tenantIndexEntry{}, errors.New("events: malformed tenant projection entry")
	}
	return entry, nil
}

// indexTenantEventsThrough writes one tiny pointer per retained source event.
// The entire projection stream uses a last-sequence CAS, so multiple replicas
// cannot publish out of source order. A crash after a pointer is durable needs
// no separate cursor: the last pointer itself identifies the next source cut.
func (l *Log) indexTenantEventsThrough(ctx context.Context, source jetstream.Stream,
	state schedulerSafetyState, through uint64) (uint64, error) {
	index, epoch, err := l.tenantIndexFor(ctx, state)
	if err != nil {
		return 0, err
	}
	covered, indexSequence, _, err := tenantIndexHead(ctx, index)
	if err != nil {
		return 0, err
	}
	if covered > state.LastSequence || through > state.LastSequence {
		return 0, errors.New("events: tenant projection cut is beyond source head")
	}
	if covered >= through {
		return covered, nil
	}
	from := covered + 1
	if from < state.FirstSequence {
		from = state.FirstSequence
	}
	err = readRetainedThrough(ctx, source, from, through, func(raw *jetstream.RawStreamMsg) error {
		event, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		if event.TenantID == "" {
			return errors.New("events: tenant projection cannot index an empty tenant")
		}
		payload, err := json.Marshal(tenantIndexEntry{
			SourceSequence: raw.Sequence, Digest: crypto.SHA256Hex(raw.Data),
		})
		if err != nil {
			return err
		}
		for attempt := 0; attempt < 8; attempt++ {
			if covered >= raw.Sequence {
				return nil
			}
			if _, err := l.js.Publish(ctx, tenantIndexTypedEventSubject(epoch, event.TenantID, event.Type), payload,
				jetstream.WithExpectStream(index.CachedInfo().Config.Name),
				jetstream.WithExpectLastSequence(indexSequence)); err == nil {
				indexSequence++
				covered = raw.Sequence
				return nil
			}
			covered, indexSequence, _, err = tenantIndexHead(ctx, index)
			if err != nil {
				return err
			}
		}
		return errors.New("events: tenant projection concurrent catch-up did not converge")
	})
	if err != nil {
		return covered, err
	}
	// A retained source can end in a hole after checkpoint pruning. A durable
	// cursor advances coverage even when no tenant pointer exists at the cut.
	// Otherwise startup retries that empty range forever.
	for attempt := 0; covered < through && attempt < 8; attempt++ {
		payload, err := json.Marshal(tenantIndexEntry{SourceSequence: through})
		if err != nil {
			return covered, err
		}
		if _, err := l.js.Publish(ctx, tenantIndexCursorSubject(epoch), payload,
			jetstream.WithExpectStream(index.CachedInfo().Config.Name),
			jetstream.WithExpectLastSequence(indexSequence)); err == nil {
			covered = through
			break
		}
		covered, indexSequence, _, err = tenantIndexHead(ctx, index)
		if err != nil {
			return covered, err
		}
	}
	if covered < through {
		return covered, errors.New("events: tenant projection concurrent cursor catch-up did not converge")
	}
	after, err := l.schedulerSafetySnapshot(ctx)
	if err != nil {
		return covered, err
	}
	if !appendOnlySince(state, after) || eventIDSourceEpoch(after) != epoch {
		return covered, ErrGenerationChanged
	}
	return covered, nil
}

// ReplayTenantThrough reads a finite, source-ordered tenant view through the
// generation-specific index. It fetches and verifies each selected immutable
// source envelope before invoking fn. No unrelated tenant payload is decoded.
func (l *Log) ReplayTenantThrough(ctx context.Context, tenantID string, from, through uint64,
	fn func(Event) error) error {
	if l == nil || tenantID == "" || fn == nil {
		return errors.New("events: tenant replay requires log, tenant, and callback")
	}
	tenantID = normalizedTenantScope(tenantID)
	if from == 0 {
		from = 1
	}
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		name, source, head, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		if through > head {
			return errors.New("events: tenant replay cut is beyond source head")
		}
		state, err := l.schedulerSafetySnapshot(readCtx)
		if err != nil {
			return err
		}
		if state.Name != name || state.LastSequence < through {
			return ErrGenerationChanged
		}
		l.tenantIndexMu.Lock()
		index, epoch, err := l.tenantIndexFor(readCtx, state)
		if err != nil {
			l.tenantIndexMu.Unlock()
			return err
		}
		covered, _, _, err := tenantIndexHead(readCtx, index)
		if err == nil && covered < through {
			cut := min(through, covered+tenantIndexReadLimit)
			covered, err = l.indexTenantEventsThrough(readCtx, source, state, cut)
			if err == nil {
				covered, _, _, err = tenantIndexHead(readCtx, index)
			}
		}
		l.tenantIndexMu.Unlock()
		if err != nil {
			return err
		}
		if covered < through {
			return fmt.Errorf("%w: covered %d of %d", ErrTenantIndexBehind, covered, through)
		}
		if l.rejectLegacySchedulerRuns.Load() {
			if err := l.preflightLegacySchedulerHistory(readCtx, source, through); err != nil {
				return err
			}
		}
		next := uint64(1)
		lastSource := uint64(0)
		for {
			rawIndex, err := index.GetMsg(readCtx, next,
				jetstream.WithGetMsgSubject(tenantIndexEventSubject(epoch, tenantID)))
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				break
			}
			if err != nil {
				return err
			}
			entry, err := decodeTenantIndexEntry(rawIndex)
			if err != nil {
				return err
			}
			if entry.SourceSequence <= lastSource {
				return errors.New("events: tenant projection source order regressed")
			}
			lastSource = entry.SourceSequence
			if entry.SourceSequence > through {
				break
			}
			if entry.SourceSequence >= from {
				rawSource, err := source.GetMsg(readCtx, entry.SourceSequence)
				if errors.Is(err, jetstream.ErrMsgNotFound) {
					// Retention may have removed this formerly indexed source
					// event. The pinned source is authoritative for visibility.
				} else if err != nil {
					return err
				} else {
					if crypto.SHA256Hex(rawSource.Data) != entry.Digest {
						return errors.New("events: tenant projection differs from retained source")
					}
					event, err := decodeStored(rawSource.Data, entry.SourceSequence)
					if err != nil {
						return err
					}
					if normalizedTenantScope(event.TenantID) != tenantID {
						return errors.New("events: tenant projection selected a different tenant")
					}
					event, err = l.openProtectedEvent(readCtx, event)
					if err != nil {
						return err
					}
					if err := fn(event); err != nil {
						return err
					}
				}
			}
			if rawIndex.Sequence == ^uint64(0) {
				return errors.New("events: tenant projection sequence overflow")
			}
			next = rawIndex.Sequence + 1
		}
		current, err := l.schedulerSafetySnapshot(readCtx)
		if err != nil {
			return err
		}
		if !appendOnlySince(state, current) || eventIDSourceEpoch(current) != epoch {
			return ErrGenerationChanged
		}
		return nil
	})
}

func (l *Log) warmTenantIndex(ctx context.Context) error {
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, source, head, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		state, err := l.schedulerSafetySnapshot(readCtx)
		if err != nil {
			return err
		}
		l.tenantIndexMu.Lock()
		defer l.tenantIndexMu.Unlock()
		for {
			index, epoch, err := l.tenantIndexFor(readCtx, state)
			if err != nil {
				return err
			}
			covered, _, _, err := tenantIndexHead(readCtx, index)
			if err != nil {
				return err
			}
			if covered >= head {
				if covered != head {
					return errors.New("events: tenant projection does not cover retained source")
				}
				return l.deleteTenantIndexesExcept(readCtx, state.Name, epoch)
			}
			cut := min(head, covered+tenantIndexBatch)
			if _, err := l.indexTenantEventsThrough(readCtx, source, state, cut); err != nil {
				return err
			}
		}
	})
}

func (l *Log) deleteTenantIndexesExcept(ctx context.Context, sourceName, keepEpoch string) error {
	if sourceName == "" {
		return errors.New("events: tenant projection cleanup requires a source stream")
	}
	for _, retired := range []struct{ prefix, subject string }{
		{tenantIndexPrefix, tenantIndexSubject},
		{"TRSTCTL_TENANT_EVENTS_V2_", "trstctl_tenant_events_v2"},
		{"TRSTCTL_TENANT_EVENTS_", "trstctl_tenant_events"},
	} {
		if err := l.deleteTenantIndexGeneration(ctx, sourceName, keepEpoch, retired.prefix, retired.subject); err != nil {
			return err
		}
	}
	return nil
}

func (l *Log) deleteTenantIndexGeneration(ctx context.Context, sourceName, keepEpoch, prefix, subject string) error {
	lister := l.js.StreamNames(ctx, jetstream.WithStreamListSubject(subject+".>"))
	for name := range lister.Name() {
		if !strings.HasPrefix(name, prefix) || name == tenantIndexPrefix+keepEpoch {
			continue
		}
		stream, err := l.js.Stream(ctx, name)
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := cachedInfoForResolvedStream(stream)
		if err != nil {
			return err
		}
		if info.Config.Metadata["trstctl.source_name"] == sourceName {
			if err := l.js.DeleteStream(ctx, name); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
				return err
			}
		}
	}
	return lister.Err()
}
