// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/crypto"
)

// EnvelopeMetadata is routing/source identity. It intentionally has no readable
// payload, actor or ciphertext buffer and does not assert body authentication.
type EnvelopeMetadata struct {
	ID            string
	Type          string
	TenantID      string
	Time          time.Time
	SchemaVersion int
	Sequence      uint64
	DeclaredKeyID string
}

func envelopeMetadata(e Event) EnvelopeMetadata {
	result := EnvelopeMetadata{ID: e.ID, Type: e.Type, TenantID: e.TenantID, Time: e.Time, SchemaVersion: e.SchemaVersion, Sequence: e.Sequence}
	if e.Protection != nil {
		result.DeclaredKeyID = e.Protection.KeyID
	}
	return result
}

// ReplayTenantMetadataTypesThrough visits source identities for at most sixteen
// event types without opening their protected bodies. Pointers must match the
// retained source digest, tenant and type. Callers must keep results private until
// this method succeeds, including its final history-generation check.
func (l *Log) ReplayTenantMetadataTypesThrough(ctx context.Context, tenantID string, from, through uint64, types []string, visit func(EnvelopeMetadata) error) error {
	if l == nil || tenantID == "" || visit == nil || len(types) > 16 {
		return errors.New("events: metadata replay requires bounded tenant/type scope")
	}
	selected := make(map[string]bool, len(types))
	for _, kind := range types {
		if kind == "" || strings.ContainsAny(kind, "*>") || strings.HasPrefix(kind, ".") || strings.HasSuffix(kind, ".") || strings.Contains(kind, "..") {
			return errors.New("events: invalid metadata event type")
		}
		selected[kind] = true
	}
	if from == 0 {
		from = 1
	}
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		name, source, head, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		if through > head {
			return errors.New("events: metadata cut exceeds source head")
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
		var covered, indexHead uint64
		if err == nil {
			covered, indexHead, _, err = tenantIndexHead(readCtx, index)
		}
		if err == nil && covered < through {
			cut := min(through, covered+tenantIndexReadLimit)
			_, err = l.indexTenantEventsThrough(readCtx, source, state, cut)
			if err == nil {
				covered, indexHead, _, err = tenantIndexHead(readCtx, index)
			}
		}
		l.tenantIndexMu.Unlock()
		if err != nil {
			return err
		}
		if covered > head {
			return ErrGenerationChanged
		}
		if covered < through {
			return ErrTenantIndexBehind
		}
		if l.rejectLegacySchedulerRuns.Load() {
			if err := l.preflightLegacySchedulerHistory(readCtx, source, through); err != nil {
				return err
			}
		}
		cursors := make([]typedReplayCursor, 0, len(selected))
		for kind := range selected {
			cursor := typedReplayCursor{subject: tenantIndexTypedEventSubject(epoch, tenantID, kind)}
			if indexHead > 0 {
				if err := cursor.next(readCtx, index, 1, indexHead); err != nil {
					return err
				}
			}
			cursors = append(cursors, cursor)
		}
		var lastSource uint64
		for {
			pick := -1
			for i := range cursors {
				if cursors[i].raw != nil && (pick < 0 || cursors[i].raw.Sequence < cursors[pick].raw.Sequence) {
					pick = i
				}
			}
			if pick < 0 {
				break
			}
			cursor := &cursors[pick]
			entry, err := decodeTenantIndexEntry(cursor.raw)
			if err != nil {
				return err
			}
			if entry.SourceSequence <= lastSource {
				return errors.New("events: metadata source order regressed")
			}
			lastSource = entry.SourceSequence
			if entry.SourceSequence > through {
				break
			}
			if entry.SourceSequence >= from {
				raw, err := source.GetMsg(readCtx, entry.SourceSequence)
				if !errors.Is(err, jetstream.ErrMsgNotFound) {
					if err != nil {
						return err
					}
					if crypto.SHA256Hex(raw.Data) != entry.Digest {
						return errors.New("events: metadata index differs from source")
					}
					event, err := decodeStored(raw.Data, entry.SourceSequence)
					if err != nil {
						return err
					}
					if event.TenantID != tenantID || !selected[event.Type] || cursor.raw.Subject != tenantIndexTypedEventSubject(epoch, tenantID, event.Type) {
						return errors.New("events: metadata index selected another scope")
					}
					if err := visit(envelopeMetadata(event)); err != nil {
						return err
					}
				}
			}
			if cursor.raw.Sequence == indexHead {
				cursor.raw = nil
			} else if err := cursor.next(readCtx, index, cursor.raw.Sequence+1, indexHead); err != nil {
				return err
			}
		}
		after, err := l.schedulerSafetySnapshot(readCtx)
		if err != nil {
			return err
		}
		if !appendOnlySince(state, after) || eventIDSourceEpoch(after) != epoch {
			return ErrGenerationChanged
		}
		return nil
	})
}
