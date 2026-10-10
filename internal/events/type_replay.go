// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go/jetstream"
)

// ReplayTenantTypesThrough visits only the named event types for one tenant in
// source order, inside an inclusive source sequence cut. JetStream's subject
// inventory locates pooled and every historical silo lane, then next-for-subject
// skips unrelated events. A tenant may have changed lanes; the immutable
// envelope, not its subject, decides tenancy. The number of cursors is bounded
// by distinct retained subjects, not by the number of events.
func (l *Log) ReplayTenantTypesThrough(ctx context.Context, tenantID string, from, through uint64,
	types []string, fn func(Event) error) error {
	if l == nil || tenantID == "" || fn == nil {
		return errors.New("events: typed replay requires log, tenant, and callback")
	}
	seen := make(map[string]bool, len(types))
	for _, eventType := range types {
		if eventType == "" || strings.ContainsAny(eventType, "*>") ||
			strings.HasPrefix(eventType, ".") || strings.HasSuffix(eventType, ".") || strings.Contains(eventType, "..") {
			return fmt.Errorf("events: invalid typed replay event type %q", eventType)
		}
		seen[eventType] = true
	}
	if from == 0 {
		from = 1
	}
	return l.withHistoryRead(ctx, func(ctx context.Context) error {
		name, stream, head, err := l.resolveReplayStream(ctx)
		if err != nil {
			return err
		}
		if through > head {
			return fmt.Errorf("events: typed replay cut %d is beyond active generation head %d", through, head)
		}
		if l.rejectLegacySchedulerRuns.Load() {
			if err := l.preflightLegacySchedulerHistory(ctx, stream, through); err != nil {
				return err
			}
		}
		if from <= through && len(seen) > 0 {
			info, err := stream.Info(ctx, jetstream.WithSubjectFilter(subjectFilter))
			if err != nil {
				return fmt.Errorf("events: list retained subjects for typed replay: %w", err)
			}
			cursors := make([]typedReplayCursor, 0, len(seen)*2)
			for subject := range info.State.Subjects {
				for eventType := range seen {
					if typedReplaySubject(subject, eventType) {
						cursors = append(cursors, typedReplayCursor{subject: subject})
						break
					}
				}
			}
			for i := range cursors {
				if err := cursors[i].next(ctx, stream, from, through); err != nil {
					return err
				}
			}
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
				event, err := decodeStored(cursor.raw.Data, cursor.raw.Sequence)
				if err != nil {
					return err
				}
				if !typedReplaySubject(cursor.raw.Subject, event.Type) {
					return fmt.Errorf("events: typed replay subject and retained envelope differ at sequence %d", event.Sequence)
				}
				if event.TenantID == tenantID && seen[event.Type] {
					if err := fn(event); err != nil {
						return err
					}
				}
				if cursor.raw.Sequence == through {
					cursor.raw = nil
				} else if err := cursor.next(ctx, stream, cursor.raw.Sequence+1, through); err != nil {
					return err
				}
			}
		}
		current, err := l.activeStreamName(ctx)
		if err != nil {
			return fmt.Errorf("events: verify typed replay generation: %w", err)
		}
		if current != name {
			return fmt.Errorf("%w: typed replay started on %s and ended on %s", ErrGenerationChanged, name, current)
		}
		return nil
	})
}

type typedReplayCursor struct {
	subject string
	raw     *jetstream.RawStreamMsg
}

func (c *typedReplayCursor) next(ctx context.Context, stream jetstream.Stream, from, through uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := stream.GetMsg(ctx, from, jetstream.WithGetMsgSubject(c.subject))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		c.raw = nil
		return nil
	}
	if err != nil {
		return err
	}
	if raw.Sequence < from {
		return errors.New("events: typed replay subject index regressed")
	}
	if raw.Sequence > through {
		c.raw = nil
		return nil
	}
	c.raw = raw
	return nil
}

func typedReplaySubject(subject, eventType string) bool {
	if subject == subjectPrefix+"."+eventType {
		return true
	}
	suffix := "." + eventType
	if !strings.HasPrefix(subject, subjectPrefix+".") || !strings.HasSuffix(subject, suffix) {
		return false
	}
	lane := strings.TrimSuffix(strings.TrimPrefix(subject, subjectPrefix+"."), suffix)
	if lane == "" || strings.HasPrefix(lane, ".") || strings.HasSuffix(lane, ".") || strings.Contains(lane, "..") {
		return false
	}
	return true
}
