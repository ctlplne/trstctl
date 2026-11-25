// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenancy"
)

// ErrAppendPositionChanged means another writer advanced the observed subject
// or stream, or the event stream moved to a different generation.
var ErrAppendPositionChanged = errors.New("events: conditional append position changed")

// AppendSubjectPosition is a broker observation for one active generation and
// one exact routed subject. The append must belong to the observing tenant.
type AppendSubjectPosition struct {
	stream   string
	subject  string
	tenantID string
	sequence uint64
}

type appendSubjectPositionKey struct{}

// AppendStreamPosition fences an event against every writer to the active
// stream. It is used when related state transitions have different subjects.
type AppendStreamPosition struct {
	stream   string
	tenantID string
	sequence uint64
}

// Sequence is the broker head observed for this active generation.
func (p AppendStreamPosition) Sequence() uint64 { return p.sequence }

type appendStreamPositionKey struct{}

// ObserveAppendStream reads the active stream head and its generation together.
func (l *Log) ObserveAppendStream(ctx context.Context, tenantID string) (AppendStreamPosition, error) {
	var position AppendStreamPosition
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		name, stream, _, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		info, err := stream.Info(readCtx)
		if err != nil {
			return err
		}
		position = AppendStreamPosition{stream: name, tenantID: tenantID, sequence: info.State.LastSeq}
		return nil
	})
	return position, err
}

// AppendAtStreamPosition publishes only if the stream head is unchanged.
func (l *Log) AppendAtStreamPosition(ctx context.Context, e Event, position AppendStreamPosition) (Event, error) {
	if position.stream == "" || position.tenantID != e.TenantID {
		return Event{}, ErrAppendPositionChanged
	}
	return l.Append(context.WithValue(ctx, appendStreamPositionKey{}, position), e)
}

// ObserveAppendSubject records the most recent event on one exact subject.
// Pooled tenants share a subject for each event type.
// Writers observe before reading the journal evidence that permits their append.
func (l *Log) ObserveAppendSubject(ctx context.Context, tenantID, eventType string) (AppendSubjectPosition, error) {
	subject, err := tenancy.EventSubject(ctx, tenantID, subjectPrefix, eventType)
	if err != nil {
		return AppendSubjectPosition{}, err
	}
	var position AppendSubjectPosition
	err = l.withHistoryRead(ctx, func(readCtx context.Context) error {
		name, stream, _, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		position = AppendSubjectPosition{stream: name, subject: subject, tenantID: tenantID}
		raw, err := stream.GetLastMsgForSubject(readCtx, subject)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		position.sequence = raw.Sequence
		secret.Wipe(raw.Data)
		return nil
	})
	return position, err
}

// AppendAtSubjectPosition publishes only when the broker still sees the
// observed subject position. Other subjects may advance independently.
func (l *Log) AppendAtSubjectPosition(ctx context.Context, e Event, position AppendSubjectPosition) (Event, error) {
	if position.stream == "" || position.subject == "" || position.tenantID != e.TenantID {
		return Event{}, ErrAppendPositionChanged
	}
	return l.Append(context.WithValue(ctx, appendSubjectPositionKey{}, position), e)
}

func appendPositionConflict(err error) bool {
	var broker *jetstream.APIError
	return errors.As(err, &broker) &&
		(broker.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence ||
			broker.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant)
}
