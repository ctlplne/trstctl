// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"

	"github.com/nats-io/nats.go"
)

// Keep the response queue in NATS's bounded async pending list. SubscribeSync
// allocates 65,536 pointer slots before SetPendingLimits can restrict the queue.
// The unbuffered handoff adds no second response queue; one callback serves each
// subscription in wire order. Its cancellation releases a blocked handoff.
type retainedInbox struct {
	nc       *nats.Conn
	sub      *nats.Subscription
	messages chan *nats.Msg
	status   <-chan nats.SubStatus
	closed   chan nats.Status
	cancel   context.CancelFunc
}

func subscribeRetainedInbox(ctx context.Context, nc *nats.Conn, subject string, messages, bytes int) (*retainedInbox, error) {
	readCtx, cancel := context.WithCancel(ctx)
	inbox := &retainedInbox{nc: nc, messages: make(chan *nats.Msg), cancel: cancel}
	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		select {
		case inbox.messages <- msg:
		case <-readCtx.Done():
		}
	})
	if err != nil {
		cancel()
		return nil, err
	}
	inbox.sub = sub
	inbox.closed = nc.StatusChanged(nats.CLOSED)
	if err := sub.SetPendingLimits(messages, bytes); err != nil {
		_ = inbox.close()
		return nil, err
	}
	inbox.status = sub.StatusChanged(nats.SubscriptionClosed, nats.SubscriptionSlowConsumer)
	return inbox, nil
}

func (i *retainedInbox) close() error {
	i.cancel()
	i.nc.RemoveStatusListener(i.closed)
	return i.sub.Unsubscribe()
}

func (i *retainedInbox) transportError() error {
	if i.nc.IsClosed() {
		return nats.ErrConnectionClosed
	}
	dropped, err := i.sub.Dropped()
	if err != nil {
		return err
	}
	if dropped != 0 {
		return nats.ErrSlowConsumer
	}
	return nil
}

func (i *retainedInbox) next(ctx context.Context) (*nats.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := i.transportError(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-i.closed:
		return nil, nats.ErrConnectionClosed
	case status, open := <-i.status:
		if status == nats.SubscriptionSlowConsumer {
			return nil, nats.ErrSlowConsumer
		}
		if !open || status == nats.SubscriptionClosed {
			if i.nc.IsClosed() {
				return nil, nats.ErrConnectionClosed
			}
			return nil, nats.ErrBadSubscription
		}
		return nil, nats.ErrBadSubscription
	case msg := <-i.messages:
		if err := i.transportError(); err != nil {
			return nil, err
		}
		if len(msg.Data) == 0 && msg.Header.Get("Status") == "503" {
			return nil, nats.ErrNoResponders
		}
		return msg, nil
	}
}
