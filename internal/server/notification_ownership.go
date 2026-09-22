// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"sync"

	"trstctl.com/trstctl/internal/notify"
)

// notificationChannelOwnership is the single ownership token for notifier
// credentials while the production composition is being assembled. The token
// owns channels until Build hands them to a Dispatcher. After that hand-off the
// Dispatcher is the only closer and Server.Shutdown releases the credentials.
//
// Every channel is wrapped in an idempotent closer. That makes cleanup exact
// even when two defensive failure paths meet (for example Build cleanup followed
// by Run cleanup), without requiring the credential-bearing implementation to
// tolerate duplicate Close calls.
type notificationChannelOwnership struct {
	mu          sync.Mutex
	channels    []*ownedNotificationChannel
	known       map[*ownedNotificationChannel]struct{}
	closed      bool
	transferred bool
}

type ownedNotificationChannel struct {
	notifier notify.Notifier
	close    sync.Once
}

func (c *ownedNotificationChannel) Name() string {
	return c.notifier.Name()
}

func (c *ownedNotificationChannel) Notify(ctx context.Context, alert notify.Alert) error {
	return c.notifier.Notify(ctx, alert)
}

func (c *ownedNotificationChannel) Close() {
	if c == nil {
		return
	}
	c.close.Do(func() {
		if closer, ok := c.notifier.(interface{ Close() }); ok {
			closer.Close()
		}
	})
}

func newNotificationChannelOwnership() *notificationChannelOwnership {
	return &notificationChannelOwnership{known: make(map[*ownedNotificationChannel]struct{})}
}

// adopt records every channel currently present in Deps and returns the complete
// append-only owned set behind close-once wrappers. Calling adopt again is
// intentional: edition attachers may add channels before Build takes ownership.
// An attacher cannot remove a previously owned credential merely by replacing
// the slice; the old channel remains in the returned set and therefore either
// reaches the Dispatcher or is closed by failure cleanup.
func (o *notificationChannelOwnership) adopt(channels []notify.Notifier) []notify.Notifier {
	if o == nil {
		return channels
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.transferred {
		return channels
	}
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		wrapper, ok := channel.(*ownedNotificationChannel)
		if !ok {
			wrapper = &ownedNotificationChannel{notifier: channel}
		}
		if _, exists := o.known[wrapper]; !exists {
			o.known[wrapper] = struct{}{}
			o.channels = append(o.channels, wrapper)
		}
	}
	owned := make([]notify.Notifier, 0, len(o.channels))
	for _, channel := range o.channels {
		owned = append(owned, channel)
	}
	return owned
}

func ensureNotificationChannelOwnership(d *Deps) *notificationChannelOwnership {
	if d.notificationChannelOwner == nil {
		d.notificationChannelOwner = newNotificationChannelOwnership()
	}
	d.NotificationChannels = d.notificationChannelOwner.adopt(d.NotificationChannels)
	return d.notificationChannelOwner
}

// closeOnError observes the constructor's final named return value when deferred.
// Successful construction leaves ownership available for transfer to Build.
func (o *notificationChannelOwnership) closeOnError(err *error) {
	if err != nil && *err != nil {
		o.closeUntransferred()
	}
}

func (o *notificationChannelOwnership) closeUntransferred() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.closed || o.transferred {
		o.mu.Unlock()
		return
	}
	o.closed = true
	channels := append([]*ownedNotificationChannel(nil), o.channels...)
	o.mu.Unlock()
	for _, channel := range channels {
		channel.Close()
	}
}

func (o *notificationChannelOwnership) transferToDispatcher() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if !o.closed {
		o.transferred = true
	}
	o.mu.Unlock()
}
