// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"math"
	"sync"
	"time"
)

// clientRateLimiter is a token bucket per client address (M4-L6): each holds
// perMinute requests and refills at perMinute a minute. The table is bounded
// (AN-7): a client whose bucket has refilled completely holds no state worth
// keeping and is swept when the table is full; when every entry is still
// refilling, new clients share one overflow bucket, so a flood from many
// addresses cannot grow memory or reset its own buckets.
type clientRateLimiter struct {
	mu         sync.Mutex
	perSecond  float64
	burst      float64
	maxClients int
	clients    map[string]*clientBucket
	overflow   clientBucket
}

type clientBucket struct {
	tokens float64
	last   time.Time
}

func newClientRateLimiter(perMinute, maxClients int) *clientRateLimiter {
	if perMinute < 1 {
		perMinute = 1
	}
	if maxClients < 1 {
		maxClients = 1
	}
	burst := float64(perMinute)
	return &clientRateLimiter{perSecond: burst / 60, burst: burst, maxClients: maxClients,
		clients: map[string]*clientBucket{}, overflow: clientBucket{tokens: burst}}
}

// allow takes one request from the client's bucket, or reports how long until
// the bucket holds one.
func (l *clientRateLimiter) allow(client string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.clients[client]
	if !ok {
		if len(l.clients) >= l.maxClients {
			l.sweepLocked(now)
		}
		if len(l.clients) >= l.maxClients {
			b = &l.overflow
		} else {
			b = &clientBucket{tokens: l.burst, last: now}
			l.clients[client] = b
		}
	}
	l.refillLocked(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return 0, true
	}
	wait := time.Duration(math.Ceil((1 - b.tokens) / l.perSecond * float64(time.Second)))
	return max(wait, time.Millisecond), false
}

func (l *clientRateLimiter) refillLocked(b *clientBucket, now time.Time) {
	if !b.last.IsZero() && now.After(b.last) {
		b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSecond)
	}
	if b.last.IsZero() || now.After(b.last) {
		b.last = now
	}
}

// sweepLocked drops every client whose bucket has refilled completely: it is
// the same as a client never seen.
func (l *clientRateLimiter) sweepLocked(now time.Time) {
	for client, b := range l.clients {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSecond >= l.burst {
			delete(l.clients, client)
		}
	}
}

// size is the number of clients the table holds.
func (l *clientRateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}
