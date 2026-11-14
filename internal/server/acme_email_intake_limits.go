// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net"
	"sync"
	"time"
)

// Per-source limits on the RFC 8823 reply intake (P15-L8), beyond its cap on
// sessions overall: one source (an IPv4 address, or an IPv6 /64) holds at
// most a few sessions at once and sends at most a budget of replies a minute,
// refilled continuously. A source over its sessions is turned away at
// connect; one over its replies is told to try again at DATA, before its
// message is read. The table of sources is bounded: idle sources are dropped
// to make room, and when none is idle a new source is turned away.
const (
	acmeIntakeDefaultSessionsPerSource = 4
	acmeIntakeDefaultRepliesPerMinute  = 20
	acmeIntakeMaxSources               = 4096
)

type acmeIntakeSource struct {
	active int
	tokens float64
	last   time.Time
}

type acmeIntakeSources struct {
	mu        sync.Mutex
	sessions  int
	perMinute float64
	now       func() time.Time
	byKey     map[string]*acmeIntakeSource
}

func newACMEIntakeSources(sessions, perMinute int) *acmeIntakeSources {
	if sessions <= 0 {
		sessions = acmeIntakeDefaultSessionsPerSource
	}
	if perMinute <= 0 {
		perMinute = acmeIntakeDefaultRepliesPerMinute
	}
	return &acmeIntakeSources{sessions: sessions, perMinute: float64(perMinute), now: time.Now, byKey: map[string]*acmeIntakeSource{}}
}

// intakeSourceKey is the source an address counts against: the IPv4
// address, or the IPv6 /64 a host is usually given whole.
func intakeSourceKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if ip == nil {
		return "unknown"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// sourceLocked returns the source's entry, refilled to now, making room by
// dropping idle sources; nil when the table is full of busy ones.
func (l *acmeIntakeSources) sourceLocked(key string) *acmeIntakeSource {
	now := l.now()
	src := l.byKey[key]
	if src == nil {
		if len(l.byKey) >= acmeIntakeMaxSources {
			for k, s := range l.byKey {
				if s.active == 0 && s.tokens+now.Sub(s.last).Minutes()*l.perMinute >= l.perMinute {
					delete(l.byKey, k)
				}
			}
			if len(l.byKey) >= acmeIntakeMaxSources {
				return nil
			}
		}
		src = &acmeIntakeSource{tokens: l.perMinute, last: now}
		l.byKey[key] = src
	}
	src.tokens += now.Sub(src.last).Minutes() * l.perMinute
	if src.tokens > l.perMinute {
		src.tokens = l.perMinute
	}
	src.last = now
	return src
}

// open admits one session from ip, or reports false when its source already
// holds its sessions; release ends the session.
func (l *acmeIntakeSources) open(ip net.IP) (func(), bool) {
	key := intakeSourceKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	src := l.sourceLocked(key)
	if src == nil || src.active >= l.sessions {
		return nil, false
	}
	src.active++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if s := l.byKey[key]; s != nil && s.active > 0 {
			s.active--
		}
	}, true
}

// take spends one reply of ip's source's budget, or reports false when it is
// spent.
func (l *acmeIntakeSources) take(ip net.IP) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	src := l.sourceLocked(intakeSourceKey(ip))
	if src == nil || src.tokens < 1 {
		return false
	}
	src.tokens--
	return true
}
