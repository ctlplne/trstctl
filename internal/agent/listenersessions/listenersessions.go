// SPDX-License-Identifier: BUSL-1.1

// Package listenersessions counts, on the host an agent runs on, the
// established TCP connections on a listener's port and how many of them a
// process older than a given moment holds (A245-L2).
//
// A revoked certificate stops being offered to new connections once its
// listener serves a replacement, but a session negotiated before that keeps
// the old certificate's keys for as long as its connection lives. A
// connection held by a process that started after the replacement was
// deployed cannot be such a session; one held by an older process might be
// (a graceful reload keeps old workers draining their connections). Counting
// them is what lets the control plane say whether those sessions are gone,
// rather than infer it from a containment stop.
package listenersessions

import (
	"errors"
	"time"
)

// ErrUnsupported reports a platform whose sockets and processes this package
// cannot read; the caller reports nothing rather than an empty observation.
var ErrUnsupported = errors.New("listenersessions: not supported on this platform")

// Observation is one count of a listener port's established connections.
type Observation struct {
	// Port is the local port the connections were counted on.
	Port int `json:"port"`
	// Established counts the established TCP connections whose local port is
	// Port.
	Established int `json:"established"`
	// HeldByOlder counts those held by at least one process that started
	// before SinceUnix.
	HeldByOlder int `json:"held_by_older"`
	// Unattributed counts those whose holding process could not be read; they
	// are not counted as newer.
	Unattributed int `json:"unattributed"`
	// SinceUnix is the moment the processes were compared with.
	SinceUnix int64 `json:"since_unix"`
	// CheckedAtUnix is when the count was taken.
	CheckedAtUnix int64 `json:"checked_at_unix"`
}

// Valid reports whether the counts are consistent with each other.
func (o Observation) Valid() bool {
	return o.Port > 0 && o.Port <= 65535 && o.Established >= 0 && o.HeldByOlder >= 0 && o.Unattributed >= 0 &&
		o.HeldByOlder+o.Unattributed <= o.Established && o.SinceUnix > 0 && o.SinceUnix <= o.CheckedAtUnix
}

// Observe counts the established connections on port and how many a process
// started before since holds. It needs to read every process's open files,
// so an agent that may not reports them as unattributed.
func Observe(port int, since time.Time) (Observation, error) {
	return observe(port, since)
}
