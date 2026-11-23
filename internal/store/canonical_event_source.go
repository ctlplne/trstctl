// SPDX-License-Identifier: BUSL-1.1

package store

import "trstctl.com/trstctl/internal/events"

// BindCanonicalEventSource publishes the configured log to projectors created
// later by command handlers that hold only the shared Store reference.
func (s *Store) BindCanonicalEventSource(source *events.Log) {
	if s != nil {
		s.canonicalEventSource.Store(source)
	}
}

// CanonicalEventSource returns the configured retained log, if any. A bare
// Store intentionally has no source and direct post-rewrap apply fails closed.
func (s *Store) CanonicalEventSource() *events.Log {
	if s == nil {
		return nil
	}
	return s.canonicalEventSource.Load()
}
