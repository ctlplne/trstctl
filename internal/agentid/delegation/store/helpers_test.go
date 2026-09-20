// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/hex"
	"testing"

	"trstctl.com/trstctl/internal/eventspec"

	"trstctl.com/trstctl/internal/agentid/delegation"
)

// evt is a stored AN-2 event with an assigned sequence, as it would read back from
// the durable log on Replay (eventspec.Event.Sequence is set on Replay). The store
// tests construct these directly so the watermark folded by the projection is
// deterministic.
type evt = eventspec.Event

// eventFixture pairs an AGID-01 typed payload with the ledger sequence it is stored
// at, so a test can declare a delegation forest as a sequence and have it encoded +
// stamped in one place.
type eventFixture struct {
	payload delegation.Payload
	seq     uint64
}

// encodeFixtures encodes each payload through the AGID-01 Encode path and stamps the
// declared sequence, returning stored-form events. A malformed fixture fails the test
// (these are hand-built, so an encode error is a test bug).
func encodeFixtures(t *testing.T, fs []eventFixture) []evt {
	t.Helper()
	out := make([]evt, 0, len(fs))
	for _, f := range fs {
		e, err := delegation.Encode(f.payload)
		if err != nil {
			t.Fatalf("encode fixture %T: %v", f.payload, err)
		}
		if e.SchemaVersion == 0 {
			e.SchemaVersion = eventspec.DefaultSchemaVersion
		}
		e.Sequence = f.seq
		out = append(out, e)
	}
	return out
}

// toEvents returns the slice unchanged; it exists so the intent (a replayable event
// prefix) reads clearly at the call site and to decouple call sites from the alias.
func toEvents(es []evt) []eventspec.Event { return es }

// hexOf renders a digest as lower-case hex — the credential-id form the projection
// emits (hex of the credential digest), so store rows can be keyed to match.
func hexOf(b []byte) string { return hex.EncodeToString(b) }
